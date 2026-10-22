# Person 2: DES-CBC + HMAC, Owner Side, Access Control

**Cipher:** DES in CBC mode, with HMAC-SHA256 encrypt-then-MAC for integrity (CBC on its own has none).
**App:** kos and room management, tenant assignment, the ownership guard used across the app, the owner's tenant/document views, approving deletion requests.
**Branches:** `feat/des-cbc`, `feat/owner`, `feat/access`

## Files you own

```
app/crypto/des_cbc.py
app/services/access.py
app/routes/owner.py
app/templates/owner/*
tests/crypto/test_des_cbc.py, tests/web/test_access.py
```

## Cipher task: `des_cbc.py`

Spec: [crypto-spec.md §5](crypto-spec.md#des-cbc--hmac-sha256-person-2-des_cbcpy-id-2).

```python
import hmac
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from .base import CipherSuite, IntegrityError, register
from .kdf import hkdf_sha256, hmac_sha256

ENC_INFO = b"kosanku/des-cbc/enc/v1"
MAC_INFO = b"kosanku/des-cbc/mac/v1"
TAG = 32

def _odd_parity(key: bytes) -> bytes:
    # DES ignores the low bit of every byte. That's why 64-bit key = 56-bit effective.
    return bytes((b & 0xFE) | (bin(b >> 1).count("1") + 1) % 2 for b in key)

def _keys(dek, salt):
    enc = _odd_parity(hkdf_sha256(dek, salt=salt, info=ENC_INFO, length=8))
    mac = hkdf_sha256(dek, salt=salt, info=MAC_INFO, length=32)
    return enc, mac

class _Sealer:
    def __init__(self, dek, salt):
        self.enc, self.mac = _keys(dek, salt)

    def seal(self, index, plaintext, ad):
        iv = get_random_bytes(8)
        ct = DES.new(self.enc, DES.MODE_CBC, iv=iv).encrypt(pad(plaintext, 8))
        return iv + ct + hmac_sha256(self.mac, ad + iv + ct)

class _Opener(_Sealer):
    def open(self, index, record, ad):
        if len(record) < 8 + 8 + TAG or (len(record) - 8 - TAG) % 8:
            raise IntegrityError()
        iv, ct, tag = record[:8], record[8:-TAG], record[-TAG:]
        if not hmac.compare_digest(tag, hmac_sha256(self.mac, ad + iv + ct)):
            raise IntegrityError()
        try:
            return unpad(DES.new(self.enc, DES.MODE_CBC, iv=iv).decrypt(ct), 8)
        except ValueError:
            raise IntegrityError() from None
```

Things to get right:

- **The order is encrypt → MAC, and on open MAC check → decrypt → unpad.** If we unpadded before checking the MAC, different errors for "bad padding" vs "bad MAC" would give a padding oracle (Vaudenay 2002). Because the tag is checked first, `unpad` never sees attacker-controlled data.
- The MAC covers the IV too. Otherwise an attacker could flip bits in the IV, which flips the same bits in the first plaintext block without being noticed.
- Fresh random IV for every chunk. Don't use a counter as the IV in CBC, it has to be unpredictable.
- Separate keys for encryption and MAC, both derived from the per-file salt.
- 8-byte padding means the last chunk grows by 1..8 bytes, and a full 1 MiB chunk gets a whole extra pad block. That's normal.

### Tests (`tests/crypto/test_des_cbc.py`)

1. **Known answer (classic textbook vector):** key `133457799BBCDFF1`, plaintext `0123456789ABCDEF` → ECB ciphertext `85E813540F0AB405`. With CBC and a zero IV, the first block must match. This proves `DES.new` is actually single DES.
2. `_odd_parity` output: every byte has an odd number of 1-bits. Two keys that differ only in the parity bits encrypt the same (shows the 56-bit effective point).
3. Flip a bit in the IV → `IntegrityError` (would silently corrupt block 1 without the MAC, put that in a comment).
4. Record with a ciphertext length that isn't a multiple of 8 → `IntegrityError`, not `ValueError`.
5. Same plaintext in two chunks → different ciphertext (random IV).
6. Passes `tests/crypto/test_contract.py`.

## App tasks

### Day 1 to 3: kos and rooms
- `GET/POST /owner/kos`: list + create (name, address). Edit and delete only if the kos has no tenants.
- `GET/POST /owner/kos/{id}/rooms`: list rooms with occupant email, add a room number.
- Every query filters by `kos.owner_id == me.id`. Don't load by id and then check. Put the filter **in the query**, so a forgotten check fails closed (returns nothing).

### Day 4: `access.py` + assignment
This module is the single source of truth for "who can see whose data". Person 4's `keys.unwrap_dek` calls it.

```python
def owner_has_tenant(owner: User, tenant: User) -> bool
    # True only if tenant sits in a room of a kos owned by owner
def can_view_subject(actor: User, subject: User) -> bool
    # tenant → only self; owner → owner_has_tenant; admin → always False
def get_owned_room_or_404(db, owner, room_id) -> Room
def get_owned_tenant_or_404(db, owner, tenant_id) -> User
```

- `POST /owner/rooms/{id}/assign` with `tenant_email`. Rules: the user must exist, have role tenant, be active, and not be in any room already (the DB unique constraint is the backstop, catch `IntegrityError` from SQLAlchemy and show a nice message).
- `POST /owner/rooms/{id}/unassign`: clears the room. The tenant's data **stays** (they can still request deletion). From now on the owner loses access automatically, because `owner_has_tenant` becomes false.

### Day 5: tenant views
- `GET /owner/tenants`: tenants across all my kos, with columns room, kos, which documents exist (✓/–).
- `GET /owner/tenants/{id}`: decrypted profile (via `vault.open_item` for `kind=profile`) and a list of documents. Each document has `AES | DES | RC4` download links → `/owner/tenants/{id}/documents/{kind}?cipher=...`.
- The download route follows the flow in [architecture.md](architecture.md#download-owner-views-a-tenants-ktp): access check → verify pass → stream. On `IntegrityError` show the 409 page and call `audit.log(ok=False)`.
- Unknown tenant **or** not your tenant → 404 both times. Don't return 403, it tells an attacker that the id exists.

### Day 6: deletion approval
- `GET /owner/deletion-requests`: pending requests from my tenants.
- `POST .../{id}/approve` → `vault.shred_user(tenant)` (Person 4), unassign room, deactivate user, status `done`, audit.
- `POST .../{id}/reject` with a required reason. The tenant sees it.
- Approve has a confirmation page ("This permanently destroys all documents of X. Type the room number to confirm."), because it can't be undone.

### Day 7: IDOR test pass (`tests/web/test_access.py`)
Owner A and owner B, each with one tenant. For every owner route with an id in it, check that owner A gets 404 when using B's ids: kos, room, tenant, document, deletion request. Also check that an admin session gets 403/404 on every `/owner/*` and `/tenant/*` route.

## Handoffs

| You give | To | When |
|----------|----|------|
| `access.owner_has_tenant`, `can_view_subject` | P4 (`keys.unwrap_dek`) | day 4 morning |
| Owner tenant detail page | everyone (demo) | day 5 |

| You need | From | When |
|----------|------|------|
| `require_role`, `check_csrf`, models | P1 | day 1 / 3 |
| `vault.open_item`, `verify_item`, `shred_user` | P4 | day 4 / 6 |

## For the report

- Why DES is broken today: 56-bit key brute-forceable (EFF Deep Crack, 1998, under 3 days; much faster now), and the 64-bit block causes Sweet32 problems. We only use it because the assignment asks for it, and we reduced the damage with per-file keys and a MAC.
- Why CBC needs a MAC, and why the order (encrypt-then-MAC) matters.
- Benchmark row for DES. Expect it to be clearly the slowest. Explain (8-byte blocks, 16 Feistel rounds, no hardware support).
