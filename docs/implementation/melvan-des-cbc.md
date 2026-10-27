# Melvan: DES-CBC + HMAC, Owner Pages, Access Control

**Cipher:** DES in CBC mode, plus an HMAC-SHA256 tag (encrypt-then-MAC), because CBC alone doesn't detect tampering.
**App:** kos and room management, putting tenants in rooms, the ownership check the whole app uses, the owner's tenant and document pages, approving deletion.
**Branches:** `feat/des-cbc`, `feat/owner`, `feat/access`

## My files

```
app/crypto/des_cbc.py
app/services/access.py
app/routes/owner.py
app/templates/owner/
tests/crypto/test_des_cbc.py, tests/web/test_access.py
```

## Cipher: `des_cbc.py`

Spec: [crypto-spec.md](crypto-spec.md#des-cbc--hmac-melvan).

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
    # DES ignores the last bit of every byte, which is why a 64-bit key only has 56 real bits
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

@register
class DesCbc(CipherSuite):
    id, name = 2, "des"
    def new_params(self):          return get_random_bytes(16)
    def sealer(self, dek, params): return _Sealer(dek, params)
    def opener(self, dek, params): return _Opener(dek, params)
```

Watch out for:

- **The order matters.** Encrypt and then MAC. When opening: check the MAC, then decrypt, then unpad. If we unpadded first, "bad padding" and "bad MAC" would give different errors, and that's a padding oracle attack (Vaudenay, 2002). With the MAC checked first, `unpad` only ever sees data we already trust.
- The MAC has to include the IV. Otherwise someone could flip bits in the IV, which flips the same bits in the first block of plaintext, and nobody would notice.
- Use a new random IV for every chunk. In CBC the IV has to be unpredictable, so a counter isn't good enough.
- Keep separate keys for encryption and for the MAC. Both come from the per-file salt.
- Padding makes every chunk 1 to 8 bytes bigger (a full 1 MiB chunk gets a whole extra block). That's normal.

### Tests (`tests/crypto/test_des_cbc.py`)

- [x] Textbook known-answer vector (key `133457799BBCDFF1`, plaintext `0123456789ABCDEF`, ciphertext `85E813540F0AB405`), already passing
- [x] CBC with a zero IV gives the same first block as ECB, already passing
- [x] Flipping the parity bits gives the same result (that's the 56-bit point), already passing
- [x] Every byte from `_odd_parity` has an odd number of 1-bits
- [x] Flipping a bit in the IV raises `IntegrityError` (add a comment: without the MAC this would silently change block 1)
- [x] A ciphertext whose length isn't a multiple of 8 raises `IntegrityError`, not `ValueError`
- [x] The same plaintext in two chunks gives different ciphertext (because of the random IV)
- [x] Passes `tests/crypto/test_contract.py`

## App

### Days 1 to 3: kos and rooms
- `GET/POST /owner/kos`: list my kos and add a new one (name, address). Editing or deleting is only allowed if it has no tenants.
- `GET/POST /owner/kos/{id}/rooms`: list rooms with who's living there, and add a room number.
- Every query filters on `kos.owner_id == me.id`. Put the filter **in the query** instead of loading by id and checking afterwards. That way, if someone forgets a check, the result is just empty.

### Day 4: `access.py` and assigning tenants
This file is the one place that decides who can see whose data. Naura's `keys.unwrap_dek` uses it.

```python
def owner_has_tenant(owner, tenant) -> bool      # True only if the tenant is in a room of the owner's kos
def can_view_subject(actor, subject) -> bool     # tenant: only themselves, owner: owner_has_tenant, admin: never
def get_owned_room_or_404(db, owner, room_id)
def get_owned_tenant_or_404(db, owner, tenant_id)
```

- `POST /owner/rooms/{id}/assign` with the tenant's email. The account has to exist (the admin creates it), be a tenant, be active, and not already have a room. The unique constraint in the database is a backup, so catch that error and show a normal message.
- `POST /owner/rooms/{id}/unassign`: empties the room. The tenant's data **stays** so they can still ask for deletion, but the owner loses access right away because `owner_has_tenant` becomes false.

### Day 5: tenant pages
- `GET /owner/tenants`: all tenants across my kos, with their room, kos, and which documents they've uploaded.
- `GET /owner/tenants/{id}`: the decrypted profile (`vault.load_bytes` for `profile`) and the list of documents. Each document gets `AES | DES | RC4` download links pointing to `/owner/tenants/{id}/documents/{kind}?cipher=...`.
- The download follows the flow in [architecture.md](architecture.md#downloading-owner-opens-a-tenants-ktp): access check, verify, then stream. If it raises `IntegrityError`, show the 409 page and call `audit.log(ok=False)`.
- Put that verify-then-stream part in one helper so Ajil can use it on the tenant side too.
- A tenant that doesn't exist and a tenant that isn't yours both give 404. Don't use 403, because that tells someone the id exists.

### Day 6: approving deletion
- `GET /owner/deletion-requests`: pending requests from my tenants.
- `POST .../{id}/approve`: `vault.shred_user(tenant)` (Naura), empty the room, deactivate the user, set status to `done`, write to the audit log.
- `POST .../{id}/reject`: a reason is required, and the tenant can see it.
- Approving can't be undone, so show a confirmation page first ("This permanently deletes all of X's documents. Type the room number to confirm.").
- Talk to Ajil about tenants who have already moved out (no room, so no current owner). The plan is that the request saves `owner_id` when it's made, and if there's no owner at all it gets approved automatically.

### Day 7: access tests (`tests/web/test_access.py`)
Set up owner A and owner B, each with one tenant. For every owner route that takes an id, check that owner A gets 404 when using B's ids (kos, room, tenant, document, deletion request). Also check that an admin gets 403 or 404 on every `/owner/*` and `/tenant/*` route.

## What I give / what I need

| I give | To | When |
|--------|----|------|
| `owner_has_tenant`, `can_view_subject` | Naura (for `keys.unwrap_dek`) | day 4 morning |
| verify-then-stream helper | Ajil | day 5 |
| owner tenant page | everyone (for the demo) | day 5 |

| I need | From | When |
|--------|------|------|
| models, `require_role`, `check_csrf` | Ata | day 1 / day 3 |
| `vault.load_bytes`, `verify_item`, `open_item`, `shred_user` | Naura | days 4 to 6 |

## For the report

- Why DES isn't safe today: the 56-bit key can be brute-forced (the EFF's Deep Crack did it in under 3 days back in 1998, and it's much faster now), and the 64-bit block size runs into Sweet32. We only use it because the assignment asks for it, and we limit the damage with a new key per file and a MAC.
- Why CBC needs a MAC, and why the order (encrypt, then MAC) matters.
- The DES row from the benchmark. It'll probably be the slowest by far. Explain why: 8-byte blocks, 16 rounds, and no hardware support.
