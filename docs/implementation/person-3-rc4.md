# Person 3: RC4 + HMAC, Tenant Side

**Cipher:** RC4 stream cipher with a per-file key `HMAC-SHA256(user key, random nonce)` (from the README), RC4-drop3072, and an HMAC-SHA256 tag per chunk.
**App:** everything the tenant does: profile and emergency contact, KTP / rental agreement / room video upload, viewing and downloading their own documents, deletion request.
**Branches:** `feat/rc4`, `feat/tenant`

## Files you own

```
app/crypto/rc4.py
app/services/uploads.py
app/routes/tenant.py
app/templates/tenant/*
tests/crypto/test_rc4.py, tests/web/test_tenant_flow.py
```

## Cipher task: `rc4.py`

Spec: [crypto-spec.md §5](crypto-spec.md#rc4--hmac-sha256-person-3-rc4py-id-3).

```python
import hmac
from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes
from .base import CipherSuite, IntegrityError, register
from .kdf import hkdf_sha256, hmac_sha256

MAC_INFO = b"kosanku/rc4/mac/v1"
DROP = 3072
TAG = 32

class _Base:
    def __init__(self, dek, nonce):
        if len(nonce) != 16:
            raise IntegrityError()
        file_key = hmac_sha256(dek, nonce)                     # README: HMAC-SHA256(user key, nonce)
        self.mac = hkdf_sha256(dek, salt=nonce, info=MAC_INFO, length=32)
        self.rc4 = ARC4.new(file_key, drop=DROP)               # one keystream for the whole file
        self.next_index = 0

    def _check_order(self, index):
        if index != self.next_index:
            raise IntegrityError()                             # keystream would be out of sync
        self.next_index += 1

class _Sealer(_Base):
    def seal(self, index, plaintext, ad):
        self._check_order(index)
        ct = self.rc4.encrypt(plaintext)
        return ct + hmac_sha256(self.mac, ad + ct)

class _Opener(_Base):
    def open(self, index, record, ad):
        if len(record) < TAG:
            raise IntegrityError()
        ct, tag = record[:-TAG], record[-TAG:]
        if not hmac.compare_digest(tag, hmac_sha256(self.mac, ad + ct)):
            raise IntegrityError()
        self._check_order(index)
        return self.rc4.decrypt(ct)
```

Things to get right:

- **Never reuse an RC4 key.** If two files used the same keystream, `C1 XOR C2 = P1 XOR P2`, and with a known file format (JPEG/PDF headers) that leaks a lot. The per-file random nonce → per-file key is what prevents it. That's the whole reason the README asks for `HMAC-SHA256(user key, nonce)`.
- **Drop the first 3072 bytes.** The first bytes of RC4 output are biased (Fluhrer–Mantin–Shamir, the attack that broke WEP). PyCryptodome's `drop=` does this for us.
- The keystream is **stateful**: chunk 5 must be decrypted right after chunk 4. `_check_order` makes misuse fail loudly instead of producing garbage.
- RC4 is malleable: flipping bit *k* of the ciphertext flips bit *k* of the plaintext. Without the HMAC an attacker could change a NIK digit without being detected. So the tag is checked **before** we touch the keystream.
- Separate MAC key from the RC4 key.

### Tests (`tests/crypto/test_rc4.py`)

1. **Known answer, no drop:** `ARC4.new(b"Key").encrypt(b"Plaintext") == bytes.fromhex("BBF316E8D940AF0AD3")`.
2. **RFC 6229:** for the 40-bit key `0102030405`, check the keystream at offset 0 and at offset 3072 against the RFC table. Then check that `ARC4.new(key, drop=3072)` starts at the offset-3072 bytes. This proves the drop really happens.
3. Same DEK, two files → different `params` → different keystreams (ciphertexts of all-zero input differ).
4. **Malleability demo:** do raw RC4 without the MAC, flip a bit in the ciphertext, and show the plaintext changed by exactly that bit. Then do it through the suite and show `IntegrityError`. Use this test in the presentation.
5. Calling `open` with index 1 before index 0 → `IntegrityError`.
6. Passes `tests/crypto/test_contract.py`.

## App tasks

### Day 3 to 4: profile
- `GET /tenant/profile`: form with the fields from [architecture.md](architecture.md#data-model) (personal + emergency contact). Pre-fill it by decrypting the existing profile item if there is one.
- `POST /tenant/profile`: validate (NIK = 16 digits, phone = digits/`+`, birth_date is a real date, required fields), build the JSON, `vault.store_bytes(me, "profile", json_bytes)`. Saving again replaces the old item (all three blobs).
- Tenant home (`GET /tenant`) shows a checklist: profile ✓, KTP ✓, agreement –, video –, plus their room/kos if assigned.

### Day 5: uploads (`uploads.py` + routes)

| kind | Allowed | Max size | Magic bytes check |
|------|---------|----------|-------------------|
| `ktp` | JPEG, PNG, PDF | 5 MB | `FF D8 FF`, `89 50 4E 47`, `%PDF` |
| `agreement` | PDF | 10 MB | `%PDF` |
| `video` | MP4, WebM | 200 MB | `ftyp` at offset 4, `1A 45 DF A3` |

- Check the magic bytes from the first chunk. Don't trust `Content-Type` or the filename.
- Enforce the size while streaming (count bytes as they come through). Don't only rely on `Content-Length`. If it goes over: abort, delete the `.tmp` files, show an error.
- `POST /tenant/documents/{kind}` → validate → `vault.store_item(me, kind, file.file, mime)`. Close `file` in a `finally` so the spooled temp file goes away.
- `GET /tenant/documents`: table with kind, size, uploaded at, `Download` (uses `READ_CIPHER`), and small `AES / DES / RC4` links.
- `GET /tenant/documents/{kind}?cipher=`: same verify-then-stream flow as the owner route. Ask Person 2 to put the shared bit in one helper so you're not copy-pasting it.
- Upload button gets disabled with an "Encrypting…" label on submit (5 lines of inline JS). A 200 MB upload encrypting three times takes a few seconds and people will double-click.

### Day 6: deletion request
- `GET /tenant/deletion-request`: shows the current status (none / pending / rejected with reason / done).
- `POST /tenant/deletion-request`: optional reason. Only one pending at a time. Allowed whether or not the tenant still has a room. After move-out is the main case, and in that case there's no owner anymore. **Decide on day 6 with Person 2:** if the tenant has no room, does the request go to the last owner (store `owner_id` on the request) or straight to auto-approve? Our suggestion: store `owner_id` at request time, and if there's no owner, auto-approve.

### Day 7: edge cases (`tests/web/test_tenant_flow.py`)
- Upload an empty file → rejected by validation (but the crypto layer must still handle empty input, that's in the contract tests).
- Upload exactly 1 MiB and exactly 1 MiB + 1 byte → round-trip equal.
- Upload a `.exe` renamed to `.pdf` → rejected.
- Upload KTP twice → only one item, three blobs, and the old files are deleted from disk.
- Tenant A cannot download tenant B's documents (there's no id in the tenant routes, it's always `me`, but test that anyway with a crafted session).

## Handoffs

| You give | To | When |
|----------|----|------|
| `uploads.validate_stream` | P4 (vault calls it per chunk) or wraps the file before vault | day 5 |
| Tenant pages working with seed data | everyone (demo) | day 5 |

| You need | From | When |
|----------|------|------|
| `require_role`, `check_csrf`, base layout | P1 | day 3 |
| `vault.store_bytes`, `store_item`, `open_item`, `verify_item` | P4 | day 4 / 5 |
| shared verify-then-stream helper | P2 | day 5 |

## For the report

- How RC4 works (KSA + PRGA) in half a page, and the known weaknesses: early-byte bias, related-key attacks (WEP), and the fact that it's prohibited in TLS (RFC 7465).
- Why each one of our three measures (per-file key, drop3072, HMAC) is there, and which attack each one stops.
- Benchmark row for RC4. It's usually fast in software, but here we pay for an HMAC on top. Compare that against GCM, which gets authentication almost for free with hardware support.
