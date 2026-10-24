# Ajil: RC4 + HMAC, Tenant Pages

**Cipher:** RC4 with a new key per file (`HMAC-SHA256(user key, random nonce)`, from the README), the first 3072 bytes of keystream dropped, and an HMAC-SHA256 tag on every chunk.
**App:** everything the tenant does: profile and emergency contact, uploading KTP / rental agreement / room video, viewing and downloading their own documents, requesting deletion.
**Branches:** `feat/rc4`, `feat/tenant`

## My files

```
app/crypto/rc4.py
app/services/uploads.py
app/routes/tenant.py
app/templates/tenant/
tests/crypto/test_rc4.py, tests/web/test_tenant_flow.py
```

## Cipher: `rc4.py`

Spec: [crypto-spec.md](crypto-spec.md#rc4--hmac-ajil).

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
            raise IntegrityError()                             # keystream would get out of sync
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

@register
class Rc4(CipherSuite):
    id, name = 3, "rc4"
    def new_params(self):          return get_random_bytes(16)
    def sealer(self, dek, params): return _Sealer(dek, params)
    def opener(self, dek, params): return _Opener(dek, params)
```

Watch out for:

- **Never use the same RC4 key twice.** If two files share a keystream, then `C1 XOR C2 = P1 XOR P2`. With known file formats (JPEG and PDF headers) that leaks a lot. The random nonce per file gives a new key per file, and that's exactly why the README asks for `HMAC-SHA256(user key, nonce)`.
- **Drop the first 3072 bytes.** The start of RC4's output is biased (that's how WEP got broken, by Fluhrer, Mantin and Shamir). PyCryptodome's `drop=` does it for us.
- The keystream keeps going across chunks, so chunk 5 has to come right after chunk 4. `_check_order` makes a mistake fail loudly instead of quietly giving garbage.
- RC4 lets you flip bits: flip bit k of the ciphertext and bit k of the plaintext flips too. Without the HMAC someone could change a digit in a NIK and we'd never know. So check the tag **before** using the keystream.
- Keep the MAC key separate from the RC4 key.

### Tests (`tests/crypto/test_rc4.py`)

- [x] `ARC4.new(b"Key").encrypt(b"Plaintext") == BBF316E8D940AF0AD3`, already passing
- [x] RFC 6229 vectors at offsets 0 and 16, already passing
- [x] `drop=3072` really skips 3072 bytes, already passing
- [x] Bit-flipping demo on raw RC4 without a MAC, already passing (use it in the presentation)
- [ ] Same DEK, two files: different `params`, so different keystreams (encrypting all zeros gives different output)
- [ ] The same bit flip through our suite raises `IntegrityError`
- [ ] Calling `open` with index 1 before index 0 raises `IntegrityError`
- [ ] Passes `tests/crypto/test_contract.py`

## App

### Days 3 to 4: profile
- `GET /tenant/profile`: a form with the fields from [architecture.md](architecture.md#tables) (personal info and emergency contact). If a profile already exists, decrypt it and fill the form.
- `POST /tenant/profile`: validate it (NIK is 16 digits, phone is digits or `+`, birth date is a real date, required fields filled in), turn it into JSON, and save it with `vault.store_bytes(me, "profile", json_bytes)`. Saving again replaces the old one, all three copies.
- Tenant home (`GET /tenant`): a checklist (profile ✓, KTP ✓, agreement –, video –) and their room and kos if they have one.

### Day 5: uploads (`uploads.py` and routes)

| Type | Allowed | Max size | How to check the real type |
|------|---------|----------|----------------------------|
| `ktp` | JPEG, PNG, PDF | 5 MB | starts with `FF D8 FF`, `89 50 4E 47` or `%PDF` |
| `agreement` | PDF | 10 MB | starts with `%PDF` |
| `video` | MP4, WebM | 200 MB | `ftyp` at byte 4, or starts with `1A 45 DF A3` |

- Check the type from the first bytes of the file. Don't trust the `Content-Type` or the file name.
- Count the bytes while reading instead of trusting `Content-Length`. If it goes over the limit, stop, delete the `.tmp` files, and show an error.
- `POST /tenant/documents/{kind}`: validate, then `vault.store_item(me, kind, file.file, mime)`. Close the file in a `finally` so FastAPI's temp file gets deleted.
- `GET /tenant/documents`: a table with type, size, upload date, a `Download` button (uses `READ_CIPHER`), and small `AES / DES / RC4` links.
- `GET /tenant/documents/{kind}?cipher=`: the same verify-then-stream as the owner side. Use Melvan's helper instead of copy-pasting it.
- On submit, disable the upload button and change its text to "Encrypting…" (about 5 lines of JS). A 200 MB file encrypted three times takes a few seconds, and people will click twice.

### Day 6: deletion request
- `GET /tenant/deletion-request`: shows the status (none / pending / rejected with the reason / done).
- `POST /tenant/deletion-request`: the reason is optional, and only one request can be pending at a time. It works whether or not the tenant still has a room. After move-out is actually the main case, and then there's no current owner. Plan: save `owner_id` on the request when it's made, and if there's no owner at all, approve it automatically. Confirm this with Melvan on day 6.

### Day 7: edge cases (`tests/web/test_tenant_flow.py`)
- Uploading an empty file gets rejected by validation (the crypto still has to handle empty input, and the contract tests cover that).
- A file of exactly 1 MiB, and one of 1 MiB + 1 byte, both come back identical.
- An `.exe` renamed to `.pdf` gets rejected.
- Uploading KTP twice leaves only one item with three blobs, and the old files are gone from disk.
- Tenant A can't download tenant B's documents. The tenant routes have no id (they always use `me`), but test it anyway with a faked session.

## What I give / what I need

| I give | To | When |
|--------|----|------|
| `uploads.validate_stream` | Naura (the vault calls it per chunk, or it wraps the file before the vault) | day 5 |
| working tenant pages with the seed data | everyone (for the demo) | day 5 |

| I need | From | When |
|--------|------|------|
| `require_role`, `check_csrf`, base layout | Ata | day 3 |
| `vault.store_bytes`, `store_item`, `load_bytes`, `verify_item`, `open_item` | Naura | days 4 to 5 |
| verify-then-stream helper | Melvan | day 5 |

## For the report

- How RC4 works (key scheduling, then generating the keystream) in about half a page, plus its known problems: the biased first bytes, related-key attacks (WEP), and the fact that TLS banned it (RFC 7465).
- Why each of our three fixes is there (new key per file, drop 3072, HMAC) and which attack each one stops.
- The RC4 row from the benchmark. RC4 is fast on its own, but we pay for the HMAC on top. Compare that with GCM, where the integrity check is almost free on CPUs with hardware support.
