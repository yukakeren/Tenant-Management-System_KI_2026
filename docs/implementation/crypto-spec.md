# Crypto Spec

This is what all four of us code against. Naura wrote `app/crypto/base.py` from it on day 1. Once we've all agreed on it at the end of day 1, we don't change the interface anymore. If you really need to, bring it up at the morning sync instead of just changing it in your branch.

## What we want

1. Every piece of tenant data is saved three times: AES-256-GCM, DES-CBC + HMAC-SHA256, and RC4 + HMAC-SHA256.
2. Every copy has an integrity check. If someone edits, cuts, reorders, or adds to a file, or moves it to another user, we get `IntegrityError`. We never return wrong data.
3. Files are encrypted in chunks so memory stays low even for a 200 MB video.
4. Each cipher person only writes the code for one chunk. The rest (chunking, header, keys) is shared code from Naura.

## The interface

It lives in `app/crypto/base.py`:

```python
class IntegrityError(Exception):
    """Integrity check failed. Never say why."""

class ChunkSealer(Protocol):
    def seal(self, index: int, plaintext: bytes, ad: bytes) -> bytes: ...

class ChunkOpener(Protocol):
    def open(self, index: int, record: bytes, ad: bytes) -> bytes: ...
        # raise IntegrityError for ANY problem (bad tag, too short, bad padding)

class CipherSuite(ABC):
    id: ClassVar[int]      # goes in the file header: 1 = aes, 2 = des, 3 = rc4
    name: ClassVar[str]    # "aes", "des" or "rc4", same as secret_blobs.cipher

    def new_params(self) -> bytes: ...                      # random per-file values (nonce/salt)
    def sealer(self, dek: bytes, params: bytes) -> ChunkSealer: ...
    def opener(self, dek: bytes, params: bytes) -> ChunkOpener: ...

REGISTRY: dict[str, CipherSuite]
def register(cls): ...          # use it as a class decorator: @register
def get_suite(name_or_id): ...
```

Rules for every cipher:

- `dek` is the user's 32-byte key. Derive your own keys from it (see below), don't use it as the cipher key directly.
- One sealer/opener per file. The container calls them with index 0, 1, 2, ... in order. RC4 needs this order, the other two don't care.
- `ad` comes from the container. Include it in your tag exactly as you get it.
- Compare tags with `hmac.compare_digest`, and check the tag **before** decrypting or unpadding.
- Turn any library error (`ValueError`, padding error, etc.) into `IntegrityError`. If a `ValueError` gets out, that's a bug.
- Don't print or log keys, nonces or plaintext, not even while debugging.

## File format

Naura's `app/crypto/container.py`. All numbers are big-endian.

```
Header
  offset  size  field
  0       4     magic       "KSK1"
  4       1     version     1
  5       1     cipher_id   1, 2 or 3
  6       4     chunk_size  1 MiB by default
  10      2     params_len
  12      n     params      from new_params()

Then one or more records:
  4 bytes  record length
  m bytes  record (whatever seal() returned)
```

- There's always at least one record. An empty file becomes one empty last chunk.
- Every chunk is exactly `chunk_size` bytes except the last one.
- We don't store which chunk is the last one in the file. The reader figures it out by checking whether anything comes after it. Since the "last chunk" flag is part of `ad`:
  - if someone cuts off the end, the new last chunk was sealed as "not last", so it fails
  - if someone adds a chunk, the real last chunk gets opened as "not last", so it fails
- The reader rejects any record length bigger than `chunk_size + 64` before reading it, so a broken length can't make us allocate gigabytes.
- Wrong magic, version or cipher id means `IntegrityError`.

Functions:

```python
CHUNK_SIZE = 1 << 20

def encrypt_stream(suites, dek, context, src, dsts) -> list[EncStats]
    # reads src ONCE and feeds every chunk to all ciphers, returns size + time per cipher
def decrypt_stream(dek, context, src) -> Iterator[bytes]     # yields plaintext chunk by chunk
def verify_stream(dek, context, src) -> None                 # same, but throws the output away
def encrypt_bytes(suite, dek, context, data) -> bytes        # for small things like the profile
def decrypt_bytes(dek, context, blob) -> bytes
```

## What gets authenticated

```
context  = "kosanku|" + subject_id + "|" + item_id + "|" + kind
file_ad  = header + context
chunk_ad = file_ad + index (8 bytes) + is_last (1 byte)
```

The container builds `chunk_ad` and passes it as `ad`. That's what stops these:

| Attack | Why it fails |
|--------|--------------|
| Change a byte in the header (nonce, chunk size, ...) | the header is in `ad` |
| Copy tenant A's KTP over tenant B's | different `subject_id` (and a different key anyway) |
| Swap someone's KTP and agreement files | different `item_id` and `kind` |
| Swap chunk 3 and chunk 4 | different `index` |
| Cut off the end, or add a chunk | the `is_last` flag |

## The three ciphers

Short version here. Each person's own doc has the full code and tests.

### AES-256-GCM (Ata)

```
params   = 8 random bytes (nonce prefix)
key      = HKDF(dek, info="kosanku/aes-gcm/v1", 32 bytes)
nonce    = params + chunk index (4 bytes)          -> 12 bytes, never repeats
record   = GCM ciphertext + 16-byte tag (tag also covers ad)
```

### DES-CBC + HMAC (Melvan)

```
params   = 16 random bytes (salt, new for every file)
enc key  = HKDF(dek, salt, "kosanku/des-cbc/enc/v1", 8 bytes), parity bits fixed
mac key  = HKDF(dek, salt, "kosanku/des-cbc/mac/v1", 32 bytes)
per chunk: random 8-byte IV, PKCS7 pad, DES-CBC encrypt
tag      = HMAC-SHA256(mac key, ad + iv + ciphertext)
record   = iv + ciphertext + tag (32 bytes)
```

Encrypt first, then MAC. The tag is checked before unpadding so there's no padding oracle. DES only has a 56-bit effective key (the README says so too). A new key per file means no single DES key encrypts enough data to hit the 64-bit block problem (Sweet32).

### RC4 + HMAC (Ajil)

```
params   = 16 random bytes (nonce, new for every file)
file key = HMAC-SHA256(dek, nonce)                 -> exactly what the README says
mac key  = HKDF(dek, salt=nonce, "kosanku/rc4/mac/v1", 32 bytes)
stream   = RC4 with the first 3072 bytes dropped, one stream for the whole file
record   = ciphertext + HMAC-SHA256(mac key, ad + ciphertext)
```

New nonce means a new key for every file, so the same keystream is never used twice. Dropping the first 3072 bytes skips the biased start of RC4. RC4 has no integrity of its own, so the HMAC is required.

### Size overhead per 1 MiB chunk

| Cipher | In header | Per chunk |
|--------|-----------|-----------|
| AES-GCM | 8 B | 16 B tag |
| DES-CBC | 16 B | 8 B IV + 1 to 8 B padding + 32 B tag |
| RC4 | 16 B | 32 B tag |

Plus the 12-byte header and 4 bytes per record for the length.

## Key helpers

`app/crypto/kdf.py` (done):

```python
def hkdf_sha256(ikm, *, salt, info, length) -> bytes
def hmac_sha256(key, msg) -> bytes
```

Everybody derives keys through these so we all do it the same way.

## Wrapping user keys

Naura's `app/crypto/keys.py`:

```
wrapped_dek = nonce (12) + AES-256-GCM(MASTER_KEY, dek, aad = "dek|" + user_id) + tag (16)
```

`MASTER_KEY` comes from `.env`. The app won't start if it isn't exactly 32 bytes.

## Errors in the app

| Error | HTTP | What the user sees | Audit log |
|-------|------|--------------------|-----------|
| `IntegrityError` | 409 | "This document failed its integrity check and was not returned." | `ok=False`, with cipher and item id |
| `PermissionError` | 404 | "Not found" (so we don't confirm the tenant exists) | `ok=False` |

A wrong key and edited data both just show up as `IntegrityError`. That's on purpose: we can't tell them apart, and we shouldn't try.
