# KosanKu: Report

Draft. Each section names who owns it; that person checks and finishes it. Everything marked **TODO** still needs a human decision or a citation check.

## 1. What we built

KosanKu replaces sending tenant documents over WhatsApp. A kos owner gets a tenant's profile, emergency contact, KTP, rental agreement and room video in one place, encrypted, and only for tenants who live in their kos.

Three roles:

| Role | UU PDP role | Can do |
|------|-------------|--------|
| Tenant | Data subject | Fill in profile and emergency contact, upload KTP / agreement / room video, download own documents, request deletion |
| Owner (exactly one) | Data controller | Manage kos and rooms, move tenants out, read documents of current tenants only, decide deletion requests |
| Admin | Operator | Create accounts (a tenant only together with the room they paid for), deactivate accounts, reset passwords, read the audit log, decide deletion requests that have no owner. Can never decrypt anything |

Stack: FastAPI with server-rendered Jinja templates, SQLite through SQLAlchemy, PyCryptodome for the ciphers, argon2id for passwords.

### Architecture and keys

```
browser ──HTTPS──> FastAPI routes ──> services/access.py   (who may see whom)
                         │
                         └──> crypto/vault.py ──> crypto/container.py ──> aes_gcm / des_cbc / rc4
                                   │                                         (one chunk each)
                                   ├──> crypto/keys.py (wrap / unwrap DEK, checks access first)
                                   ├──> SQLite: metadata, wrapped DEKs, audit log
                                   └──> storage/blobs/<tenant>/<item>.<cipher>.bin
```

```
MASTER_KEY  (32 bytes, .env only)
   │  AES-256-GCM, aad = "dek|" + user_id
   ▼
user DEK  (32 random bytes per tenant, stored wrapped in users.wrapped_dek)
   ├── AES key       = HKDF(DEK, info="kosanku/aes-gcm/v1")
   ├── DES enc key   = HKDF(DEK, file salt, "kosanku/des-cbc/enc/v1", 8 bytes)
   ├── DES MAC key   = HKDF(DEK, file salt, "kosanku/des-cbc/mac/v1")
   ├── RC4 file key  = HMAC-SHA256(DEK, file nonce)
   └── RC4 MAC key   = HKDF(DEK, file nonce, "kosanku/rc4/mac/v1")
```

The only way to get a DEK is `keys.unwrap_dek(subject, actor)`, which first asks `access.can_view_subject`. Admins always get `PermissionError`. Changing a password doesn't touch the DEK, so an admin password reset doesn't open any documents.

Every item (profile, KTP, agreement, video) is stored three times, once per cipher. Each copy decrypts on its own. The upload reads the file once and feeds every 1 MiB chunk to all three ciphers.

## 2. AES-256-GCM

GCM is counter mode for secrecy plus a GHASH authenticator. The 16-byte tag covers both the ciphertext and the additional authenticated data (AAD), so one call gives confidentiality and integrity. We always use `decrypt_and_verify`, so no unverified plaintext is ever returned.

- Key: `HKDF(DEK, info="kosanku/aes-gcm/v1")`, 256 bits.
- Nonce: 8 random bytes per file (stored in the header) plus the 4-byte chunk index. That's unique inside a file and practically never repeats across files.
- Why nonce reuse would be a disaster: two messages under the same key and nonce share a keystream, so XORing the ciphertexts gives the XOR of the plaintexts, and the GHASH key can be recovered, which lets an attacker forge tags.
- Tests: GCM spec test case 16 (256-bit key, 96-bit IV, with AAD), nonce construction, short record gives `IntegrityError`, fresh params per file, contract tests.

## 3. DES-CBC + HMAC-SHA256 

DES is broken by key size: 56 effective bits. The EFF's Deep Crack found a DES key in under 3 days in 1998, and today it's far faster. The 64-bit block also runs into Sweet32 (birthday collisions after about 32 GiB under one key). We use DES only because the assignment asks for it, and limit the damage:

- A new 16-byte salt per file, so every file has its own DES key and no key encrypts anywhere near 32 GiB.
- A random 8-byte IV per chunk, PKCS#7 padding.
- Encrypt-then-MAC: `tag = HMAC-SHA256(mac key, ad + iv + ciphertext)`. The tag is checked before decrypting or unpadding, so there's no padding oracle. MAC-then-encrypt would force us to decrypt and unpad first, and the difference between "bad padding" and "bad MAC" is exactly what a padding-oracle attack uses.
- Parity bits on the key are set explicitly to make the 56-bit effective key visible.

## 4. RC4 + HMAC-SHA256

RC4 builds a 256-byte permutation from the key (key scheduling, KSA), then generates the keystream by swapping entries (PRGA) and XORs it with the data. Known problems: the first bytes of the keystream are biased (Fluhrer–Mantin–Shamir, Mantin–Shamir), related keys leak the key (how WEP was broken), and TLS banned it in RFC 7465. It has no integrity of its own: flipping a ciphertext bit flips the same plaintext bit.

Our three fixes and what each stops:

| Fix | Stops |
|-----|-------|
| New key per file: `HMAC-SHA256(DEK, 16-byte random nonce)` | Keystream reuse across files, and related-key attacks (keys are PRF outputs, not "base key + IV") |
| Drop the first 3072 keystream bytes | The biased start of the keystream |
| HMAC-SHA256 over `ad + ciphertext` per chunk | Bit-flipping and every other edit (see the bit-flipping test in `test_rc4.py`) |

RC4 is also stateful: one stream runs through the whole file, so chunks have to be processed in order, and the opener rejects out-of-order indexes.

## 5. Chunked format and tamper checklist

Files are encrypted in 1 MiB chunks so a 200 MB video never sits in memory. The file is a `KSK1` header (magic, version, cipher id, chunk size, params) followed by length-prefixed records. Each chunk is authenticated with

```
context  = "kosanku|" + subject_id + "|" + item_id + "|" + kind
chunk_ad = header + context + chunk index (8 bytes) + is_last (1 byte)
```

Without the index and the last-chunk flag, chunked encryption can be reordered or truncated without detection. This is the problem the STREAM construction (Hoang, Reyhanitabar, Rogaway and Vizár, 2015) solves, and our AD follows the same idea. Putting `subject_id`, `item_id` and `kind` in the AD means a valid file moved to another tenant, or swapped between KTP and agreement, also fails. The reader rejects any record length above `chunk_size + 64` before allocating, so a corrupted length can't make us allocate gigabytes.

Downloads read the file twice: first verify every chunk without output, then decrypt and stream. Otherwise a tampered chunk 150 would be noticed only after the browser already had 149 MB.

### Tamper checklist

Every cell is one test in `tests/crypto/test_tamper_checklist.py`, run against real files written by the vault (2.5 MiB file, so three records). Each ends in `IntegrityError` from both the verify pass and the decrypt pass.

| | AES | DES | RC4 |
|---|---|---|---|
| Change 1 byte in the header | ✅ | ✅ | ✅ |
| Change 1 byte in the params | ✅ | ✅ | ✅ |
| Change 1 byte in the ciphertext | ✅ | ✅ | ✅ |
| Change 1 byte in the tag | ✅ | ✅ | ✅ |
| Change the DES IV | n/a | ✅ | n/a |
| Swap two chunks | ✅ | ✅ | ✅ |
| Remove the last record | ✅ | ✅ | ✅ |
| Cut the last record in half | ✅ | ✅ | ✅ |
| Add a copied record at the end | ✅ | ✅ | ✅ |
| Move the file to another tenant | ✅ | ✅ | ✅ |
| Swap KTP and agreement | ✅ | ✅ | ✅ |
| Wrong key | ✅ | ✅ | ✅ |

Over HTTP, a tampered copy gives a 409 page and an audit-log row with `ok=False`, while the other two copies of the same document still download (`test_owner_flow.py::test_tampered_copy_gives_409_and_audit`). A wrong key and edited data look the same on purpose: we never say why a check failed.

## 6. Access control (Melvan)

`services/access.py` is the single place that decides who sees whom:

- Tenant: only themselves. Tenant routes have no ids in the URL; they always use the logged-in user.
- Owner: only tenants currently in a room of one of their kos. The filter is in the SQL query (`Kos.owner_id == me.id`), not a check after loading, so a forgotten check returns nothing instead of leaking.
- Admin: never. Enforced in `unwrap_dek`, not only by hiding buttons.
- Another owner's ids give 404, not 403, so you can't probe which ids exist.
- Moving a tenant out ends the owner's access immediately; the tenant's data stays so they can still ask for deletion.

Other protections: argon2id passwords, CSRF token on every POST, 5 failed logins per IP per 5 minutes, signed session cookie (HTTP-only, SameSite=Lax, HTTPS-only in production, 8 hours), forced password change after the admin creates or resets an account, and security headers (CSP `default-src 'self'`, `X-Frame-Options: DENY`, `nosniff`). Every download is sent as `Content-Disposition: attachment`.

Test results (all passing):

| Test | Checks |
|------|--------|
| `tests/web/test_access.py` | The access service: owner A vs owner B, admin always denied, unassigned tenants |
| `tests/web/test_owner_flow.py` | Over HTTP: owner A gets 404 on owner B's kos, rooms, tenants, documents and deletion requests; download of each copy; move-out ends access |
| `tests/web/test_auth.py` | Login, same error for wrong email and wrong password, rate limit, CSRF, roles, inactive users, forced password change, admin can't reach tenant data by any URL, admin routes don't contain any decrypting call |
| `tests/crypto/test_keys.py` | Swapping `wrapped_dek` between users fails, admin always gets `PermissionError` |

## 7. UU PDP 

**Classification.** UU No. 27/2022 Art. 4 splits personal data into specific data (health, biometric, genetic, criminal records, child data, personal financial data) and general data (name, sex, nationality, religion, marital status, and data combined to identify a person). The elucidation of Art. 4(2)(b) names a facial image as biometric data, so the KTP photo and possibly the room video count as specific data. The NIK, name, birth date, address and phone are general data that identify a person when combined. We treat all of it the same way: encrypted at rest, only visible to the subject and their controller.

**Roles.** The tenant is the data subject, the kos owner the data controller, and the admin an operator who runs the system but has no access to content.

**Deletion.** A tenant can request deletion after moving out. The kos owner who was responsible when the request was made decides it; if the tenant had no room at that point, the admin decides. Approving deletes all three copies of every document, the database rows, and the tenant's wrapped DEK (crypto-shredding). Any copy that survives somewhere, such as a backup, can't be decrypted once the key is gone. **TODO:** cite the article on the subject's right to deletion (we believe Art. 8) and the controller's security obligation, and check the article numbers.

**Data minimisation.** Unencrypted are only what routing needs and what the admin may see: email, role, active or not, which room, document type, size and dates. The audit log never contains personal data.

## 8. Benchmark and memory

### Speed

`python scripts/bench.py`, container only (no HTTP), median of 5 runs, one cipher at a time. Intel Core Ultra 7 155H, Python 3.12, PyCryptodome 4.1.0.

| Size | Cipher | Encrypt MB/s | Decrypt MB/s | Overhead (bytes) |
|---|---|---:|---:|---:|
| 1 KB | AES | 7.6 | 9.7 | 40 |
| 1 KB | DES | 6.3 | 7.2 | 80 |
| 1 KB | RC4 | 11.3 | 14.7 | 64 |
| 1 MiB | AES | 515.4 | 1,061.3 | 40 |
| 1 MiB | DES | 31.0 | 33.2 | 80 |
| 1 MiB | RC4 | 250.4 | 332.2 | 64 |
| 10 MiB | AES | 661.3 | 1,105.4 | 220 |
| 10 MiB | DES | 31.1 | 33.1 | 548 |
| 10 MiB | RC4 | 272.7 | 332.3 | 388 |
| 100 MiB | AES | 800.1 | 1,087.8 | 2,020 |
| 100 MiB | DES | 31.1 | 32.9 | 5,228 |
| 100 MiB | RC4 | 295.8 | 327.2 | 3,628 |
| 200 MiB | AES | 830.8 | 1,073.3 | 4,020 |
| 200 MiB | DES | 30.9 | 32.5 | 10,428 |
| 200 MiB | RC4 | 299.5 | 326.0 | 7,228 |

AES-GCM is by far the fastest because the CPU has AES-NI and carry-less multiply (PCLMULQDQ) instructions, so both encryption and the GHASH tag run in hardware. DES is the slowest by an order of magnitude: 8-byte blocks, 16 Feistel rounds in software, no hardware support, and the HMAC on top. RC4 itself is very fast, but it pays for a separate HMAC-SHA256 pass over every byte, which GCM gets almost for free. At 1 KB every cipher is dominated by fixed costs (key derivation, header), not throughput. The overhead column matches the spec exactly. Per 1 MiB chunk: AES adds a 16 B tag, RC4 a 32 B tag, DES an 8 B IV + 8 B padding (a full block, since 1 MiB is a multiple of 8) + 32 B tag, each plus a 4 B record length. On top comes a 20 B (AES) or 28 B (DES, RC4) header. For 200 MiB: AES 200 × 20 + 20 = 4,020 B, about 0.002 %.

### Memory

`tests/web/test_memory.py` starts a real uvicorn process, uploads a 200 MiB random video through `POST /tenant/documents/video`, then downloads it with each cipher and compares the SHA-256. It reads the server's peak resident memory (`VmHWM`) from `/proc`.

| Step | Peak RSS (MiB) | Time |
|---|---:|---:|
| After startup and login (peak reset) | 77.2 | |
| 200 MiB upload, encrypted with all three ciphers | 83.2 | 7.6 s |
| Verify + download, AES | 83.2 | 0.4 s |
| Verify + download, DES | 84.1 | 12.5 s |
| Verify + download, RC4 | 84.1 | 1.3 s |

Peak 84 MiB, under the 100 MiB budget. The same run with a 20 MiB file peaks at 85 MiB.

The process uses about 77 MiB before the upload (Python, FastAPI, SQLAlchemy, PyCryptodome). The 200 MiB upload, encrypted three times, adds about 6–8 MiB, and the result is the same for a 20 MiB file, so memory doesn't grow with file size. The upload is spooled to a temporary file by the multipart parser and read back 1 MiB at a time.

One thing we found while measuring: each login briefly uses about 64 MiB more, because that is argon2id's default memory cost. That's by design (it makes password cracking on GPUs expensive), but several logins at the same moment would each need 64 MiB. The test resets the peak counter after logging in so it measures only the upload and download.

## 9. Limitations and what we'd do with more time

- **The master key is in `.env`.** Anyone with the server and `.env` can decrypt everything. With more time: a KMS or HSM holding the master key, so the server can unwrap DEKs but never sees the master key itself.
- **The plaintext upload briefly sits in a temp file.** The multipart parser spools uploads over 1 MB to disk before we encrypt. We close (and so delete) it right after encrypting, but it isn't wiped and could be recovered from the disk. With more time: encrypt while parsing the multipart stream.
- **A hacked server sees everything** it decrypts while running. Out of scope this week.
- **DES and RC4 are only here because the assignment asks for them.** For real use, AES-GCM alone would be the right choice.
- **The login limit is kept in the server's memory.** It resets on restart, and with several worker processes each one counts separately. Fine for one process; with more time it would live in the database or Redis.
- **Backups aren't wiped on deletion**, they become unreadable because the key is gone. That's crypto-shredding, but if a backup of the database also has the old `wrapped_dek`, and the attacker has `MASTER_KEY`, it could be unwrapped. Backups of the database must be rotated out.
- **SQLite** is fine for one server. For several servers we'd switch `DATABASE_URL` to PostgreSQL; the code uses SQLAlchemy, so only the driver and URL change.
