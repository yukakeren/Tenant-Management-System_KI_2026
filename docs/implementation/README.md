# KosanKu Implementation Plan

This is our plan for building KosanKu in one week with four people. Everyone gets one part of the crypto, and one part of the web app, so nobody ends up just waiting for someone else to finish.

We're keeping the UI simple (server-rendered pages with Tailwind, no JS framework). Most of our time should go into the cipher backend and getting the full flow working: upload, encrypt, store, check access, verify, decrypt, download, delete.

## Docs in this folder

| File | What's in it |
|------|--------------|
| [crypto-spec.md](crypto-spec.md) | The shared cipher interface, the file format, and how each cipher works. Read this first. |
| [architecture.md](architecture.md) | Stack, folders, database tables, how keys are stored, and the main flows |
| [ata-aes-gcm.md](ata-aes-gcm.md) | Ata: AES-256-GCM, project skeleton, login, admin |
| [melvan-des-cbc.md](melvan-des-cbc.md) | Melvan: DES-CBC + HMAC, owner pages, access control, approving deletion |
| [naura-rc4.md](naura-rc4.md) | Naura: RC4 + HMAC, tenant pages (profile, uploads, deletion request) |
| [ajil-crypto-core.md](ajil-crypto-core.md) | Ajil: chunked file mode, keys, vault, benchmark and tamper scripts |
| [testing.md](testing.md) | Tests, the tamper checklist, the demo, and the report checklist |

## Who does what

| | Cipher | App |
|---|---|---|
| **Ata** | AES-256-GCM | Skeleton, DB, login/session, CSRF, base layout, admin pages |
| **Melvan** | DES-CBC with HMAC-SHA256 (encrypt-then-MAC) | Kos and rooms, assigning tenants, ownership checks, owner document view, approving deletion |
| **Naura** | RC4 (drop first 3072 bytes) with a per-file key and HMAC-SHA256 | Tenant profile and emergency contact, uploads (KTP, agreement, video), my documents, deletion request |
| **Ajil** | The chunked file format all three ciphers run inside, key wrapping, storing everything three times | Streaming upload/download, crypto-shredding, benchmark and tamper scripts, merging |

How we split the crypto: Ata, Melvan and Naura each only write the part that encrypts and decrypts **one chunk** for their cipher. Ajil writes everything around that (splitting files into chunks, the file header, keys, saving three copies). Because of that we can all work at the same time from day 2. We agree on the interface at the end of day 1, and after that we don't change it without talking about it first.

## How we work

- Quick sync every morning (15 min), and merge what's working into `main` every night.
- Never push straight to `main`. Make a branch (`feat/aes-gcm`, `feat/owner`, ...) and open a PR. Someone else has to review it before it gets merged.
- Ajil reviews anything in `app/crypto/`. Ata reviews routes and templates.
- If you're stuck for more than an hour, say so in the group.

## We're done when

- Every piece of tenant data (profile, KTP, rental agreement, room video) is saved on disk three times: once with AES-GCM, once with DES-CBC+HMAC, once with RC4+HMAC.
- Each copy decrypts on its own, and changing even one byte makes it fail with `IntegrityError` instead of returning broken data.
- A 200 MB video uploads and downloads without the server using more than about 100 MB of memory.
- Owners only see tenants in their own kos. Admin can never see document contents, not in the UI and not through any route.
- When a deletion request is approved, the tenant's files are deleted and their key is destroyed.
- `pytest` passes and `scripts/bench.py` prints the speed comparison for the report.

## Not doing

Rent payment, room booking, chat, digital signing, face recognition. Even if we have extra time.
