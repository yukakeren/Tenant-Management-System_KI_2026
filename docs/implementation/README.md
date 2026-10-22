# KosanKu Implementation Plan

This folder is the build plan for KosanKu. We have one week and four people. Each person owns one piece of the crypto layer, and also one slice of the web app so that nobody is stuck waiting on someone else.

The UI stays minimal: server-rendered pages, Tailwind, no JS framework. Most of the effort goes into the cipher backend and making the whole flow (upload, encrypt, store, check access, verify, decrypt, download, delete) work end to end.

## Documents

| File | What's inside |
|------|---------------|
| [architecture.md](architecture.md) | Stack, folder layout, data model, key hierarchy, request flows |
| [crypto-spec.md](crypto-spec.md) | Shared cipher interface, container format, AAD rules, error handling. **Everyone reads this first** |
| [person-1-aes-gcm.md](person-1-aes-gcm.md) | AES-256-GCM, plus project skeleton, auth, admin |
| [person-2-des-cbc.md](person-2-des-cbc.md) | DES-CBC + HMAC, plus the owner side, access control, deletion approval |
| [person-3-rc4.md](person-3-rc4.md) | RC4 with per-file keys + HMAC, plus the tenant side: profile, uploads, deletion request |
| [person-4-crypto-core.md](person-4-crypto-core.md) | Chunked streaming mode, key management, vault, benchmark and tamper tooling |
| [testing.md](testing.md) | Shared test plan, the demo script, and what counts as "done" |

## Team split

| | Cipher work | App work |
|---|---|---|
| **Person 1** | AES-256-GCM (AEAD, nonce = prefix + chunk counter) | Skeleton, DB, login/session, CSRF, base layout, admin account management |
| **Person 2** | DES-CBC + HMAC-SHA256 encrypt-then-MAC, per-file key | Kos/room CRUD, tenant assignment, ownership checks, owner document view, deletion approval |
| **Person 3** | RC4-drop3072, per-file key = HMAC-SHA256(user key, nonce), HMAC-SHA256 tag | Tenant profile and emergency contact, KTP/agreement/video upload, my documents, deletion request |
| **Person 4** | Chunked container format (the "mode" all three ciphers run inside), key wrapping, multi-cipher vault | Streaming upload/download, crypto-shredding, benchmark and tamper scripts, integration and merge duty |

The rule: **each cipher owner implements only the per-chunk seal/open** behind one interface (`ChunkSealer` / `ChunkOpener`). Person 4 owns everything around it (framing, chunking, keys, storing three ciphertexts). Because of this we can work in parallel from day 2. The interface gets frozen at the end of day 1.

Daily: 15 minute sync in the morning, and merge into `main` before going to sleep. Nobody pushes directly to `main`. Branches are `feat/<area>` and every PR needs one review from another member. Person 4 reviews all crypto PRs. Person 1 reviews all route/template PRs.

## Definition of done

- Every stored personal item (profile JSON, KTP, rental agreement, room video) exists on disk as **three** ciphertexts: AES-GCM, DES-CBC+HMAC, RC4+HMAC.
- Each of the three can be decrypted on its own, and flipping any single byte makes it fail with `IntegrityError`, never garbage output.
- A 200 MB video uploads and downloads while the process stays under ~100 MB RSS.
- An owner can only see tenants in their own kos. An admin can never get plaintext, not through the UI and not through any route.
- When a tenant's deletion is approved, their ciphertext files are removed and their wrapped key is destroyed.
- `pytest` is green and `scripts/bench.py` prints the comparison table we put in the report.

## Out of scope

Rent payment, room booking, chat, digital signing, face recognition. Don't build them, even if there's time left over.
