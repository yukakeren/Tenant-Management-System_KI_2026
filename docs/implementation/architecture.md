# Architecture

## Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Language | Python 3.12 | Everyone already knows it |
| Web | FastAPI + Jinja2 templates | Server-rendered, `UploadFile` streams, `StreamingResponse` for downloads |
| DB | SQLite via SQLAlchemy 2.0 | Zero setup. Only metadata and wrapped keys live here, the ciphertext lives on disk |
| Crypto | PyCryptodome | Still ships `DES` and `ARC4` without legacy-provider tricks (Node and the newer `cryptography` versions moved them to "decrepit"/legacy) |
| Passwords | argon2-cffi | Argon2id, default params |
| Sessions | Starlette `SessionMiddleware` (signed cookie) | Simple. Cookie only holds `user_id` and the CSRF token |
| UI | Tailwind CSS v4 standalone CLI | No Node needed. One `app.css` built from templates |
| Tests | pytest + httpx `TestClient` | |

Run locally:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # put MASTER_KEY and SECRET_KEY in here
python scripts/seed.py          # admin + 1 owner + 2 tenants + 1 kos
./bin/tailwindcss -i app/static/input.css -o app/static/app.css --watch &
uvicorn app.main:app --reload
```

## Folder layout

```
app/
  main.py                 # app factory, middleware, router includes          (P1)
  config.py               # env loading: MASTER_KEY, SECRET_KEY, READ_CIPHER  (P1)
  db.py, models.py        # engine, session, ORM models                       (P1)
  auth/
    security.py           # argon2 hash/verify, CSRF helpers                  (P1)
    deps.py               # current_user, require_role(...)                   (P1)
    routes.py             # /login, /logout                                   (P1)
  crypto/
    base.py               # CipherSuite, ChunkSealer, ChunkOpener, IntegrityError, registry (P4)
    kdf.py                # hkdf_sha256(), hmac_sha256()                      (P4)
    container.py          # chunked container format: write / read / verify   (P4)
    keys.py               # master key, DEK create / wrap / unwrap / destroy  (P4)
    vault.py              # store_item, open_item, verify_item, shred_user    (P4)
    aes_gcm.py            # AES-256-GCM suite                                 (P1)
    des_cbc.py            # DES-CBC + HMAC-SHA256 suite                       (P2)
    rc4.py                # RC4-drop3072 + HMAC-SHA256 suite                  (P3)
  services/
    access.py             # can_view_subject(actor, subject) etc.             (P2)
    uploads.py            # size limits, magic-byte checks                    (P3, P1 helps)
    audit.py              # audit_log writer                                  (P1)
  routes/
    tenant.py             # profile, uploads, my documents, deletion request  (P3)
    owner.py              # kos, rooms, assign, tenant docs, deletion approval(P2)
    admin.py              # accounts, audit log                               (P1)
  templates/
    base.html, login.html, tenant/*, owner/*, admin/*
  static/input.css, app.css
storage/blobs/<subject_id>/<item_id>.<cipher>.bin    # gitignored
scripts/seed.py (P1)  bench.py (P4)  tamper.py (P4)
tests/
  crypto/test_contract.py (P4)  test_aes_gcm.py (P1)  test_des_cbc.py (P2)  test_rc4.py (P3)
  crypto/test_container.py, test_keys.py, test_vault.py (P4)
  web/test_auth.py (P1)  test_access.py (P2)  test_tenant_flow.py (P3)
```

## Data model

```
users
  id, email (unique), password_hash, role ENUM(tenant, owner, admin),
  is_active, must_change_password, wrapped_dek BLOB NULL, created_at
  -- wrapped_dek is NULL for admin: admins own no personal data and get no key
  -- must_change_password is TRUE on creation/reset; the user must pick a new one at first login

kos
  id, owner_id -> users.id, name, address

rooms
  id, kos_id -> kos.id, number, tenant_id -> users.id UNIQUE NULL
  -- UNIQUE(tenant_id): one tenant occupies exactly one room

secret_items
  id, subject_id -> users.id, kind ENUM(profile, ktp, agreement, video),
  mime, plain_size, created_at, updated_at
  -- UNIQUE(subject_id, kind): re-upload replaces the old item

secret_blobs
  id, item_id -> secret_items.id, cipher ENUM(aes, des, rc4),
  path, ct_size, enc_ms
  -- one row per cipher, so 3 rows per item

deletion_requests
  id, tenant_id, reason, status ENUM(pending, approved, rejected, done),
  requested_at, decided_by -> users.id NULL, decided_at NULL

audit_log
  id, actor_id, action, target_type, target_id, ok BOOL, detail, at
  -- never write plaintext personal data here
```

What stays plaintext is only what we need for routing and what admin is allowed to see ("non-sensitive data" in the use case diagram): email, role, active flag, which room/kos, item kind, size, timestamps. Everything the tenant types or uploads is encrypted.

The profile is stored as **one** item (`kind = profile`) holding JSON:

```json
{
  "full_name": "...", "nik": "...", "birth_date": "YYYY-MM-DD", "gender": "...",
  "phone": "...", "origin_address": "...", "occupation": "...",
  "emergency_contact": { "name": "...", "relation": "...", "phone": "..." }
}
```

## Key hierarchy

```
MASTER_KEY  (32 bytes, base64 in .env, never in the DB, never logged)
   │  AES-256-GCM wrap, AAD = b"dek|" + user_id
   ▼
user DEK    (32 random bytes per tenant, stored as users.wrapped_dek)
   │  per-cipher derivation, see crypto-spec.md
   ├─ AES key        = HKDF(DEK, info="kosanku/aes-gcm")
   ├─ DES enc/mac    = HKDF(DEK, salt=file_salt, info="kosanku/des-*")
   └─ RC4 file key   = HMAC-SHA256(DEK, file_nonce)
```

- Only `crypto/keys.py` reads `MASTER_KEY`.
- `keys.unwrap_dek(subject, actor)` is the **only** way to get a DEK. It checks the actor first: either `actor.id == subject.id`, or the actor is an owner and `access.owner_has_tenant(actor, subject)` is true. Admin always gets `PermissionError`. That's how "admin has no way to decrypt documents" holds in code and isn't just a missing button.
- Honest limitation for the report: anyone with shell access to the server and the `.env` file can decrypt everything. Protecting against a compromised host is out of scope for this week.

## Main flows

### Account creation (there is no public registration)

```
admin:  POST /admin/users  {email, role: owner|tenant}
          1. generate a random temporary password (12 chars), argon2 hash it
          2. insert user with must_change_password = TRUE
          3. if role == tenant: keys.create_dek(user)
          4. show the temp password ONCE on the result page; admin hands it over (owner relays to tenant)
          5. audit("create_user")
user:   first login → every route redirects to /account/password until a new password is set
owner:  assigns the tenant to a room by email (the account must already exist)
```

The temp password is never stored in plaintext or written to the audit log. After the user changes it, the admin no longer knows any working credential. The admin can reset it (new temp password, `must_change_password = TRUE`), but resetting doesn't give access to documents: the tenant's DEK is wrapped with `MASTER_KEY`, not the password, so documents survive a reset and admin still can't unwrap them.

### Upload (tenant uploads KTP or video)

```
browser ──multipart──▶ POST /tenant/documents/{kind}
  1. require_role(tenant), CSRF check
  2. uploads.validate(kind, file)           size limit + magic bytes
  3. dek = keys.unwrap_dek(me, me)
  4. vault.store_item(me, kind, file.file, dek)
       ├─ read 1 MiB at a time (one read-ahead to know which chunk is final)
       ├─ feed every chunk to 3 container writers (aes, des, rc4)
       ├─ write storage/blobs/<me>/<item>.<cipher>.bin.tmp, then rename
       └─ insert secret_items + 3 secret_blobs rows (with enc_ms)
  5. audit("upload", item) ; redirect to /tenant/documents
```

FastAPI's `UploadFile` spools anything over 1 MB to a temp file, so plaintext touches `/tmp` for a moment. We close it right after step 4. This goes into the report as a known limitation.

### Download (owner views a tenant's KTP)

```
GET /owner/tenants/{tid}/documents/{kind}?cipher=aes
  1. require_role(owner); access.owner_has_tenant(me, tid) or 404
  2. dek = keys.unwrap_dek(tenant, me)
  3. blob = pick secret_blob for cipher (default settings.READ_CIPHER = "aes")
  4. vault.verify_item(blob, dek)           pass 1: authenticate every chunk, output nothing
       └─ IntegrityError → 409 page "Data failed integrity check", audit(ok=False)
  5. StreamingResponse(vault.open_item(blob, dek))   pass 2: decrypt chunk by chunk
```

The `?cipher=` parameter is there so the demo can show that all three copies decrypt to the same file. Only the subject and their owner can use it.

We do two passes because if we decrypted and streamed in one pass, a tampered chunk 150 would only be caught after 149 MB had already gone out to the browser. Two passes cost one extra read. It's worth it.

### Deletion after move-out

```
tenant: POST /tenant/deletion-request         → status pending
owner:  POST /owner/deletion-requests/{id}/approve
          1. access check
          2. vault.shred_user(tenant)
               ├─ delete every blob file for the subject
               ├─ delete secret_blobs / secret_items rows
               └─ keys.destroy_dek(tenant)  → users.wrapped_dek = NULL
          3. room.tenant_id = NULL, user.is_active = False
          4. request.status = done, audit
```

Even if a backup copy of a blob survives somewhere, it can't be decrypted once the wrapped DEK is gone (crypto-shredding).

## Routes summary

| Role | Route | Owner |
|------|-------|-------|
| all | `GET/POST /login`, `POST /logout` | P1 |
| all | `GET/POST /account/password` (forced on first login, also reachable from the top bar) | P1 |
| admin | `GET /admin/users`, `POST /admin/users` (create owner **or tenant**), `POST /admin/users/{id}/reset-password`, `POST /admin/users/{id}/toggle`, `GET /admin/audit` | P1 |
| owner | `GET/POST /owner/kos`, `GET/POST /owner/kos/{id}/rooms`, `POST /owner/rooms/{id}/assign` (by tenant email), `POST /owner/rooms/{id}/unassign` | P2 |
| owner | `GET /owner/tenants`, `GET /owner/tenants/{id}`, `GET /owner/tenants/{id}/documents/{kind}` | P2 |
| owner | `GET /owner/deletion-requests`, `POST .../{id}/approve`, `POST .../{id}/reject` | P2 |
| tenant | `GET/POST /tenant/profile` | P3 |
| tenant | `GET /tenant/documents`, `POST /tenant/documents/{kind}`, `GET /tenant/documents/{kind}` | P3 |
| tenant | `GET/POST /tenant/deletion-request` | P3 |

## UI

Pages are still plain forms and tables:

- Shared classes go in `input.css` with `@apply`: `.btn`, `.btn-danger`, `.input`, `.card`, `.table`.
- Flash messages come from the session (success = green, error = red).
- Owner tenant detail page shows the profile and a row per document with three small download links: `AES`, `DES`, `RC4`. This makes the "same data, three ciphers" point visible in the demo.
