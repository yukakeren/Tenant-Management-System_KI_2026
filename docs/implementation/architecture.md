# Architecture

## Stack

| Part | What we use | Why |
|------|-------------|-----|
| Language | Python 3.12 | We all know it |
| Web | FastAPI + Jinja2 templates | Pages are rendered on the server, and it handles big uploads/downloads as streams |
| Database | SQLite with SQLAlchemy 2.0 | No setup. Only metadata and wrapped keys go here, the encrypted files are on disk |
| Crypto | PyCryptodome | It still has DES and RC4 built in. Node and the newer `cryptography` package moved those to legacy modules |
| Passwords | argon2-cffi | Argon2id with default settings |
| Sessions | Starlette `SessionMiddleware` (signed cookie) | Simple. The cookie only has the user id and the CSRF token |
| UI | Tailwind CSS v4 (standalone CLI) | No Node needed, builds one `app.css` |
| Tests | pytest + httpx | |

To run it, see the "Development" section in the root README.

## Folders (and who owns what)

```
app/
  main.py                 app setup, middleware, routers                      Ata
  config.py               reads .env (MASTER_KEY, SECRET_KEY, READ_CIPHER)    Ata
  db.py, models.py        database connection and tables                      Ata
  auth/
    security.py           password hashing, CSRF                              Ata
    deps.py               current_user, require_role(...)                     Ata
    routes.py             /login, /logout, /account/password                  Ata
  crypto/
    base.py               cipher interface, IntegrityError, registry          Naura
    kdf.py                hkdf_sha256(), hmac_sha256()                        Naura
    container.py          chunked file format: write / read / verify          Naura
    keys.py               master key, create / wrap / unwrap / destroy DEK    Naura
    vault.py              store_item, open_item, verify_item, shred_user      Naura
    aes_gcm.py            AES-256-GCM                                         Ata
    des_cbc.py            DES-CBC + HMAC-SHA256                               Melvan
    rc4.py                RC4-drop3072 + HMAC-SHA256                          Ajil
  services/
    access.py             who can see whose data                              Melvan
    uploads.py            size limits, file type checks                       Ajil (Ata helps)
    audit.py              writes to audit_log                                 Ata
  routes/
    tenant.py             profile, uploads, my documents, deletion request    Ajil
    owner.py              kos, rooms, assign, tenant docs, approve deletion   Melvan
    admin.py              accounts, audit log                                 Ata
  templates/              base.html, login.html, tenant/, owner/, admin/
  static/                 input.css (source), app.css (built, not in git)
storage/blobs/<subject_id>/<item_id>.<cipher>.bin                             not in git
scripts/                  seed.py (Ata), bench.py and tamper.py (Naura)
tests/
  crypto/                 test_contract.py, test_container.py, test_keys.py, test_vault.py (Naura)
                          test_aes_gcm.py (Ata), test_des_cbc.py (Melvan), test_rc4.py (Ajil)
  web/                    test_auth.py (Ata), test_access.py (Melvan), test_tenant_flow.py (Ajil)
```

## Tables

```
users
  id, email (unique), password_hash, role (tenant / owner / admin),
  is_active, must_change_password, wrapped_dek (nullable), created_at
  -- admins have no wrapped_dek: they don't own personal data so they don't get a key
  -- must_change_password is true after the admin creates or resets the account

kos
  id, owner_id, name, address

rooms
  id, kos_id, number, tenant_id (unique, nullable)
  -- unique tenant_id: one tenant can only be in one room

secret_items
  id, subject_id, kind (profile / ktp / agreement / video), mime, plain_size, created_at, updated_at
  -- unique (subject_id, kind): uploading again replaces the old one

secret_blobs
  id, item_id, cipher (aes / des / rc4), path, ct_size, enc_ms
  -- one row per cipher, so 3 rows per item

deletion_requests
  id, tenant_id, owner_id, reason, status (pending / approved / rejected / done),
  reject_reason, requested_at, decided_by, decided_at

audit_log
  id, actor_id, action, target_type, target_id, ok, detail, at
  -- never put personal data in here
```

The only things we keep unencrypted are what we need for routing, plus what admin is allowed to see (the "non-sensitive data" in the use case diagram): email, role, active or not, which room and kos, document type, size, and dates. Anything the tenant types or uploads is encrypted.

The profile is saved as one item (`kind = profile`) containing JSON:

```json
{
  "full_name": "...", "nik": "...", "birth_date": "YYYY-MM-DD", "gender": "...",
  "phone": "...", "origin_address": "...", "occupation": "...",
  "emergency_contact": { "name": "...", "relation": "...", "phone": "..." }
}
```

## Keys

```
MASTER_KEY   32 bytes, base64 in .env. Never in the database, never logged.
   |  wrapped with AES-256-GCM, aad = "dek|" + user_id
   v
user DEK     32 random bytes per tenant, saved as users.wrapped_dek
   |  each cipher derives its own keys (see crypto-spec.md)
   |-- AES key       = HKDF(DEK, "kosanku/aes-gcm/v1")
   |-- DES keys      = HKDF(DEK, file salt, "kosanku/des-cbc/...")
   '-- RC4 file key  = HMAC-SHA256(DEK, file nonce)
```

- Only `crypto/keys.py` reads `MASTER_KEY`.
- `keys.unwrap_dek(subject, actor)` is the only way to get a DEK, and it checks who's asking first. Either it's the tenant themselves, or an owner whose kos the tenant lives in. Admin always gets `PermissionError`. That's how "admin can't decrypt documents" is enforced in the code, not just by hiding a button.
- Limitation for the report: anyone with access to the server and the `.env` file can decrypt everything. We're not trying to protect against a hacked server this week.

## Main flows

### Creating accounts (there's no sign-up page)

```
admin:  POST /admin/users  (email, role = owner or tenant)
          1. make a random temporary password and hash it
          2. save the user with must_change_password = true
          3. if it's a tenant: keys.create_dek(user)
          4. show the temporary password once; admin gives it to the person (or to the owner, who passes it on)
          5. audit log
user:   first login -> sent to /account/password until they set their own password
owner:  puts the tenant in a room using their email (the account has to exist already)
```

We never save the temporary password in plain text or put it in the audit log. Once the user changes it, the admin doesn't know any working password. The admin can reset a password, but that doesn't open the documents: the DEK is wrapped with `MASTER_KEY`, not the password. So documents survive a reset and the admin still can't unwrap them.

### Uploading (tenant uploads KTP or video)

```
POST /tenant/documents/{kind}
  1. require_role(tenant), check CSRF
  2. uploads.validate(kind, file)           size limit + check the real file type
  3. dek = keys.unwrap_dek(me, me)
  4. vault.store_item(me, kind, file.file, dek)
       - read 1 MiB at a time (reads one chunk ahead to know which one is last)
       - feed every chunk to all 3 ciphers
       - write to <item>.<cipher>.bin.tmp, then rename when done
       - save secret_items + 3 secret_blobs rows (with how long each took)
  5. audit log, redirect to /tenant/documents
```

FastAPI saves uploads bigger than 1 MB to a temp file, so the plaintext is on disk for a moment. We close it right after step 4. This goes in the report as a known limitation.

### Downloading (owner opens a tenant's KTP)

```
GET /owner/tenants/{tid}/documents/{kind}?cipher=aes
  1. require_role(owner); access.owner_has_tenant(me, tid), otherwise 404
  2. dek = keys.unwrap_dek(tenant, me)
  3. pick the blob for the chosen cipher (default READ_CIPHER = aes)
  4. vault.verify_item(...)       first pass: check every chunk, output nothing
       IntegrityError -> 409 page, audit log with ok=False
  5. StreamingResponse(vault.open_item(...))     second pass: decrypt and send chunk by chunk
```

`?cipher=` is there for the demo, to show all three copies give back the same file. Only the tenant and their owner can use it.

Why two passes: if we decrypted and sent in one go and chunk 150 was tampered with, the browser would already have 149 MB before we noticed. Reading the file twice is slower, but it's worth it.

### Deleting after move-out

```
tenant: POST /tenant/deletion-request          -> pending
owner:  POST /owner/deletion-requests/{id}/approve
          1. access check
          2. vault.shred_user(tenant)
               - delete all of the tenant's blob files
               - delete their secret_blobs and secret_items rows
               - keys.destroy_dek(tenant) -> wrapped_dek = NULL
          3. empty the room, deactivate the user
          4. status = done, audit log
```

Even if a copy of a file survives somewhere (a backup, for example), nobody can decrypt it once the key is gone. This is called crypto-shredding.

## Routes

| Who | Route | Built by |
|-----|-------|----------|
| everyone | `GET/POST /login`, `POST /logout` | Ata |
| everyone | `GET/POST /account/password` (forced on first login, also in the top bar) | Ata |
| admin | `GET /admin/users`, `POST /admin/users` (create owner or tenant), `POST /admin/users/{id}/reset-password`, `POST /admin/users/{id}/toggle`, `GET /admin/audit` | Ata |
| owner | `GET/POST /owner/kos`, `GET/POST /owner/kos/{id}/rooms`, `POST /owner/rooms/{id}/assign` (by email), `POST /owner/rooms/{id}/unassign` | Melvan |
| owner | `GET /owner/tenants`, `GET /owner/tenants/{id}`, `GET /owner/tenants/{id}/documents/{kind}` | Melvan |
| owner | `GET /owner/deletion-requests`, `POST .../{id}/approve`, `POST .../{id}/reject` | Melvan |
| tenant | `GET/POST /tenant/profile` | Ajil |
| tenant | `GET /tenant/documents`, `POST /tenant/documents/{kind}`, `GET /tenant/documents/{kind}` | Ajil |
| tenant | `GET/POST /tenant/deletion-request` | Ajil |

## UI

Pages are just forms and tables for now:

- Shared styles are in `input.css`: `.btn`, `.btn-danger`, `.input`, `.card`, `.table`. Change how they look if you want, but keep the names, since every page uses them.
- Flash messages come from the session (green for success, red for errors).
- The owner's tenant page shows the profile and one row per document, with three small download links: `AES`, `DES`, `RC4`. That makes "same data, three ciphers" easy to see in the demo.
