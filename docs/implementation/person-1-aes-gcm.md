# Person 1: AES-256-GCM + Skeleton, Auth, Admin

**Cipher:** AES-256-GCM. This is the default read cipher (`READ_CIPHER=aes`), so it's the one that runs on every normal download. It has to be solid.
**App:** project skeleton, DB models, login/session/CSRF, base layout, admin pages.
**Branches:** `feat/skeleton`, `feat/aes-gcm`, `feat/auth`, `feat/admin`

## Files you own

```
app/main.py, app/config.py, app/db.py, app/models.py
app/auth/{security.py, deps.py, routes.py}
app/crypto/aes_gcm.py
app/services/audit.py
app/routes/admin.py
app/templates/{base.html, login.html, change_password.html, admin/*}
app/static/input.css
scripts/seed.py
tests/crypto/test_aes_gcm.py, tests/web/test_auth.py
```

## Cipher task: `aes_gcm.py`

Spec: [crypto-spec.md §5](crypto-spec.md#aes-256-gcm-person-1-aes_gcmpy-id-1).

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from .base import CipherSuite, IntegrityError, register
from .kdf import hkdf_sha256

INFO = b"kosanku/aes-gcm/v1"

class _Sealer:
    def __init__(self, key, prefix):
        self.key, self.prefix = key, prefix

    def _nonce(self, index):
        if not 0 <= index < 2**32:
            raise OverflowError("too many chunks")
        return self.prefix + index.to_bytes(4, "big")

    def seal(self, index, plaintext, ad):
        c = AES.new(self.key, AES.MODE_GCM, nonce=self._nonce(index), mac_len=16)
        c.update(ad)
        ct, tag = c.encrypt_and_digest(plaintext)
        return ct + tag

class _Opener(_Sealer):
    def open(self, index, record, ad):
        if len(record) < 16:
            raise IntegrityError()
        c = AES.new(self.key, AES.MODE_GCM, nonce=self._nonce(index), mac_len=16)
        c.update(ad)
        try:
            return c.decrypt_and_verify(record[:-16], record[-16:])
        except ValueError:
            raise IntegrityError() from None

@register
class AesGcm(CipherSuite):
    id, name = 1, "aes"
    def new_params(self):          return get_random_bytes(8)
    def sealer(self, dek, params): return _Sealer(hkdf_sha256(dek, salt=b"", info=INFO, length=32), params)
    def opener(self, dek, params): return _Opener(hkdf_sha256(dek, salt=b"", info=INFO, length=32), params)
```

Things to get right:

- **Nonce uniqueness is everything in GCM.** If the same (key, nonce) gets used twice, the attacker gets the XOR of the plaintexts and can forge tags. Our nonce = random per-file prefix + chunk counter, so inside a file it's unique by construction, and across files it's unique with overwhelming probability. Write this down for the report.
- `params` must be exactly 8 bytes. The opener should raise `IntegrityError` otherwise (the header might be corrupted).
- Don't call `decrypt()` and then `verify()` separately. `decrypt_and_verify` makes sure no unauthenticated plaintext gets returned.

### Tests (`tests/crypto/test_aes_gcm.py`)

1. **Known answer:** take one vector from NIST CAVP `gcmEncryptExtIV256.rsp` with a 96-bit IV and non-empty AAD. Call PyCryptodome directly with it to make sure our wiring (mac_len, update order) matches NIST.
2. Nonce derivation: `_nonce(0) == prefix + b"\0\0\0\0"`, `_nonce(2**32)` raises.
3. Two sealers from the same DEK with different `new_params()` produce different ciphertexts for the same input.
4. Tag that's 1 byte short / record shorter than 16 → `IntegrityError` (not `ValueError`).
5. Must pass the shared `tests/crypto/test_contract.py` (Person 4 writes it).

## App tasks

### Day 1: skeleton
- `requirements.txt`: fastapi, uvicorn, jinja2, python-multipart, sqlalchemy, pycryptodome, argon2-cffi, itsdangerous, python-dotenv, pytest, httpx.
- `config.py` loads `.env`: `SECRET_KEY`, `MASTER_KEY`, `DATABASE_URL`, `STORAGE_DIR`, `READ_CIPHER` (default `aes`). Write `.env.example` with a one-liner that generates the keys: `python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"`.
- `models.py`: all tables from [architecture.md](architecture.md#data-model), including the unique constraints (`rooms.tenant_id`, `secret_items(subject_id, kind)`). Everyone else codes against these, so push them **by end of day 1**.
- Tailwind standalone CLI in `bin/` (gitignored, add the download command to the root README), `input.css` with `.btn .btn-danger .input .card .table`.
- `base.html`: top bar + flash messages + `{% block content %}`.

### Day 3: auth
- `security.py`: `hash_password`, `verify_password` (argon2id), `new_csrf_token`, `check_csrf(request, form_token)`.
- Session cookie: `https_only` behind a flag, `same_site="lax"`, max age 8 h. Session stores only `user_id` and `csrf`.
- `deps.py`: `current_user` (loads the user and rejects inactive ones), `require_role(*roles)`.
- `/login` gives the same error message for unknown email and wrong password. Add a simple per-IP failed-attempt counter in memory (5 tries / 5 min).
- **No public registration.** Every account is created by the admin (see "Account creation" in [architecture.md](architecture.md#account-creation-there-is-no-public-registration)).
- `GET/POST /account/password`: current password + new password twice (min 10 chars, not equal to the old one). On success set `must_change_password = False`.
- In `current_user`: if `must_change_password` is true, redirect every route except `/account/password` and `/logout` there.
- `seed.py`: 1 admin, 2 owners, 3 tenants (tenants get a DEK via `keys.create_dek`), 2 kos with rooms, 2 tenants already assigned. Seeded users get `must_change_password = False` so the demo doesn't start with password screens. Print the credentials.

### Day 4: admin
- `GET /admin/users`: table with email, role, active, created_at, and the room/kos if it's a tenant. **No profile fields.** This is the "view user non-sensitive data" use case.
- `POST /admin/users` with `email` + `role` (owner or tenant, never admin). Generate a temp password with `secrets.token_urlsafe(9)`, set `must_change_password = True`, and for tenants call `keys.create_dek(user)` (Person 4) so the tenant has a DEK from the start. Show the temp password once on the result page, never store or log it.
- `POST /admin/users/{id}/reset-password`: new temp password, `must_change_password = True`. Documents are not affected (the DEK isn't tied to the password).
- `POST /admin/users/{id}/toggle` activates/deactivates.
- Admin has no route that touches `secret_items`. Add a test that loops over every route in `app.routes` and checks that none under `/admin` call `vault` (you can just grep the imports in `routes/admin.py` in the test, crude but it works).

### Day 6: audit
- `audit.py`: `log(actor, action, target_type, target_id, ok=True, detail="")`. Everyone calls this.
- `GET /admin/audit`: last 200 rows, filter by `ok=False` so integrity failures and denied access are easy to spot.

### Day 7: hardening
- Security headers middleware: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, basic CSP (`default-src 'self'`).
- Custom 404/409/500 templates. No stack traces when `DEBUG=false`.
- `Content-Disposition: attachment` on every document download, so an uploaded HTML file can't execute in our origin.

## Handoffs

| You give | To | When |
|----------|----|------|
| `models.py`, `base.html`, `.btn/.input` classes | everyone | end of day 1 |
| `current_user`, `require_role`, `check_csrf` | P2, P3 | day 3 |
| `audit.log` | everyone | day 6 (stub with `pass` on day 3 so others can already call it) |

| You need | From | When |
|----------|------|------|
| `base.py`, `kdf.py`, contract tests | P4 | end of day 1 |
| `keys.create_dek` | P4 | day 3 |

## For the report

- How GCM gives confidentiality + integrity in one pass, and what the 16-byte tag covers (ciphertext + AAD).
- The nonce scheme and why reuse would be catastrophic.
- Benchmark row for AES from `scripts/bench.py`. It should be the fastest of the three on any CPU with AES-NI. Explain why.
