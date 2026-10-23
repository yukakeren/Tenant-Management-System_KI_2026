# Ata: AES-256-GCM, Skeleton, Login, Admin

**Cipher:** AES-256-GCM. It's the default cipher for downloads (`READ_CIPHER=aes`), so every normal download goes through it. It needs to be solid.
**App:** project skeleton, database models, login and sessions, base layout, admin pages.
**Branches:** `feat/aes-gcm`, `feat/auth`, `feat/admin`

## My files

```
app/main.py, app/config.py, app/db.py, app/models.py
app/auth/security.py, deps.py, routes.py
app/crypto/aes_gcm.py
app/services/audit.py
app/routes/admin.py
app/templates/base.html, login.html, change_password.html, admin/
app/static/input.css
scripts/seed.py
tests/crypto/test_aes_gcm.py, tests/web/test_auth.py
```

## Cipher: `aes_gcm.py`

Spec: [crypto-spec.md](crypto-spec.md#aes-256-gcm-ata).

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

Watch out for:

- **Never reuse a nonce with the same key.** In GCM that leaks the XOR of the two plaintexts and lets someone forge tags. Our nonce is a random prefix per file plus the chunk number. That's always different inside one file, and practically never repeats across files. Explain this in the report.
- `params` must be exactly 8 bytes. If it isn't, the header is probably broken, so raise `IntegrityError`.
- Use `decrypt_and_verify`, not `decrypt()` and then `verify()`. That way we never hand back plaintext that hasn't been checked.

### Tests (`tests/crypto/test_aes_gcm.py`)

- [x] Known-answer test (GCM spec test case 16: 256-bit key, 96-bit IV, with AAD), already passing
- [ ] `_nonce(0) == prefix + b"\0\0\0\0"`, and `_nonce(2**32)` raises
- [ ] Same DEK, different `new_params()` gives a different ciphertext for the same input
- [ ] A record shorter than 16 bytes raises `IntegrityError`, not `ValueError`
- [ ] Passes `tests/crypto/test_contract.py` (just uncomment `aes_gcm` in `app/crypto/__init__.py` and it runs automatically)

## App

### Day 1: skeleton (done)
- [x] `requirements.txt`, `.env.example`, `config.py` (won't start with bad keys)
- [x] `models.py` with all the tables and unique constraints
- [x] Tailwind setup, `input.css` with the shared classes, `base.html`

### Day 3: login
- `security.py`: `hash_password`, `verify_password` (argon2id), `new_csrf_token`, `check_csrf(request, token)`.
- Session cookie: `same_site="lax"`, expires after 8 hours, HTTPS-only when `DEBUG=false`. Only `user_id` and `csrf` go in the session.
- `deps.py`: `current_user` (blocks inactive users) and `require_role(*roles)`.
- `/login` shows the same error for a wrong email and a wrong password. Also add a simple in-memory limit per IP: 5 failed tries per 5 minutes.
- No sign-up page. The admin creates all accounts (see "Creating accounts" in [architecture.md](architecture.md#creating-accounts-theres-no-sign-up-page)).
- `GET/POST /account/password`: old password, then the new one twice (at least 10 characters, not the same as the old one). On success set `must_change_password = False`.
- In `current_user`: if `must_change_password` is true, send them to `/account/password` for every route except that page and `/logout`.
- `seed.py`: 1 admin, 2 owners, 3 tenants (with keys from `keys.create_dek`), 2 kos with rooms, 2 tenants already in rooms. Set `must_change_password = False` for seeded users so the demo doesn't start with password screens. Print the logins at the end.

### Day 4: admin pages
- `GET /admin/users`: email, role, active, created date, and the room/kos for tenants. **No profile data.** This is the "view user non-sensitive data" use case.
- `POST /admin/users` with email and role (owner or tenant, never admin). Make a temp password with `secrets.token_urlsafe(9)` and set `must_change_password = True`. For tenants, call Ajil's `keys.create_dek(user)` so they have a key from the start. Show the temp password once and don't save or log it.
- `POST /admin/users/{id}/reset-password`: new temp password, `must_change_password = True`. Documents aren't affected because the key isn't tied to the password.
- `POST /admin/users/{id}/toggle`: activate or deactivate.
- Admin must have no route that touches documents. Add a test that checks `routes/admin.py` doesn't import `vault`. It's a crude check, but it works.

### Day 6: audit log
- `audit.py`: `log(actor, action, target_type, target_id, ok=True, detail="")`. Everyone calls this.
- `GET /admin/audit`: last 200 entries, with a filter for `ok=False` so failed integrity checks and blocked access are easy to find.

### Day 7: hardening
- Security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, and a basic CSP (`default-src 'self'`).
- Our own 404, 409 and 500 pages. No stack traces when `DEBUG=false`.
- `Content-Disposition: attachment` on every download, so an uploaded HTML file can't run on our site.

## What I give / what I need

| I give | To | When |
|--------|----|------|
| models, `base.html`, shared CSS classes | everyone | day 1 (done) |
| `current_user`, `require_role`, `check_csrf` | Melvan, Naura | day 3 |
| `audit.log` | everyone | an empty stub on day 3 so people can call it, the real thing on day 6 |

| I need | From | When |
|--------|------|------|
| `base.py`, `kdf.py`, contract tests | Ajil | day 1 (done) |
| `keys.create_dek` | Ajil | day 3 |

## For the report

- How GCM gives both secrecy and integrity in one go, and what the 16-byte tag covers (the ciphertext and the AAD).
- Our nonce scheme, and why reusing a nonce would be a disaster.
- The AES row from `scripts/bench.py`. It should be the fastest of the three on any CPU with AES-NI. Explain why.
