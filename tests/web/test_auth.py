"""Ata. Login, roles, CSRF, inactive users, forced password change, admin account pages."""
import inspect
import io

import pytest

from app.auth.security import hash_password
from app.crypto import vault
from app.models import AuditLog, Role, Room, User
from app.routes import admin as admin_routes
from .conftest import PASSWORD


def test_login_redirects_to_role_home(make_client, world):
    for email, home in [("admin@test.test", "/admin/users"), ("owner_a@test.test", "/owner/kos"),
                        ("tenant_a@test.test", "/tenant")]:
        c = make_client()
        assert c.login(email).headers["location"] == home
        assert c.get(home).status_code == 200


def test_wrong_email_and_wrong_password_look_the_same(make_client, world):
    c = make_client()
    bad_pw = c.post("/login", data={"email": "owner_a@test.test", "password": "nope", "csrf": c.csrf("/login")})
    no_user = c.post("/login", data={"email": "ghost@test.test", "password": "nope", "csrf": c.csrf("/login")})
    assert bad_pw.status_code == no_user.status_code == 400
    assert "Wrong email or password." in bad_pw.text and "Wrong email or password." in no_user.text


def test_login_rate_limited_after_5_failures(make_client, world):
    c = make_client()
    for _ in range(5):
        c.post("/login", data={"email": "owner_a@test.test", "password": "nope", "csrf": c.csrf("/login")})
    r = c.post("/login", data={"email": "owner_a@test.test", "password": PASSWORD, "csrf": c.csrf("/login")})
    assert r.status_code == 429


def test_post_without_csrf_is_rejected(make_client, world):
    c = make_client()
    assert c.post("/login", data={"email": "owner_a@test.test", "password": PASSWORD}).status_code == 403
    c.login("owner_a@test.test")
    r = c.post("/owner/kos", data={"name": "X", "address": "Y", "csrf": "forged"})
    assert r.status_code == 403
    assert c.submit("/owner/kos", {"name": "X", "address": "Y"}).status_code == 303


def test_anonymous_is_sent_to_login(make_client, world):
    r = make_client().get("/tenant/documents", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_roles_are_enforced(make_client, world):
    tenant, owner, admin = make_client(), make_client(), make_client()
    tenant.login("tenant_a@test.test")
    owner.login("owner_a@test.test")
    admin.login("admin@test.test")
    assert tenant.get("/admin/users").status_code == 403
    assert tenant.get("/owner/tenants").status_code == 403
    assert owner.get("/tenant/documents").status_code == 403
    # Admin never reaches tenant data, not even by URL
    for url in ["/owner/tenants", f"/owner/tenants/{world.tenant_a}",
                f"/owner/tenants/{world.tenant_a}/documents/ktp", "/tenant/profile", "/tenant/documents/ktp"]:
        assert admin.get(url).status_code in (403, 404), url


def test_admin_routes_read_only_the_video():
    # Crude but useful: the admin routes' only way to decrypt is the room-video download.
    source = inspect.getsource(admin_routes)
    for reader in ("import vault", "vault.", "unwrap_dek(", "open_item(", "verify_item(", "load_bytes("):
        assert reader not in source, reader
    calls = [line.strip() for line in source.splitlines() if "stream_document(" in line and "import" not in line]
    assert calls == ['return stream_document(db, tenant, "video", settings.read_cipher, me, inline=True)']


def test_admin_sees_video_and_nothing_else(make_client, world, db_factory):
    tenant = make_client()
    tenant.login("tenant_a@test.test")
    video = b"\x00\x00\x00\x18ftypisom" + b"VIDEO" * 100
    ktp = b"\x89PNG\r\n\x1a\n" + b"KTP" * 100
    tenant.submit("/tenant/documents/video", files={"file": ("v.mp4", io.BytesIO(video), "video/mp4")})
    tenant.submit("/tenant/documents/ktp", files={"file": ("k.png", io.BytesIO(ktp), "image/png")})
    tenant.submit("/tenant/profile", {
        "full_name": "Budi Santoso", "nik": "3201234567890001", "birth_date": "2000-01-31",
        "gender": "male", "phone": "081234567890", "origin_address": "Jl. Asal 1", "occupation": "Student",
        "ec_name": "Siti", "ec_relation": "Mother", "ec_phone": "+6289876543210"})

    admin = make_client()
    admin.login("admin@test.test")
    page = admin.get("/admin/users").text
    assert f"/admin/users/{world.tenant_a}/video" in page
    assert "Budi Santoso" not in page and "3201234567890001" not in page
    r = admin.get(f"/admin/users/{world.tenant_a}/video")
    assert r.status_code == 200 and r.content == video
    assert r.headers["content-disposition"].startswith("inline")
    assert admin.get(f"/admin/users/{world.owner_a}/video").status_code == 404

    # The key path itself refuses the admin for anything but the video
    with db_factory() as db:
        t, a = db.get(User, world.tenant_a), db.get(User, world.admin)
        vault.verify_item(t, "video", "aes", a)
        for kind in ("ktp", "profile"):
            with pytest.raises(PermissionError):
                vault.verify_item(t, kind, "aes", a)
            with pytest.raises(PermissionError):
                vault.load_bytes(t, kind, a)


def test_inactive_user_is_blocked_and_kicked_out(make_client, world, db_factory):
    c = make_client()
    c.login("tenant_a@test.test")
    with db_factory() as db:
        db.get(User, world.tenant_a).is_active = False
        db.commit()
    assert c.get("/tenant", follow_redirects=False).headers["location"] == "/login"
    r = c.post("/login", data={"email": "tenant_a@test.test", "password": PASSWORD, "csrf": c.csrf("/login")})
    assert r.status_code == 400


def test_admin_creates_tenant_with_key_and_forced_password_change(make_client, world, db_factory):
    admin = make_client()
    admin.login("admin@test.test")
    r = admin.post("/admin/users", data={"email": "New@Test.test", "role": "tenant",
                                         "room_id": world.room_a_empty, "csrf": admin.csrf()})
    assert r.status_code == 200
    temp = r.text.split('font-mono">')[1].split("<")[0]
    with db_factory() as db:
        new = db.query(User).filter_by(email="new@test.test").one()
        assert new.wrapped_dek is not None and new.must_change_password
        assert db.get(Room, world.room_a_empty).tenant_id == new.id
        # The temp password is in neither the DB nor the audit log
        assert temp not in new.password_hash
        assert not any(temp in e.detail for e in db.query(AuditLog))

    user = make_client()
    assert user.login("new@test.test", temp).headers["location"] == "/account/password"
    assert user.get("/tenant", follow_redirects=False).headers["location"] == "/account/password"
    bad = {"old_password": temp, "new_password": "short", "confirm_password": "short"}
    assert user.submit("/account/password", bad).status_code == 400
    bad = {"old_password": temp, "new_password": "long-enough-1", "confirm_password": "long-enough-2"}
    assert user.submit("/account/password", bad).status_code == 400
    ok = {"old_password": temp, "new_password": "long-enough-1", "confirm_password": "long-enough-1"}
    assert user.submit("/account/password", ok).headers["location"] == "/tenant"
    assert user.get("/tenant").status_code == 200


def test_admin_cannot_create_admin_or_duplicate(make_client, world, db_factory):
    admin = make_client()
    admin.login("admin@test.test")
    admin.submit("/admin/users", {"email": "boss@test.test", "role": "admin"})
    admin.submit("/admin/users", {"email": "owner_a@test.test", "role": "owner"})
    with db_factory() as db:
        assert db.query(User).filter_by(email="boss@test.test").first() is None
        assert db.query(User).filter_by(email="owner_a@test.test").count() == 1


def test_tenant_needs_an_empty_room(make_client, world, db_factory):
    admin = make_client()
    admin.login("admin@test.test")
    admin.submit("/admin/users", {"email": "noroom@test.test", "role": "tenant"})
    admin.submit("/admin/users", {"email": "taken@test.test", "role": "tenant", "room_id": world.room_a})
    admin.submit("/admin/users", {"email": "ghost@test.test", "role": "tenant", "room_id": 9999})
    with db_factory() as db:
        for email in ("noroom@test.test", "taken@test.test", "ghost@test.test"):
            assert db.query(User).filter_by(email=email).first() is None, email
        assert db.get(Room, world.room_a).tenant_id == world.tenant_a


def test_only_one_owner(make_client, db_factory):
    with db_factory() as db:
        db.add(User(email="admin@test.test", password_hash=hash_password(PASSWORD), role=Role.admin,
                    must_change_password=False))
        db.commit()
    admin = make_client()
    admin.login("admin@test.test")
    assert 'value="owner"' in admin.get("/admin/users").text
    assert admin.submit("/admin/users", {"email": "first@test.test", "role": "owner"}).status_code == 200
    assert 'value="owner"' not in admin.get("/admin/users").text
    admin.submit("/admin/users", {"email": "second@test.test", "role": "owner"})
    with db_factory() as db:
        assert db.query(User).filter_by(role=Role.owner).count() == 1


def test_reset_password_keeps_the_key(make_client, world, db_factory):
    with db_factory() as db:
        dek_before = db.get(User, world.tenant_a).wrapped_dek
    admin = make_client()
    admin.login("admin@test.test")
    r = admin.submit(f"/admin/users/{world.tenant_a}/reset-password")
    temp = r.text.split('font-mono">')[1].split("<")[0]
    with db_factory() as db:
        tenant = db.get(User, world.tenant_a)
        assert tenant.wrapped_dek == dek_before and tenant.must_change_password
    c = make_client()
    assert c.post("/login", data={"email": "tenant_a@test.test", "password": PASSWORD,
                                  "csrf": c.csrf("/login")}).status_code == 400
    c.login("tenant_a@test.test", temp)


def test_admin_toggle_and_audit_filter(make_client, world, db_factory):
    admin = make_client()
    admin.login("admin@test.test")
    assert admin.submit(f"/admin/users/{world.owner_b}/toggle").status_code == 303
    assert admin.submit(f"/admin/users/{world.admin}/toggle").status_code == 400
    with db_factory() as db:
        assert db.get(User, world.owner_b).is_active is False
    page = admin.get("/admin/audit?failed=true").text
    assert "deactivate_user" not in page
    assert "deactivate_user" in admin.get("/admin/audit").text


def test_security_headers(make_client):
    r = make_client().get("/login")
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["content-security-policy"] == "default-src 'self'"
