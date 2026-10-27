"""Ajil. Tenant flow over HTTP: profile, uploads, downloads, deletion request."""
import io

import pytest
from sqlalchemy import select

from app.models import AuditLog, CipherName, DeletionRequest, DeletionStatus, SecretBlob, SecretItem, User
from .conftest import PASSWORD

MIB = 1024 * 1024
PROFILE = {
    "full_name": "Budi Santoso", "nik": "3201234567890001", "birth_date": "2000-01-31", "gender": "male",
    "phone": "081234567890", "origin_address": "Jl. Asal 1", "occupation": "Student",
    "ec_name": "Siti", "ec_relation": "Mother", "ec_phone": "+6289876543210",
}


@pytest.fixture
def tenant(make_client, world):
    c = make_client()
    c.login("tenant_a@test.test")
    return c


def upload(c, kind, name, data, mime):
    return c.submit(f"/tenant/documents/{kind}", files={"file": (name, io.BytesIO(data), mime)})


def test_profile_validated_encrypted_and_read_back(tenant, db_factory):
    r = tenant.submit("/tenant/profile", {**PROFILE, "nik": "123"})
    assert r.status_code == 400 and "NIK must be exactly 16 digits." in r.text
    assert tenant.submit("/tenant/profile", {**PROFILE, "birth_date": "2999-01-01"}).status_code == 400
    assert tenant.submit("/tenant/profile", PROFILE).status_code == 303
    page = tenant.get("/tenant/profile").text
    assert 'value="Budi Santoso"' in page and 'value="+6289876543210"' in page
    with db_factory() as db:
        assert len(db.scalars(select(SecretBlob)).all()) == 3
    assert "✓" in tenant.get("/tenant").text


@pytest.mark.parametrize("size", [1, MIB, MIB + 1])
def test_upload_and_download_every_cipher(tenant, size):
    data = (b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * (size // 256 + 1))[:max(size, 8)]
    assert upload(tenant, "ktp", "ktp.png", data, "image/png").status_code == 303
    assert "Download" in tenant.get("/tenant/documents").text
    for cipher in ("aes", "des", "rc4"):
        assert tenant.get(f"/tenant/documents/ktp?cipher={cipher}").content == data
    assert tenant.get("/tenant/documents/ktp").content == data


def test_fake_and_empty_uploads_rejected(tenant, db_factory):
    r = upload(tenant, "ktp", "virus.png", b"<?php echo 'x'; ?>", "image/png")
    assert r.status_code == 400 and "header file tidak sesuai" in r.text
    assert upload(tenant, "agreement", "evil.pdf", b"MZ\x90\x00" + b"\x00" * 64, "application/pdf").status_code == 400
    assert upload(tenant, "ktp", "empty.png", b"", "image/png").status_code == 400
    assert upload(tenant, "passport", "p.png", b"\x89PNG\r\n\x1a\n", "image/png").status_code == 404
    with db_factory() as db:
        assert db.scalars(select(SecretItem)).first() is None


def test_reupload_replaces(tenant, world, db_factory, tmp_path):
    upload(tenant, "ktp", "a.png", b"\x89PNG\r\n\x1a\nfirst", "image/png")
    upload(tenant, "ktp", "b.png", b"\x89PNG\r\n\x1a\nsecond", "image/png")
    assert tenant.get("/tenant/documents/ktp").content.endswith(b"second")
    with db_factory() as db:
        assert len(db.scalars(select(SecretItem)).all()) == 1
        assert len(db.scalars(select(SecretBlob)).all()) == 3
    assert len([p for p in (tmp_path / str(world.tenant_a)).iterdir() if p.is_file()]) == 3


def test_deletion_request_goes_to_owner(tenant, world, db_factory):
    tenant.submit("/tenant/deletion-request", {"reason": "Lulus kuliah"})
    tenant.submit("/tenant/deletion-request", {"reason": "again"})  # only one pending at a time
    with db_factory() as db:
        reqs = db.scalars(select(DeletionRequest)).all()
        assert len(reqs) == 1
        assert reqs[0].owner_id == world.owner_a and reqs[0].status == DeletionStatus.pending
        assert db.query(AuditLog).filter_by(actor_id=world.tenant_a, action="request_deletion").count() == 1
    assert "pending" in tenant.get("/tenant/deletion-request").text


def test_deletion_without_owner_waits_for_admin(make_client, world, db_factory, tmp_path):
    c = make_client()
    c.login("free@test.test")
    upload(c, "ktp", "ktp.png", b"\x89PNG\r\n\x1a\nfree", "image/png")
    c.submit("/tenant/deletion-request", {"reason": "moved out"})
    assert "Waiting for the admin" in c.get("/tenant/deletion-request").text
    assert (tmp_path / str(world.free)).exists()  # nothing deleted yet
    with db_factory() as db:
        req = db.scalars(select(DeletionRequest)).one()
        assert req.owner_id is None and req.status == DeletionStatus.pending

    owner = make_client()
    owner.login("owner_a@test.test")
    assert owner.get(f"/owner/deletion-requests/{req.id}/approve").status_code == 404

    admin = make_client()
    admin.login("admin@test.test")
    assert "free@test.test" in admin.get("/admin/deletion-requests").text
    assert "Type <code" in admin.get(f"/admin/deletion-requests/{req.id}/approve").text
    admin.submit(f"/admin/deletion-requests/{req.id}/approve", {"confirm": "wrong"})
    assert (tmp_path / str(world.free)).exists()
    r = admin.submit(f"/admin/deletion-requests/{req.id}/approve", {"confirm": "free@test.test"})
    assert r.status_code == 303
    assert not (tmp_path / str(world.free)).exists()
    with db_factory() as db:
        user = db.get(User, world.free)
        assert user.wrapped_dek is None and not user.is_active
        req = db.get(DeletionRequest, req.id)
        assert req.status == DeletionStatus.done and req.decided_by == world.admin
    assert c.post("/login", data={"email": "free@test.test", "password": PASSWORD,
                                  "csrf": c.csrf("/login")}).status_code == 400


def test_admin_rejects_ownerless_request_and_cannot_touch_owned_ones(make_client, world, db_factory):
    free, tenant_a, admin = make_client(), make_client(), make_client()
    free.login("free@test.test")
    tenant_a.login("tenant_a@test.test")
    admin.login("admin@test.test")
    free.submit("/tenant/deletion-request")
    tenant_a.submit("/tenant/deletion-request")
    with db_factory() as db:
        ids = {r.tenant_id: r.id for r in db.scalars(select(DeletionRequest))}
    owned = ids[world.tenant_a]
    assert admin.get(f"/admin/deletion-requests/{owned}/approve").status_code == 404
    assert admin.submit(f"/admin/deletion-requests/{owned}/approve", {"confirm": "101"}).status_code == 404
    assert "tenant_a@test.test" not in admin.get("/admin/deletion-requests").text

    admin.submit(f"/admin/deletion-requests/{ids[world.free]}/reject", {"reason": "Unpaid deposit"})
    assert "Unpaid deposit" in free.get("/tenant/deletion-request").text


@pytest.mark.slow
def test_tenant_video_200mib(tenant, world, db_factory, tmp_path):
    size = 200 * MIB
    video_path = tmp_path / "test_video.mp4"
    with open(video_path, "wb") as f:  # built on disk, never fully in RAM
        f.write(b"\x00\x00\x00\x18ftypisom")
        f.truncate(size)

    with open(video_path, "rb") as f:
        r = tenant.submit("/tenant/documents/video", files={"file": ("test_video.mp4", f, "video/mp4")})
    assert r.status_code == 303, r.text

    with db_factory() as db:
        item = db.scalar(select(SecretItem).where(SecretItem.subject_id == world.tenant_a))
        assert item.plain_size == size
        assert {b.cipher for b in db.scalars(select(SecretBlob))} == set(CipherName)
