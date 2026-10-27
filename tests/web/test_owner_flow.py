"""Melvan. Owner routes over HTTP: isolation between owners, downloads, tampering, deletion."""
import io

import pytest
from sqlalchemy import select

from app.models import AuditLog, DeletionRequest, DeletionStatus, Kos, Room, SecretBlob, User

PNG = b"\x89PNG\r\n\x1a\n" + b"KTP-BYTES" * 100


@pytest.fixture
def clients(make_client, world):
    owner_a, owner_b, tenant_a = make_client(), make_client(), make_client()
    owner_a.login("owner_a@test.test")
    owner_b.login("owner_b@test.test")
    tenant_a.login("tenant_a@test.test")
    return owner_a, owner_b, tenant_a


def upload_ktp(tenant):
    r = tenant.submit("/tenant/documents/ktp", files={"file": ("ktp.png", io.BytesIO(PNG), "image/png")})
    assert r.status_code == 303, r.text


def request_deletion(tenant, db_factory, tenant_id):
    tenant.submit("/tenant/deletion-request", {"reason": "moving out"})
    with db_factory() as db:
        return db.scalar(select(DeletionRequest.id).where(DeletionRequest.tenant_id == tenant_id))


def test_kos_and_rooms(clients, world, db_factory):
    owner_a, _, _ = clients
    assert owner_a.submit("/owner/kos", {"name": "Kos C", "address": "Jl. C"}).status_code == 303
    assert "Kos C" in owner_a.get("/owner/kos").text
    owner_a.submit(f"/owner/kos/{world.kos_a}/rooms", {"number": "103"})
    owner_a.submit(f"/owner/kos/{world.kos_a}/rooms", {"number": "103"})  # duplicate is refused
    with db_factory() as db:
        assert db.query(Room).filter_by(kos_id=world.kos_a, number="103").count() == 1
    assert "tenant_a@test.test" in owner_a.get("/owner/tenants").text
    # Tenants are placed in rooms by the admin, not by the owner
    assert owner_a.submit(f"/owner/rooms/{world.room_a_empty}/assign",
                          {"email": "free@test.test"}).status_code in (404, 405)


def test_edit_and_delete_kos(clients, world, db_factory):
    owner_a, owner_b, _ = clients
    owner_a.submit(f"/owner/kos/{world.kos_a}/edit", {"name": "Kos A Baru", "address": "Jl. Baru"})
    owner_a.submit(f"/owner/kos/{world.kos_a}/edit", {"name": "", "address": "Jl. Kosong"})  # refused
    with db_factory() as db:
        kos = db.get(Kos, world.kos_a)
        assert (kos.name, kos.address) == ("Kos A Baru", "Jl. Baru")

    # Kos A has a tenant: can't delete until they move out
    owner_a.submit(f"/owner/kos/{world.kos_a}/delete")
    with db_factory() as db:
        assert db.get(Kos, world.kos_a) is not None
    owner_a.submit(f"/owner/rooms/{world.room_a}/unassign")
    assert owner_a.submit(f"/owner/kos/{world.kos_a}/delete").headers["location"] == "/owner/kos"
    with db_factory() as db:
        assert db.get(Kos, world.kos_a) is None
        assert db.query(Room).filter_by(kos_id=world.kos_a).count() == 0
        assert db.get(User, world.tenant_a).wrapped_dek is not None  # tenant's data untouched


def test_owner_cannot_use_other_owners_ids(clients, world, db_factory, make_client):
    owner_a, _, _ = clients
    tenant_b = make_client()
    tenant_b.login("tenant_b@test.test")
    upload_ktp(tenant_b)
    req_b = request_deletion(tenant_b, db_factory, world.tenant_b)

    assert owner_a.get(f"/owner/kos/{world.kos_b}/rooms").status_code == 404
    assert owner_a.submit(f"/owner/kos/{world.kos_b}/edit", {"name": "X", "address": "Y"}).status_code == 404
    assert owner_a.submit(f"/owner/kos/{world.kos_b}/delete").status_code == 404
    assert owner_a.submit(f"/owner/kos/{world.kos_b}/rooms", {"number": "X"}).status_code == 404
    assert owner_a.submit(f"/owner/rooms/{world.room_b}/unassign").status_code == 404
    assert owner_a.get(f"/owner/tenants/{world.tenant_b}").status_code == 404
    assert owner_a.get(f"/owner/tenants/{world.tenant_b}/documents/ktp").status_code == 404
    assert owner_a.get(f"/owner/deletion-requests/{req_b}/approve").status_code == 404
    assert owner_a.submit(f"/owner/deletion-requests/{req_b}/approve", {"confirm": "B1"}).status_code == 404
    assert owner_a.submit(f"/owner/deletion-requests/{req_b}/reject", {"reason": "no"}).status_code == 404
    assert "tenant_b@test.test" not in owner_a.get("/owner/tenants").text
    with db_factory() as db:
        assert db.get(User, world.tenant_b).wrapped_dek is not None


@pytest.mark.parametrize("cipher", ["aes", "des", "rc4"])
def test_owner_downloads_each_copy(clients, world, cipher):
    owner_a, _, tenant_a = clients
    upload_ktp(tenant_a)
    r = owner_a.get(f"/owner/tenants/{world.tenant_a}/documents/ktp?cipher={cipher}")
    assert r.status_code == 200 and r.content == PNG
    assert r.headers["content-disposition"].startswith("attachment")


def test_owner_sees_profile(clients, world):
    owner_a, _, tenant_a = clients
    tenant_a.submit("/tenant/profile", {
        "full_name": "Budi Santoso", "nik": "3201234567890001", "birth_date": "2000-01-31",
        "gender": "male", "phone": "081234567890", "origin_address": "Jl. Asal 1", "occupation": "Student",
        "ec_name": "Siti", "ec_relation": "Mother", "ec_phone": "+6289876543210"})
    page = owner_a.get(f"/owner/tenants/{world.tenant_a}").text
    assert "Budi Santoso" in page and "3201234567890001" in page


def test_tampered_copy_gives_409_and_audit(clients, world, db_factory):
    owner_a, _, tenant_a = clients
    upload_ktp(tenant_a)
    with db_factory() as db:
        path = db.scalar(select(SecretBlob.path).where(SecretBlob.cipher == "rc4"))
    with open(path, "r+b") as f:
        f.seek(-1, 2)
        last = f.read(1)
        f.seek(-1, 2)
        f.write(bytes([last[0] ^ 1]))
    r = owner_a.get(f"/owner/tenants/{world.tenant_a}/documents/ktp?cipher=rc4")
    assert r.status_code == 409 and PNG not in r.content
    assert owner_a.get(f"/owner/tenants/{world.tenant_a}/documents/ktp?cipher=aes").content == PNG
    with db_factory() as db:
        assert db.query(AuditLog).filter_by(action="download", ok=False).count() == 1


def test_move_out_ends_owner_access(clients, world):
    owner_a, _, tenant_a = clients
    upload_ktp(tenant_a)
    owner_a.submit(f"/owner/rooms/{world.room_a}/unassign")
    assert owner_a.get(f"/owner/tenants/{world.tenant_a}").status_code == 404
    assert owner_a.get(f"/owner/tenants/{world.tenant_a}/documents/ktp").status_code == 404
    assert tenant_a.get("/tenant/documents/ktp").content == PNG  # tenant keeps their data


def test_approve_deletion_shreds_everything(clients, world, db_factory, tmp_path):
    owner_a, _, tenant_a = clients
    upload_ktp(tenant_a)
    req = request_deletion(tenant_a, db_factory, world.tenant_a)
    assert "moving out" in owner_a.get("/owner/deletion-requests").text

    owner_a.submit(f"/owner/deletion-requests/{req}/approve", {"confirm": "wrong"})
    assert (tmp_path / str(world.tenant_a)).exists()

    r = owner_a.submit(f"/owner/deletion-requests/{req}/approve", {"confirm": "101"})
    assert r.status_code == 303
    assert not (tmp_path / str(world.tenant_a)).exists()
    with db_factory() as db:
        tenant = db.get(User, world.tenant_a)
        assert tenant.wrapped_dek is None and not tenant.is_active
        assert db.get(Room, world.room_a).tenant_id is None
        r = db.get(DeletionRequest, req)
        assert r.status == DeletionStatus.done and r.decided_by == world.owner_a
    assert tenant_a.get("/tenant", follow_redirects=False).headers["location"] == "/login"


def test_reject_needs_reason_and_tenant_sees_it(clients, world, db_factory):
    owner_a, _, tenant_a = clients
    req = request_deletion(tenant_a, db_factory, world.tenant_a)
    owner_a.submit(f"/owner/deletion-requests/{req}/reject", {"reason": ""})
    with db_factory() as db:
        assert db.get(DeletionRequest, req).status == DeletionStatus.pending
    owner_a.submit(f"/owner/deletion-requests/{req}/reject", {"reason": "Rent still unpaid"})
    assert "Rent still unpaid" in tenant_a.get("/tenant/deletion-request").text
