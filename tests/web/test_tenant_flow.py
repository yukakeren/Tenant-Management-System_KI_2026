"""
End-to-End Test for Tenant Flow:
Profile encryption -> File Upload (KTP/Agreement) -> Decrypted Download -> Deletion Request
"""

import io
import os
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.models import User, Role, Kos, Room, ItemKind, DeletionStatus
from app.routes.tenant import router as tenant_router

TEST_DB_URL = "sqlite:///:memory:"

engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app = FastAPI()
app.include_router(tenant_router)
app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    owner = User(
        id=1,
        email="owner@kos.com",
        password_hash="mock_hash",
        role=Role.owner,
        is_active=True,
    )
    db.add(owner)
    db.flush()

    kos = Kos(id=1, owner_id=owner.id, name="Kos Melati", address="Jl. Melati No. 10")
    db.add(kos)
    db.flush()

    tenant = User(
        id=2,
        email="tenant@kos.com",
        password_hash="mock_hash",
        role=Role.tenant,
        is_active=True,
        wrapped_dek=os.urandom(32),  # Simulasi DEK
    )
    db.add(tenant)
    db.flush()

    room = Room(id=1, kos_id=kos.id, number="101", tenant_id=tenant.id)
    db.add(room)

    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)


def test_tenant_profile_encrypt_and_read():
    headers = {"X-User-Id": "2"}

    form_data = {
        "full_name": "Budi Santoso",
        "nik": "3201234567890001",
        "phone": "081234567890",
        "emergency_contact_name": "Siti (Ibu)",
        "emergency_contact_phone": "089876543210",
        "emergency_relation": "Orang Tua",
    }
    res = client.post("/tenant/profile", data=form_data, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    res_get = client.get("/tenant/profile", headers=headers)
    assert res_get.status_code == 200
    data = res_get.json()
    assert data["email"] == "tenant@kos.com"
    assert data["profile"]["full_name"] == "Budi Santoso"
    assert data["profile"]["nik"] == "3201234567890001"
    assert data["profile"]["emergency"]["relation"] == "Orang Tua"


def test_tenant_upload_valid_ktp_and_download_decrypted():
    headers = {"X-User-Id": "2"}

    png_content = b"\x89PNG\r\n\x1a\n" + b"MOCK_IMAGE_DATA_KTP_AJIL"
    files = {"file": ("my_ktp.png", io.BytesIO(png_content), "image/png")}

    res_upload = client.post("/tenant/upload/ktp", files=files, headers=headers)
    assert res_upload.status_code == 200
    upload_json = res_upload.json()
    assert upload_json["status"] == "success"
    assert upload_json["plain_size"] == len(png_content)

    res_list = client.get("/tenant/documents", headers=headers)
    assert res_list.status_code == 200
    docs = res_list.json()["documents"]
    assert any(d["kind"] == "ktp" for d in docs)

    res_down = client.get("/tenant/documents/ktp/download", headers=headers)
    assert res_down.status_code == 200
    assert res_down.content == png_content


def test_tenant_upload_fake_header_rejected():
    headers = {"X-User-Id": "2"}

    fake_content = b"<?php echo 'malicious script'; ?>"
    files = {"file": ("virus.png", io.BytesIO(fake_content), "image/png")}

    res = client.post("/tenant/upload/ktp", files=files, headers=headers)
    assert res.status_code == 400
    assert "header file tidak sesuai" in res.json()["detail"]


def test_tenant_deletion_request():
    headers = {"X-User-Id": "2"}

    form_data = {"reason": "Saya sudah lulus kuliah dan masa sewa telah habis."}
    res = client.post("/tenant/deletion-request", data=form_data, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    db = TestingSessionLocal()
    from app.models import DeletionRequest, AuditLog

    req = db.query(DeletionRequest).filter_by(tenant_id=2).first()
    assert req is not None
    assert req.owner_id == 1
    assert req.status == DeletionStatus.pending
    assert "lulus kuliah" in req.reason

    log = db.query(AuditLog).filter_by(actor_id=2, action="request_deletion").first()
    assert log is not None
    assert log.ok is True
    db.close()