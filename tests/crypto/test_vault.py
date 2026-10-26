"""Vault tests need all three cipher suites (RC4 must be merged first)."""
import pytest
import app.crypto
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from app.db import Base
from app.models import User, Role, SecretBlob, SecretItem, Kos, Room, DeletionRequest, DeletionStatus
from app.crypto.base import REGISTRY, IntegrityError
from app.crypto.keys import create_dek
from app.crypto import vault

pytestmark = pytest.mark.skipif("rc4" not in REGISTRY, reason="RC4 implementation not merged yet")


@pytest.fixture
def env(tmp_path, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(vault, "settings", SimpleNamespace(storage_dir=tmp_path, read_cipher="aes"))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = User(email="tenant@test.test", password_hash="x", role=Role.tenant)
        db.add(tenant); db.flush()
        owner = User(email="owner@test.test", password_hash="x", role=Role.owner)
        db.add(owner); db.flush()
        kos = Kos(owner_id=owner.id, name="Kosan", address="Test")
        db.add(kos); db.flush()
        db.add(Room(kos_id=kos.id, number="1", tenant_id=tenant.id))
        db.add(DeletionRequest(tenant_id=tenant.id, owner_id=owner.id,
                               status=DeletionStatus.pending))
        create_dek(tenant); db.commit()
        yield tenant, owner, db, tmp_path
    engine.dispose()


def test_store_read_replace_shred(env):
    tenant, owner, db, root = env
    item = vault.store_bytes(tenant, "profile", b"first", tenant)
    assert len(list(db.scalars(select(SecretBlob)))) == 3
    for c in ("aes", "des", "rc4"):
        vault.verify_item(tenant, "profile", c, tenant)
        assert b"".join(vault.open_item(tenant, "profile", c, tenant)) == b"first"
    vault.store_bytes(tenant, "profile", b"second", tenant)
    assert len(list(db.scalars(select(SecretItem)))) == 1
    assert len(list(db.scalars(select(SecretBlob)))) == 3
    assert vault.load_bytes(tenant, "profile", tenant) == b"second"
    vault.shred_user(tenant, owner)
    assert tenant.wrapped_dek is None
    assert not list(db.scalars(select(SecretItem)))
    assert not (root / str(tenant.id)).exists()


def test_tamper_and_admin_denied(env):
    tenant, owner, db, root = env
    item = vault.store_bytes(tenant, "profile", b"secret", tenant)
    target = root / str(tenant.id) / f"{item.id}.aes.bin"
    bad = bytearray(target.read_bytes()); bad[-1] ^= 1; target.write_bytes(bad)
    with pytest.raises(IntegrityError):
        vault.verify_item(tenant, "profile", "aes", tenant)
    assert vault.load_bytes(tenant, "profile", tenant, cipher="des") == b"secret"
    admin = User(email="admin@test.test", password_hash="x", role=Role.admin)
    db.add(admin); db.flush()
    with pytest.raises(PermissionError):
        vault.load_bytes(tenant, "profile", admin)
