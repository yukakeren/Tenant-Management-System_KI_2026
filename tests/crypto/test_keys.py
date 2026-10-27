"""DEK wrapping and access control tests."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.db import Base
from app.models import User, Role, Kos, Room
from app.crypto.base import IntegrityError
from app.crypto.keys import create_dek, unwrap_dek, destroy_dek


@pytest.fixture
def users():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = User(email="t@test.test", password_hash="x", role=Role.tenant)
        other = User(email="u@test.test", password_hash="x", role=Role.tenant)
        admin = User(email="a@test.test", password_hash="x", role=Role.admin)
        owner = User(email="o@test.test", password_hash="x", role=Role.owner)
        db.add_all([tenant, other, admin, owner]); db.flush()
        kos = Kos(owner_id=owner.id, name="Test", address="Test")
        db.add(kos); db.flush()
        db.add(Room(kos_id=kos.id, number="1", tenant_id=tenant.id)); db.flush()
        create_dek(tenant)
        create_dek(other)
        db.commit()
        yield tenant, other, admin, owner
    engine.dispose()


def test_self_and_owner(users):
    tenant, other, admin, owner = users
    assert len(unwrap_dek(tenant, tenant)) == 32
    assert unwrap_dek(tenant, owner) == unwrap_dek(tenant, tenant)
    with pytest.raises(PermissionError):
        unwrap_dek(other, owner)
    with pytest.raises(PermissionError):
        unwrap_dek(tenant, admin)
    with pytest.raises(PermissionError):
        unwrap_dek(tenant, other)


def test_swapped_keys_fail(users):
    tenant, other, *_ = users
    tenant.wrapped_dek = other.wrapped_dek
    with pytest.raises(IntegrityError):
        unwrap_dek(tenant, tenant)


def test_destroy(users):
    tenant, *_ = users
    destroy_dek(tenant)
    with pytest.raises(PermissionError):
        unwrap_dek(tenant, tenant)
