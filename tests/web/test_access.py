"""Tests for access control service (Person 2 - Melvan).

Verifies ownership isolation:
- owner_has_tenant(owner, tenant) returns True only when tenant is in owner's kos
- can_view_subject(actor, subject) enforces:
    - Admin: NEVER has access (returns False)
    - Tenant: only accesses themselves
    - Owner: only accesses their current tenants
- get_owned_*_or_404 helpers:
    - Owner A gets 404 for Owner B's resources (kos, room, tenant, deletion request)
"""

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base
from app.models import DeletionRequest, DeletionStatus, Kos, Role, Room, User
from app.services.access import (
    can_view_subject,
    get_owned_deletion_request_or_404,
    get_owned_kos_or_404,
    get_owned_room_or_404,
    get_owned_tenant_or_404,
    owner_has_tenant,
)


@pytest.fixture
def db_session():
    # Use SQLite in-memory database for isolated testing
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def setup_data(db_session: Session):
    """Seed Owners A & B, Tenants A & B, an Unassigned Tenant, and an Admin."""
    admin = User(
        email="admin@kosanku.test",
        password_hash="hash",
        role=Role.admin,
        is_active=True,
    )
    owner_a = User(
        email="owner_a@kosanku.test",
        password_hash="hash",
        role=Role.owner,
        is_active=True,
    )
    owner_b = User(
        email="owner_b@kosanku.test",
        password_hash="hash",
        role=Role.owner,
        is_active=True,
    )
    tenant_a = User(
        email="tenant_a@kosanku.test",
        password_hash="hash",
        role=Role.tenant,
        is_active=True,
    )
    tenant_b = User(
        email="tenant_b@kosanku.test",
        password_hash="hash",
        role=Role.tenant,
        is_active=True,
    )
    tenant_unassigned = User(
        email="tenant_unassigned@kosanku.test",
        password_hash="hash",
        role=Role.tenant,
        is_active=True,
    )
    db_session.add_all([admin, owner_a, owner_b, tenant_a, tenant_b, tenant_unassigned])
    db_session.flush()

    kos_a = Kos(owner_id=owner_a.id, name="Kos Melati", address="Jl. Melati No. 1")
    kos_b = Kos(owner_id=owner_b.id, name="Kos Mawar", address="Jl. Mawar No. 2")
    db_session.add_all([kos_a, kos_b])
    db_session.flush()

    room_a = Room(kos_id=kos_a.id, number="101", tenant_id=tenant_a.id)
    room_b = Room(kos_id=kos_b.id, number="201", tenant_id=tenant_b.id)
    db_session.add_all([room_a, room_b])
    db_session.flush()

    del_req_a = DeletionRequest(
        tenant_id=tenant_a.id,
        owner_id=owner_a.id,
        reason="Moving out",
        status=DeletionStatus.pending,
    )
    del_req_b = DeletionRequest(
        tenant_id=tenant_b.id,
        owner_id=owner_b.id,
        reason="Graduated",
        status=DeletionStatus.pending,
    )
    db_session.add_all([del_req_a, del_req_b])
    db_session.commit()

    return {
        "admin": admin,
        "owner_a": owner_a,
        "owner_b": owner_b,
        "tenant_a": tenant_a,
        "tenant_b": tenant_b,
        "tenant_unassigned": tenant_unassigned,
        "kos_a": kos_a,
        "kos_b": kos_b,
        "room_a": room_a,
        "room_b": room_b,
        "del_req_a": del_req_a,
        "del_req_b": del_req_b,
    }


def test_owner_has_tenant(db_session, setup_data):
    owner_a = setup_data["owner_a"]
    owner_b = setup_data["owner_b"]
    tenant_a = setup_data["tenant_a"]
    tenant_b = setup_data["tenant_b"]
    tenant_unassigned = setup_data["tenant_unassigned"]
    admin = setup_data["admin"]

    # Owner A has Tenant A, but not Tenant B or unassigned tenant
    assert owner_has_tenant(owner_a, tenant_a, db=db_session) is True
    assert owner_has_tenant(owner_a, tenant_b, db=db_session) is False
    assert owner_has_tenant(owner_a, tenant_unassigned, db=db_session) is False

    # Owner B has Tenant B, but not Tenant A
    assert owner_has_tenant(owner_b, tenant_b, db=db_session) is True
    assert owner_has_tenant(owner_b, tenant_a, db=db_session) is False

    # Admin is not an owner
    assert owner_has_tenant(admin, tenant_a, db=db_session) is False


def test_can_view_subject_tenant_rules(db_session, setup_data):
    tenant_a = setup_data["tenant_a"]
    tenant_b = setup_data["tenant_b"]
    owner_a = setup_data["owner_a"]

    # Tenant can only view themselves
    assert can_view_subject(tenant_a, tenant_a, db=db_session) is True
    assert can_view_subject(tenant_a, tenant_b, db=db_session) is False
    assert can_view_subject(tenant_a, owner_a, db=db_session) is False


def test_can_view_subject_owner_rules(db_session, setup_data):
    owner_a = setup_data["owner_a"]
    owner_b = setup_data["owner_b"]
    tenant_a = setup_data["tenant_a"]
    tenant_b = setup_data["tenant_b"]
    tenant_unassigned = setup_data["tenant_unassigned"]

    # Owner can view themselves
    assert can_view_subject(owner_a, owner_a, db=db_session) is True

    # Owner A can view their tenant (Tenant A), but NOT Tenant B or unassigned
    assert can_view_subject(owner_a, tenant_a, db=db_session) is True
    assert can_view_subject(owner_a, tenant_b, db=db_session) is False
    assert can_view_subject(owner_a, tenant_unassigned, db=db_session) is False

    # Owner B cannot view Owner A's tenant
    assert can_view_subject(owner_b, tenant_a, db=db_session) is False


def test_can_view_subject_admin_never_allowed(db_session, setup_data):
    admin = setup_data["admin"]
    tenant_a = setup_data["tenant_a"]
    owner_a = setup_data["owner_a"]

    # Admin has NO access to personal data, even their own or tenants'
    assert can_view_subject(admin, tenant_a, db=db_session) is False
    assert can_view_subject(admin, owner_a, db=db_session) is False
    assert can_view_subject(admin, admin, db=db_session) is False


def test_get_owned_kos_or_404(db_session, setup_data):
    owner_a = setup_data["owner_a"]
    owner_b = setup_data["owner_b"]
    kos_a = setup_data["kos_a"]
    kos_b = setup_data["kos_b"]

    # Owner A can get Kos A
    assert get_owned_kos_or_404(db_session, owner_a, kos_a.id).id == kos_a.id

    # Owner A trying to access Owner B's Kos raises 404
    with pytest.raises(HTTPException) as exc:
        get_owned_kos_or_404(db_session, owner_a, kos_b.id)
    assert exc.value.status_code == 404

    # Nonexistent ID raises 404
    with pytest.raises(HTTPException) as exc:
        get_owned_kos_or_404(db_session, owner_a, 999999)
    assert exc.value.status_code == 404


def test_get_owned_room_or_404(db_session, setup_data):
    owner_a = setup_data["owner_a"]
    room_a = setup_data["room_a"]
    room_b = setup_data["room_b"]

    # Owner A can get Room A
    assert get_owned_room_or_404(db_session, owner_a, room_a.id).id == room_a.id

    # Owner A getting Room B raises 404
    with pytest.raises(HTTPException) as exc:
        get_owned_room_or_404(db_session, owner_a, room_b.id)
    assert exc.value.status_code == 404


def test_get_owned_tenant_or_404(db_session, setup_data):
    owner_a = setup_data["owner_a"]
    tenant_a = setup_data["tenant_a"]
    tenant_b = setup_data["tenant_b"]

    # Owner A can get Tenant A
    assert get_owned_tenant_or_404(db_session, owner_a, tenant_a.id).id == tenant_a.id

    # Owner A getting Tenant B raises 404
    with pytest.raises(HTTPException) as exc:
        get_owned_tenant_or_404(db_session, owner_a, tenant_b.id)
    assert exc.value.status_code == 404


def test_get_owned_deletion_request_or_404(db_session, setup_data):
    owner_a = setup_data["owner_a"]
    del_req_a = setup_data["del_req_a"]
    del_req_b = setup_data["del_req_b"]

    # Owner A can get Deletion Request A
    assert (
        get_owned_deletion_request_or_404(db_session, owner_a, del_req_a.id).id
        == del_req_a.id
    )

    # Owner A getting Deletion Request B raises 404
    with pytest.raises(HTTPException) as exc:
        get_owned_deletion_request_or_404(db_session, owner_a, del_req_b.id)
    assert exc.value.status_code == 404
