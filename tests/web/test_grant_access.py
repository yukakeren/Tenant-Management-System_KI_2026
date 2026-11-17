"""Security and grant access control tests (Melvan).

Tests:
- Data models for public_keys and access_grants.
- Admin request creation, parameter validation, and reason requirement.
- Invariant: only one pending request per tenant.
- Isolation: users can only query their own grants (404 on cross-user queries).
- Grant state machine transitions and audit logging.
- Expiration check (ensure_active) via TTL.
- Purge on tenant deletion (crypto-shredding integration).
- Core security invariant: admin unwrap_dek MUST STILL raise PermissionError for personal data.
"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.crypto.keys import unwrap_dek
from app.models import AccessGrant, AuditLog, GrantStatus, PublicKey, Role, User
from app.services import grants


def test_models_created_and_accessible(db_factory, world):
    with db_factory() as db:
        admin = db.get(User, world.admin)
        pk = PublicKey(user_id=admin.id, pem="-----BEGIN PUBLIC KEY-----\nMIIB...Fake\n-----END PUBLIC KEY-----")
        db.add(pk)
        db.commit()

        loaded_admin = db.get(User, world.admin)
        assert loaded_admin.public_key is not None
        assert loaded_admin.public_key.pem.startswith("-----BEGIN")

        # Test AccessGrant model
        tenant = db.get(User, world.tenant_a)
        grant = AccessGrant(
            tenant_id=tenant.id,
            requester_id=admin.id,
            kinds="ktp,profile",
            reason="Verification for lease compliance",
            status=GrantStatus.pending,
        )
        db.add(grant)
        db.commit()

        assert grant.id is not None
        assert grant.status == GrantStatus.pending
        assert grant.tenant.email == "tenant_a@test.test"
        assert grant.requester.email == "admin@test.test"


def test_create_request_validation(db_factory, world):
    with db_factory() as db:
        admin = db.get(User, world.admin)
        owner_a = db.get(User, world.owner_a)
        tenant_a = db.get(User, world.tenant_a)

        # Only admin can create request
        with pytest.raises(PermissionError, match="Only admins"):
            grants.create_request(db, owner_a, tenant_a, ["ktp"], "reason")

        # Target must be a tenant
        with pytest.raises(ValueError, match="only be requested for tenants"):
            grants.create_request(db, admin, owner_a, ["ktp"], "reason")

        # Cannot request own data
        with pytest.raises(ValueError, match="Cannot request access to your own data"):
            grants.create_request(db, admin, admin, ["ktp"], "reason")

        # Empty reason refused
        with pytest.raises(ValueError, match="Reason.*required"):
            grants.create_request(db, admin, tenant_a, ["ktp"], "   ")

        # Empty kinds refused
        with pytest.raises(ValueError, match="At least one document kind"):
            grants.create_request(db, admin, tenant_a, [], "reason")

        # Video not allowed (only profile, ktp, agreement)
        with pytest.raises(ValueError, match="Invalid document kinds"):
            grants.create_request(db, admin, tenant_a, ["video"], "reason")

        # Valid request succeeds and logs audit
        grant = grants.create_request(db, admin, tenant_a, ["ktp", "profile"], "Official verification")
        assert grant.id is not None
        assert grant.status == GrantStatus.pending
        assert grant.kinds == "ktp,profile"

        audit_entry = db.scalar(
            select(AuditLog).where(
                AuditLog.action == "request_access",
                AuditLog.target_id == grant.id,
            )
        )
        assert audit_entry is not None
        assert audit_entry.actor_id == admin.id
        assert audit_entry.ok is True


def test_single_pending_request_rule(db_factory, world):
    with db_factory() as db:
        admin = db.get(User, world.admin)
        tenant_a = db.get(User, world.tenant_a)

        # First request succeeds
        g1 = grants.create_request(db, admin, tenant_a, ["ktp"], "First request")
        assert g1.status == GrantStatus.pending

        # Second pending request for same tenant is rejected
        with pytest.raises(ValueError, match="Tenant already has a pending access request"):
            grants.create_request(db, admin, tenant_a, ["profile"], "Second request")

        # Once resolved (e.g. rejected), a new request is allowed
        grants.transition(db, g1, GrantStatus.rejected, actor=tenant_a, reason="Refused")
        assert g1.status == GrantStatus.rejected

        g2 = grants.create_request(db, admin, tenant_a, ["profile"], "Third request after rejection")
        assert g2.status == GrantStatus.pending


def test_get_grant_isolation(db_factory, world):
    with db_factory() as db:
        admin = db.get(User, world.admin)
        tenant_a = db.get(User, world.tenant_a)
        tenant_b = db.get(User, world.tenant_b)
        owner_a = db.get(User, world.owner_a)

        grant = grants.create_request(db, admin, tenant_a, ["ktp"], "Checking")

        # Tenant A can retrieve it
        retrieved = grants.get_tenant_grant_or_404(db, grant.id, tenant_a)
        assert retrieved.id == grant.id

        # Tenant B gets 404 (isolation)
        with pytest.raises(HTTPException) as exc:
            grants.get_tenant_grant_or_404(db, grant.id, tenant_b)
        assert exc.value.status_code == 404

        # Admin who requested gets it
        admin_retrieved = grants.get_admin_grant_or_404(db, grant.id, admin)
        assert admin_retrieved.id == grant.id

        # Non-admin or wrong role gets 404
        with pytest.raises(HTTPException) as exc:
            grants.get_admin_grant_or_404(db, grant.id, owner_a)
        assert exc.value.status_code == 404


def test_state_transitions_and_audit(db_factory, world):
    with db_factory() as db:
        admin = db.get(User, world.admin)
        tenant_a = db.get(User, world.tenant_a)

        grant = grants.create_request(db, admin, tenant_a, ["agreement"], "Contract check")

        # Approve
        grants.transition(db, grant, GrantStatus.approved, actor=tenant_a)
        assert grant.status == GrantStatus.approved
        assert grant.decided_at is not None
        assert grant.expires_at is not None
        assert grant.expires_at > grant.decided_at

        # Verify audit for approval
        approve_audit = db.scalar(
            select(AuditLog).where(
                AuditLog.action == "approve_access",
                AuditLog.target_id == grant.id,
            )
        )
        assert approve_audit is not None
        assert approve_audit.actor_id == tenant_a.id

        # Revoke
        grant.wrapped_key = b"dummy-key-wrapped"
        grants.transition(db, grant, GrantStatus.revoked, actor=tenant_a)
        assert grant.status == GrantStatus.revoked
        assert grant.revoked_at is not None
        assert grant.wrapped_key is None  # destroyed on revoke

        # Illegal transition from revoked -> approved raises ValueError
        with pytest.raises(ValueError, match="Invalid grant transition"):
            grants.transition(db, grant, GrantStatus.approved, actor=tenant_a)


def test_ensure_active_and_auto_expiration(db_factory, world):
    with db_factory() as db:
        admin = db.get(User, world.admin)
        tenant_a = db.get(User, world.tenant_a)

        grant = grants.create_request(db, admin, tenant_a, ["ktp"], "Check")
        grants.transition(db, grant, GrantStatus.approved, actor=tenant_a)
        grant.wrapped_key = b"wrapped-grant-key"
        db.commit()

        # Currently active
        assert grants.ensure_active(grant, db) is True
        assert grant.status == GrantStatus.approved

        # Simulate expiration by setting expires_at in the past
        grant.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.commit()

        # ensure_active transitions to expired and clears wrapped_key
        assert grants.ensure_active(grant, db) is False
        assert grant.status == GrantStatus.expired
        assert grant.wrapped_key is None

        # Expire audit entry logged
        expire_audit = db.scalar(
            select(AuditLog).where(
                AuditLog.action == "expire_access",
                AuditLog.target_id == grant.id,
            )
        )
        assert expire_audit is not None


def test_purge_for_tenant(db_factory, world):
    with db_factory() as db:
        admin = db.get(User, world.admin)
        tenant_a = db.get(User, world.tenant_a)
        tenant_b = db.get(User, world.tenant_b)

        g_a1 = grants.create_request(db, admin, tenant_a, ["ktp"], "Tenant A 1")
        grants.transition(db, g_a1, GrantStatus.approved, actor=tenant_a)
        g_b1 = grants.create_request(db, admin, tenant_b, ["ktp"], "Tenant B 1")

        # Purge tenant_a
        grants.purge_for_tenant(db, tenant_a)

        # tenant_a grants are gone
        assert len(grants.list_grants_for_tenant(db, tenant_a)) == 0
        # tenant_b grant remains intact
        assert len(grants.list_grants_for_tenant(db, tenant_b)) == 1


def test_admin_unwrap_dek_still_forbidden(world, db_factory):
    """REGRESSION TEST: The new grant feature MUST NOT weaken existing access boundaries.
    
    Admin unwrap_dek MUST still fail with PermissionError for any onboarding document.
    Admin can only unwrap to view video (legacy exception).
    """
    with db_factory() as db:
        admin = db.get(User, world.admin)
        tenant = db.get(User, world.tenant_a)

        # Admin attempting to unwrap DEK without kind or with personal kinds
        with pytest.raises(PermissionError):
            unwrap_dek(tenant, admin)

        with pytest.raises(PermissionError):
            unwrap_dek(tenant, admin, kind="ktp")

        with pytest.raises(PermissionError):
            unwrap_dek(tenant, admin, kind="profile")

        with pytest.raises(PermissionError):
            unwrap_dek(tenant, admin, kind="agreement")

        # Admin is only allowed for video
        video_dek = unwrap_dek(tenant, admin, kind="video")
        assert len(video_dek) == 32

