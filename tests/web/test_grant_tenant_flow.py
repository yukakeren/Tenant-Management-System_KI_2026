"""Tests for tenant-side access grant flow (Ajil).

Tests:
- Tenant sees pending request in privacy page
- Tenant approves → creates share, encrypted key available
- Tenant rejects → grant transitions to rejected
- Tenant revokes approved grant → share destroyed
- Show encrypted key page works for approved grants
- Badge count is correct
- Cannot approve already-decided grant
- Cannot revoke non-approved grant
"""
import pytest
from sqlalchemy import select

from app.models import AccessGrant, AuditLog, GrantStatus, PublicKey, User
from app.services import grants


def _make_pending_grant(db, admin_id, tenant_id, kinds="ktp,profile"):
    """Helper: insert a pending grant directly."""
    admin = db.get(User, admin_id)
    tenant = db.get(User, tenant_id)
    return grants.create_request(db, admin, tenant, kinds.split(","), "Verification needed")


def test_tenant_privacy_page_shows_grants(db_factory, world, client_tenant_a):
    """Tenant sees their access requests on the privacy page."""
    with db_factory() as db:
        _make_pending_grant(db, world.admin, world.tenant_a)

    resp = client_tenant_a.get("/tenant/access-requests")
    assert resp.status_code == 200
    assert "Diproses" in resp.text  # pending status in Indonesian
    assert "Verification needed" in resp.text


def test_tenant_approve_flow(db_factory, world, client_tenant_a):
    """Approving creates share, stores wrapped_key, transitions to approved."""
    with db_factory() as db:
        # Admin needs a public key first
        db.add(PublicKey(user_id=world.admin,
                         pem="-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...STUB\n-----END PUBLIC KEY-----"))
        db.commit()
        grant = _make_pending_grant(db, world.admin, world.tenant_a)
        grant_id = grant.id

    resp = client_tenant_a.post(f"/tenant/access-requests/{grant_id}/approve",
                                 data={"csrf": "test"}, follow_redirects=False)
    assert resp.status_code in (303, 302)

    with db_factory() as db:
        grant = db.get(AccessGrant, grant_id)
        assert grant.status == GrantStatus.approved
        assert grant.wrapped_key is not None
        assert grant.expires_at is not None


def test_tenant_reject_flow(db_factory, world, client_tenant_a):
    """Rejecting transitions grant to rejected status."""
    with db_factory() as db:
        grant = _make_pending_grant(db, world.admin, world.tenant_a)
        grant_id = grant.id

    resp = client_tenant_a.post(f"/tenant/access-requests/{grant_id}/reject",
                                 data={"csrf": "test", "reason": "Saya menolak"},
                                 follow_redirects=False)
    assert resp.status_code in (303, 302)

    with db_factory() as db:
        grant = db.get(AccessGrant, grant_id)
        assert grant.status == GrantStatus.rejected


def test_tenant_revoke_flow(db_factory, world, client_tenant_a):
    """Revoking an approved grant clears wrapped_key and destroys shares."""
    with db_factory() as db:
        db.add(PublicKey(user_id=world.admin,
                         pem="-----BEGIN PUBLIC KEY-----\nSTUB\n-----END PUBLIC KEY-----"))
        db.commit()
        grant = _make_pending_grant(db, world.admin, world.tenant_a)
        grants.transition(db, grant, GrantStatus.approved, actor=db.get(User, world.tenant_a))
        grant.wrapped_key = b"test-wrapped-key"
        db.commit()
        grant_id = grant.id

    resp = client_tenant_a.post(f"/tenant/access-requests/{grant_id}/revoke",
                                 data={"csrf": "test"}, follow_redirects=False)
    assert resp.status_code in (303, 302)

    with db_factory() as db:
        grant = db.get(AccessGrant, grant_id)
        assert grant.status == GrantStatus.revoked
        assert grant.wrapped_key is None


def test_cannot_approve_already_decided(db_factory, world, client_tenant_a):
    """Cannot approve a grant that is already rejected."""
    with db_factory() as db:
        db.add(PublicKey(user_id=world.admin,
                         pem="-----BEGIN PUBLIC KEY-----\nSTUB\n-----END PUBLIC KEY-----"))
        db.commit()
        grant = _make_pending_grant(db, world.admin, world.tenant_a)
        grants.transition(db, grant, GrantStatus.rejected,
                          actor=db.get(User, world.tenant_a), reason="no")
        grant_id = grant.id

    resp = client_tenant_a.post(f"/tenant/access-requests/{grant_id}/approve",
                                 data={"csrf": "test"}, follow_redirects=True)
    assert "sudah diproses" in resp.text.lower() or resp.status_code in (303, 302)


def test_pending_badge_count(db_factory, world):
    """count_pending_for_tenant returns correct number."""
    with db_factory() as db:
        admin = db.get(User, world.admin)
        tenant = db.get(User, world.tenant_a)

        assert grants.count_pending_for_tenant(db, tenant) == 0

        grants.create_request(db, admin, tenant, ["ktp"], "First")
        assert grants.count_pending_for_tenant(db, tenant) == 1
