"""Grant and access management service (Melvan).

Handles:
- Admin requests to access tenant onboarding documents.
- State machine for access grants (pending -> approved / rejected / revoked / expired).
- Enforces single pending request per tenant.
- Auto-expiration check (TTL-based) on grant access.
- Purging grants and shares upon tenant account deletion.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AccessGrant, GrantStatus, Role, User
from app.services import audit

ALLOWED_KINDS = {"profile", "ktp", "agreement"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_request(
    db: Session,
    requester: User,
    tenant: User,
    kinds: list[str],
    reason: str,
) -> AccessGrant:
    """Admin creates a request to access specified tenant documents.
    
    Enforces:
    - Requester must be admin.
    - Target must be a tenant.
    - Only profile, ktp, and agreement may be requested.
    - Tenant may have at most one pending request at any time.
    """
    if requester.role != Role.admin:
        raise PermissionError("Only admins can request tenant document access.")
    if requester.id == tenant.id:
        raise ValueError("Cannot request access to your own data.")
    if tenant.role != Role.tenant:
        raise ValueError("Access can only be requested for tenants.")

    clean_kinds = [k.strip().lower() for k in kinds if k.strip()]
    if not clean_kinds:
        raise ValueError("At least one document kind must be requested.")
    invalid = set(clean_kinds) - ALLOWED_KINDS
    if invalid:
        raise ValueError(f"Invalid document kinds requested: {', '.join(sorted(invalid))}")

    clean_reason = (reason or "").strip()
    if not clean_reason:
        raise ValueError("Reason for access request is required.")

    # Check for existing pending request
    existing = db.scalar(
        select(AccessGrant).where(
            AccessGrant.tenant_id == tenant.id,
            AccessGrant.status == GrantStatus.pending,
        )
    )
    if existing is not None:
        raise ValueError("Tenant already has a pending access request.")

    grant = AccessGrant(
        tenant_id=tenant.id,
        requester_id=requester.id,
        kinds=",".join(sorted(set(clean_kinds))),
        reason=clean_reason,
        status=GrantStatus.pending,
    )
    db.add(grant)
    db.commit()
    db.refresh(grant)

    audit.log(db, requester, "request_access", "access_grant", grant.id, ok=True)
    return grant


def ensure_active(grant: AccessGrant, db: Session | None = None) -> bool:
    """Check whether an approved grant is still active.
    
    If the grant has expired, automatically transitions it to expired,
    clears wrapped_key, and cleans up share files.
    """
    if grant.status != GrantStatus.approved:
        return False

    if grant.expires_at is not None:
        expires_at = grant.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if _now() > expires_at:
            if db is not None:
                transition(db, grant, GrantStatus.expired, actor=None)
            else:
                grant.status = GrantStatus.expired
                grant.wrapped_key = None
            return False

    return True


def get_tenant_grant_or_404(db: Session, grant_id: int, tenant: User) -> AccessGrant:
    """Retrieve an access grant belonging to the given tenant, or 404."""
    if tenant.role != Role.tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access request not found.")
    grant = db.scalar(
        select(AccessGrant).where(
            AccessGrant.id == grant_id,
            AccessGrant.tenant_id == tenant.id,
        )
    )
    if grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access request not found.")
    ensure_active(grant, db)
    return grant


def get_admin_grant_or_404(db: Session, grant_id: int, admin: User) -> AccessGrant:
    """Retrieve an access grant requested by the given admin, or 404."""
    if admin.role != Role.admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access request not found.")
    grant = db.scalar(
        select(AccessGrant).where(
            AccessGrant.id == grant_id,
            AccessGrant.requester_id == admin.id,
        )
    )
    if grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access request not found.")
    ensure_active(grant, db)
    return grant


def transition(
    db: Session,
    grant: AccessGrant,
    target_status: GrantStatus,
    actor: User | None = None,
    reason: str = "",
) -> None:
    """Single authority for grant state changes with strict transition rules."""
    now = _now()
    audit_action: str

    if grant.status == GrantStatus.pending and target_status == GrantStatus.approved:
        grant.status = GrantStatus.approved
        grant.decided_at = now
        grant.expires_at = now + timedelta(minutes=settings.access_grant_ttl_minutes)
        audit_action = "approve_access"

    elif grant.status == GrantStatus.pending and target_status == GrantStatus.rejected:
        grant.status = GrantStatus.rejected
        grant.decided_at = now
        grant.reject_reason = (reason or "")[:1000]
        audit_action = "reject_access"

    elif grant.status == GrantStatus.approved and target_status == GrantStatus.revoked:
        grant.status = GrantStatus.revoked
        grant.revoked_at = now
        grant.wrapped_key = None
        _try_destroy_shares(grant.tenant_id, grant.id)
        audit_action = "revoke_access"

    elif grant.status == GrantStatus.approved and target_status == GrantStatus.expired:
        grant.status = GrantStatus.expired
        grant.wrapped_key = None
        _try_destroy_shares(grant.tenant_id, grant.id)
        audit_action = "expire_access"

    else:
        raise ValueError(f"Invalid grant transition from {grant.status.value} to {target_status.value}")

    db.commit()
    audit.log(db, actor, audit_action, "access_grant", grant.id, ok=True)


def _try_destroy_shares(tenant_id: int, grant_id: int) -> None:
    try:
        from app.crypto import shares
        shares.destroy_share(tenant_id, grant_id)
    except (ImportError, AttributeError):
        pass


def purge_for_tenant(db: Session, tenant: User) -> None:
    """Purge all access grants and share files when a tenant account is deleted."""
    grants = list(db.scalars(select(AccessGrant).where(AccessGrant.tenant_id == tenant.id)))
    for g in grants:
        _try_destroy_shares(tenant.id, g.id)
        db.delete(g)
    db.commit()


def list_grants_for_tenant(db: Session, tenant: User) -> list[AccessGrant]:
    """Return all grants for a tenant, running expiration checks on approved ones."""
    grants = list(
        db.scalars(
            select(AccessGrant)
            .where(AccessGrant.tenant_id == tenant.id)
            .order_by(AccessGrant.requested_at.desc())
        )
    )
    for g in grants:
        if g.status == GrantStatus.approved:
            ensure_active(g, db)
    return grants


def list_grants_for_admin(db: Session, admin: User) -> list[AccessGrant]:
    """Return all grants requested by an admin, running expiration checks on approved ones."""
    grants = list(
        db.scalars(
            select(AccessGrant)
            .where(AccessGrant.requester_id == admin.id)
            .order_by(AccessGrant.requested_at.desc())
        )
    )
    for g in grants:
        if g.status == GrantStatus.approved:
            ensure_active(g, db)
    return grants


def count_pending_for_tenant(db: Session, tenant: User) -> int:
    """Count pending access requests for tenant badge/banner."""
    return db.scalar(
        select(func.count(AccessGrant.id)).where(
            AccessGrant.tenant_id == tenant.id,
            AccessGrant.status == GrantStatus.pending,
        )
    ) or 0
