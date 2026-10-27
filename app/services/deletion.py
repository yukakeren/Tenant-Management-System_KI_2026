"""Deciding deletion requests. Owners decide their tenants' requests; the admin decides
requests that have no owner (tenant already moved out when asking)."""
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.crypto import vault
from app.models import DeletionRequest, DeletionStatus, User
from app.services import audit


def tenant_of_pending(db: Session, req: DeletionRequest) -> User:
    if req.status != DeletionStatus.pending:
        raise HTTPException(400, "This request has already been decided.")
    return db.get(User, req.tenant_id)


def confirm_word(tenant: User) -> str:
    # Typed back by the decider before an irreversible shred
    return tenant.room.number if tenant.room else tenant.email


def approve(db: Session, req: DeletionRequest, tenant: User, actor: User) -> None:
    room = tenant.room
    try:
        vault.shred_user(tenant, actor)  # deletes files and DEK, marks the request done, commits
    except PermissionError:
        raise HTTPException(404, "Deletion request not found.") from None
    if room is not None:
        room.tenant_id = None
    tenant.is_active = False
    req.decided_by = actor.id
    req.decided_at = datetime.now(timezone.utc)
    db.commit()
    audit.log(db, actor, "approve_deletion", "user", tenant.id)


def reject(db: Session, req: DeletionRequest, tenant: User, actor: User, reason: str) -> None:
    req.status = DeletionStatus.rejected
    req.reject_reason = reason[:1000]
    req.decided_by = actor.id
    req.decided_at = datetime.now(timezone.utc)
    db.commit()
    audit.log(db, actor, "reject_deletion", "user", tenant.id)
