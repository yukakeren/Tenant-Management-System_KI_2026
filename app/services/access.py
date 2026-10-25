"""Access control service (Person 2 - Melvan).

This module is the single source of truth for authorization across KosanKu.
It decides who can access which tenant's data, enforcing strict tenant-owner boundaries:
- Tenants can only view and access their own data.
- Owners can only view and access data for tenants currently staying in their kos rooms.
- Admins can manage accounts, but are strictly prohibited from viewing or decrypting any personal data.

To prevent enumeration attacks, any request for an entity not owned by the caller
raises HTTP 404 rather than 403.
"""

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, object_session

from app.models import DeletionRequest, Kos, Role, Room, User


def owner_has_tenant(owner: User, tenant: User, db: Session | None = None) -> bool:
    """Check whether the given tenant occupies a room in any Kos owned by owner.

    Returns True only if the tenant is assigned to a room of the owner's kos.
    """
    if owner.role != Role.owner or tenant.role != Role.tenant:
        return False

    session = db or object_session(owner) or object_session(tenant)
    if session is not None:
        stmt = (
            select(Room.id)
            .join(Kos, Room.kos_id == Kos.id)
            .where(Room.tenant_id == tenant.id, Kos.owner_id == owner.id)
        )
        return session.scalar(stmt) is not None

    # In-memory relationship fallback (e.g. for mock tests with pre-populated relationships)
    if getattr(tenant, "room", None) is not None and tenant.room is not None:
        if getattr(tenant.room, "kos", None) is not None and tenant.room.kos is not None:
            return tenant.room.kos.owner_id == owner.id

    return False


def can_view_subject(actor: User, subject: User, db: Session | None = None) -> bool:
    """Determine if actor is authorized to access/decrypt subject's data.

    Rules:
    - Admin: NEVER allowed to access personal subject data (returns False).
    - Tenant: can only access their own data (actor.id == subject.id).
    - Owner: can access subject data if subject is currently assigned to a room in their Kos.
    """
    if actor.role == Role.admin:
        return False

    if actor.role == Role.tenant:
        return actor.id == subject.id

    if actor.role == Role.owner:
        if actor.id == subject.id:
            return True
        return owner_has_tenant(actor, subject, db=db)

    return False


def get_owned_kos_or_404(db: Session, owner: User, kos_id: int) -> Kos:
    """Retrieve a Kos by ID ensuring it belongs to the given owner.
    Raises 404 if it does not exist or belongs to another owner.
    """
    stmt = select(Kos).where(Kos.id == kos_id, Kos.owner_id == owner.id)
    kos = db.scalar(stmt)
    if kos is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Kos not found",
        )
    return kos


def get_owned_room_or_404(db: Session, owner: User, room_id: int) -> Room:
    """Retrieve a Room by ID ensuring its parent Kos belongs to the given owner.
    Filters at the query level (Kos.owner_id == owner.id).
    Raises 404 if it does not exist or is not owned by the caller.
    """
    stmt = (
        select(Room)
        .join(Kos, Room.kos_id == Kos.id)
        .where(Room.id == room_id, Kos.owner_id == owner.id)
    )
    room = db.scalar(stmt)
    if room is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Room not found",
        )
    return room


def get_owned_tenant_or_404(db: Session, owner: User, tenant_id: int) -> User:
    """Retrieve a Tenant by ID ensuring they currently occupy a room in the owner's Kos.
    Filters at the query level to prevent information leakage.
    Raises 404 if the user does not exist or is not the caller's tenant.
    """
    stmt = (
        select(User)
        .join(Room, Room.tenant_id == User.id)
        .join(Kos, Room.kos_id == Kos.id)
        .where(User.id == tenant_id, User.role == Role.tenant, Kos.owner_id == owner.id)
    )
    tenant = db.scalar(stmt)
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )
    return tenant


def get_owned_deletion_request_or_404(
    db: Session, owner: User, request_id: int
) -> DeletionRequest:
    """Retrieve a DeletionRequest by ID ensuring it belongs to the owner.
    Matches either requests explicitly assigned to this owner or for tenants
    currently in this owner's rooms.
    Raises 404 if not found or unauthorized.
    """
    stmt = (
        select(DeletionRequest)
        .outerjoin(Room, Room.tenant_id == DeletionRequest.tenant_id)
        .outerjoin(Kos, Room.kos_id == Kos.id)
        .where(
            DeletionRequest.id == request_id,
            (DeletionRequest.owner_id == owner.id) | (Kos.owner_id == owner.id),
        )
    )
    req = db.scalar(stmt)
    if req is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deletion request not found",
        )
    return req
