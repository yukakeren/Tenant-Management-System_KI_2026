import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    tenant = "tenant"
    owner = "owner"
    admin = "admin"


class ItemKind(str, enum.Enum):
    profile = "profile"
    ktp = "ktp"
    agreement = "agreement"
    video = "video"


class CipherName(str, enum.Enum):
    aes = "aes"
    des = "des"
    rc4 = "rc4"


class DeletionStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    done = "done"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # set when the admin creates/resets the account, cleared after the user picks their own password
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    # nonce(12) || ct(32) || tag(16), wrapped with MASTER_KEY. NULL for admins and after shredding.
    wrapped_dek: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    kos_list: Mapped[list["Kos"]] = relationship(back_populates="owner")
    room: Mapped["Room | None"] = relationship(back_populates="tenant", foreign_keys="Room.tenant_id")


class Kos(Base):
    __tablename__ = "kos"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    address: Mapped[str] = mapped_column(String(255))

    owner: Mapped[User] = relationship(back_populates="kos_list")
    rooms: Mapped[list["Room"]] = relationship(back_populates="kos", cascade="all, delete-orphan")


class Room(Base):
    __tablename__ = "rooms"
    __table_args__ = (UniqueConstraint("kos_id", "number"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kos_id: Mapped[int] = mapped_column(ForeignKey("kos.id"), index=True)
    number: Mapped[str] = mapped_column(String(20))
    # unique: one tenant occupies at most one room
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), unique=True, nullable=True)

    kos: Mapped[Kos] = relationship(back_populates="rooms")
    tenant: Mapped[User | None] = relationship(back_populates="room", foreign_keys=[tenant_id])


class SecretItem(Base):
    __tablename__ = "secret_items"
    __table_args__ = (UniqueConstraint("subject_id", "kind"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    subject_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[ItemKind] = mapped_column(Enum(ItemKind))
    mime: Mapped[str] = mapped_column(String(100))
    plain_size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    blobs: Mapped[list["SecretBlob"]] = relationship(back_populates="item", cascade="all, delete-orphan")


class SecretBlob(Base):
    __tablename__ = "secret_blobs"
    __table_args__ = (UniqueConstraint("item_id", "cipher"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("secret_items.id"), index=True)
    cipher: Mapped[CipherName] = mapped_column(Enum(CipherName))
    path: Mapped[str] = mapped_column(String(500))
    ct_size: Mapped[int] = mapped_column(Integer)
    enc_ms: Mapped[float] = mapped_column()

    item: Mapped[SecretItem] = relationship(back_populates="blobs")


class DeletionRequest(Base):
    __tablename__ = "deletion_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    # owner at the time of the request, so it still has someone to go to after move-out
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[DeletionStatus] = mapped_column(Enum(DeletionStatus), default=DeletionStatus.pending)
    reject_reason: Mapped[str] = mapped_column(Text, default="")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(50))
    target_type: Mapped[str] = mapped_column(String(50), default="")
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    detail: Mapped[str] = mapped_column(String(255), default="")  # never put personal data here
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
