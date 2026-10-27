from sqlalchemy.orm import Session

from app.models import AuditLog, User


def log(db: Session, actor: User | None, action: str, target_type: str = "",
        target_id: int | None = None, ok: bool = True, detail: str = "") -> None:
    """Commits on its own. Never pass personal data in detail."""
    db.add(AuditLog(actor_id=actor.id if actor else None, action=action, target_type=target_type,
                    target_id=target_id, ok=ok, detail=detail[:255]))
    db.commit()
