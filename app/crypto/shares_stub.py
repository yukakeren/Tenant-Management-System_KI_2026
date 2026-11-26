# Tambahkan import ini
from app.models import (
    DeletionRequest, DeletionStatus, ItemKind, Role,
    SecretItem, User, AccessGrant, GrantStatus, PublicKey  # ← tambahan
)
from app.services import audit, grants as grant_service  # ← tambahan

# Untuk Fase 1, pakai stub. Fase 2, ganti ke modul asli.
try:
    from app.crypto import shares
    from app.crypto import asym
except ImportError:
    from app.crypto import shares_stub as shares
    from app.crypto import asym_stub as asym
