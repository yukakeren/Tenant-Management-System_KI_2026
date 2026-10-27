"""Demo data: 1 admin, 2 owners, 3 tenants, 2 kos with rooms, 2 tenants already in rooms.

Run once on an empty database: python scripts/seed.py
"""
# Allow direct execution from the repository root (python scripts/...).
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

from sqlalchemy import select

from app.auth.security import hash_password
from app.config import settings
from app.crypto.keys import create_dek
from app.db import SessionLocal, init_db
from app.models import Kos, Role, Room, User

PASSWORD = "kosanku-demo"  # demo only; every seeded account uses it


def main() -> None:
    init_db()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    with SessionLocal() as db:
        if db.scalar(select(User.id).limit(1)) is not None:
            sys.exit("The database already has users. Delete kosanku.db (and storage/) to reseed.")

        def user(email: str, role: Role) -> User:
            u = User(email=email, password_hash=hash_password(PASSWORD), role=role,
                     must_change_password=False)
            db.add(u)
            db.flush()
            if role == Role.tenant:
                create_dek(u)
            return u

        user("admin@kosanku.test", Role.admin)
        owner1 = user("owner1@kosanku.test", Role.owner)
        owner2 = user("owner2@kosanku.test", Role.owner)
        tenant1 = user("tenant1@kosanku.test", Role.tenant)
        tenant2 = user("tenant2@kosanku.test", Role.tenant)
        user("tenant3@kosanku.test", Role.tenant)  # no room yet, for the assign demo

        melati = Kos(owner_id=owner1.id, name="Kos Melati", address="Jl. Melati No. 10, Bandung")
        mawar = Kos(owner_id=owner2.id, name="Kos Mawar", address="Jl. Mawar No. 5, Bandung")
        db.add_all([melati, mawar])
        db.flush()
        db.add_all([
            Room(kos_id=melati.id, number="101", tenant_id=tenant1.id),
            Room(kos_id=melati.id, number="102"),
            Room(kos_id=melati.id, number="103"),
            Room(kos_id=mawar.id, number="A1", tenant_id=tenant2.id),
            Room(kos_id=mawar.id, number="A2"),
        ])
        db.commit()

    print(f"Seeded. Every account's password is: {PASSWORD}")
    print("  admin@kosanku.test    admin")
    print("  owner1@kosanku.test   owner of Kos Melati (101 tenant1, 102, 103)")
    print("  owner2@kosanku.test   owner of Kos Mawar (A1 tenant2, A2)")
    print("  tenant1@kosanku.test  tenant in Kos Melati 101")
    print("  tenant2@kosanku.test  tenant in Kos Mawar A1")
    print("  tenant3@kosanku.test  tenant without a room")


if __name__ == "__main__":
    main()
