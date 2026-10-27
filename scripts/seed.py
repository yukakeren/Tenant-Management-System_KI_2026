"""Demo data: 1 admin, 1 owner with 2 kos, 3 tenants each in a room with their documents
already uploaded (profile, KTP, rental agreement, room video), and some empty rooms.

Run once on an empty database: python scripts/seed.py

Demo files in scripts/demo_files/: the KTPs are generated fake specimens (fictional people,
marked "SPESIMEN - DATA FIKTIF"); agreement.pdf is the W3C dummy PDF and room_video.mp4 is
a 5-second sample clip from samplelib.com.
"""
# Allow direct execution from the repository root (python scripts/...).
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import json
from pathlib import Path

from sqlalchemy import select

from app.auth.security import hash_password
from app.config import settings
from app.crypto import vault
from app.crypto.keys import create_dek
from app.db import SessionLocal, init_db
from app.models import ItemKind, Kos, Role, Room, User

PASSWORD = "kosanku-demo"  # demo only; every seeded account uses it
FILES = Path(__file__).resolve().parent / "demo_files"

TENANTS = [
    ("tenant1@kosanku.test", "Kos Melati", "101", {
        "full_name": "Budi Santoso", "nik": "3273010101000001", "birth_date": "2000-01-31",
        "gender": "male", "phone": "081234567801", "origin_address": "Jl. Asal No. 1, Bandung",
        "occupation": "Student",
        "emergency_contact": {"name": "Sri Santoso", "relation": "Mother", "phone": "081234567811"}}),
    ("tenant2@kosanku.test", "Kos Melati", "102", {
        "full_name": "Siti Rahayu", "nik": "3273010202000002", "birth_date": "2001-02-14",
        "gender": "female", "phone": "081234567802", "origin_address": "Jl. Contoh No. 2, Bogor",
        "occupation": "Private employee",
        "emergency_contact": {"name": "Ahmad Rahayu", "relation": "Father", "phone": "081234567812"}}),
    ("tenant3@kosanku.test", "Kos Mawar", "A1", {
        "full_name": "Andi Pratama", "nik": "3273010303000003", "birth_date": "1999-03-03",
        "gender": "male", "phone": "081234567803", "origin_address": "Jl. Fiktif No. 3, Bekasi",
        "occupation": "Student",
        "emergency_contact": {"name": "Dewi Pratama", "relation": "Sister", "phone": "081234567813"}}),
]


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
            return u

        user("admin@kosanku.test", Role.admin)
        owner = user("owner@kosanku.test", Role.owner)
        kos = {
            "Kos Melati": Kos(owner_id=owner.id, name="Kos Melati", address="Jl. Melati No. 10, Bandung"),
            "Kos Mawar": Kos(owner_id=owner.id, name="Kos Mawar", address="Jl. Mawar No. 5, Bandung"),
        }
        db.add_all(kos.values())
        db.flush()
        rooms = {(k, n): Room(kos_id=kos[k].id, number=n) for k, n in [
            ("Kos Melati", "101"), ("Kos Melati", "102"), ("Kos Melati", "103"),
            ("Kos Mawar", "A1"), ("Kos Mawar", "A2")]}
        db.add_all(rooms.values())
        db.flush()

        tenants = []
        for i, (email, kos_name, number, profile) in enumerate(TENANTS, start=1):
            t = user(email, Role.tenant)
            create_dek(t)
            rooms[(kos_name, number)].tenant_id = t.id
            tenants.append((i, t, profile))
        db.commit()

        # Uploaded the way the tenant would: each file encrypted with AES, DES and RC4
        for i, t, profile in tenants:
            vault.store_bytes(t, ItemKind.profile, json.dumps(profile).encode(), t)
            for kind, path, mime in [(ItemKind.ktp, FILES / f"ktp_tenant{i}.jpg", "image/jpeg"),
                                     (ItemKind.agreement, FILES / "agreement.pdf", "application/pdf"),
                                     (ItemKind.video, FILES / "room_video.mp4", "video/mp4")]:
                with path.open("rb") as f:
                    vault.store_item(t, kind, f, mime, t)

    print(f"Seeded. Every account's password is: {PASSWORD}")
    print("  admin@kosanku.test    admin")
    print("  owner@kosanku.test    owner of Kos Melati (101 tenant1, 102 tenant2, 103 empty) and Kos Mawar (A1 tenant3, A2 empty)")
    for email, kos_name, number, profile in TENANTS:
        print(f"  {email:<21} {profile['full_name']}, {kos_name} {number}, all documents uploaded")


if __name__ == "__main__":
    main()
