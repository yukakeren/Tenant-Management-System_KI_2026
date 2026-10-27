"""Full-app fixtures: real routes, login and CSRF, on an in-memory DB and a temp blob folder."""
import dataclasses
import re
from types import SimpleNamespace

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import security
from app.crypto import vault
from app.crypto.keys import create_dek
from app.db import Base, get_db
from app.main import create_app
from app.models import Kos, Role, Room, User

PASSWORD = "correct-horse-battery"
_CSRF = re.compile(r'name="csrf" value="([^"]+)"')


class Client(TestClient):
    def csrf(self, page: str = "/account/password") -> str:
        return _CSRF.search(self.get(page).text).group(1)

    def login(self, email: str, password: str = PASSWORD):
        r = self.post("/login", data={"email": email, "password": password,
                                      "csrf": self.csrf("/login")}, follow_redirects=False)
        assert r.status_code == 303, r.text
        return r

    def submit(self, url: str, data: dict | None = None, **kw):
        """POST a form with the session's CSRF token, without following the redirect."""
        return self.post(url, data={**(data or {}), "csrf": self.csrf()}, follow_redirects=False, **kw)


@pytest.fixture
def db_factory(tmp_path, monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(vault, "settings", dataclasses.replace(vault.settings, storage_dir=tmp_path))
    # Fast argon2 parameters so each test doesn't spend seconds hashing
    monkeypatch.setattr(security, "_ph", PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1))
    security._FAILS.clear()
    yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def make_client(db_factory):
    app = create_app()

    def override_get_db():
        db = db_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return lambda: Client(app)


@pytest.fixture
def world(db_factory):
    """Admin; owner A with tenant A in room 101; owner B with tenant B in room B1; a tenant who has moved out (no room)."""
    with db_factory() as db:
        def user(email, role, **kw):
            u = User(email=email, password_hash=security.hash_password(PASSWORD), role=role,
                     must_change_password=False, **kw)
            db.add(u)
            db.flush()
            if role == Role.tenant:
                create_dek(u)
            return u

        admin = user("admin@test.test", Role.admin)
        owner_a, owner_b = user("owner_a@test.test", Role.owner), user("owner_b@test.test", Role.owner)
        tenant_a, tenant_b = user("tenant_a@test.test", Role.tenant), user("tenant_b@test.test", Role.tenant)
        free = user("free@test.test", Role.tenant)
        kos_a = Kos(owner_id=owner_a.id, name="Kos A", address="Jl. A")
        kos_b = Kos(owner_id=owner_b.id, name="Kos B", address="Jl. B")
        db.add_all([kos_a, kos_b])
        db.flush()
        room_a = Room(kos_id=kos_a.id, number="101", tenant_id=tenant_a.id)
        room_a_empty = Room(kos_id=kos_a.id, number="102")
        room_b = Room(kos_id=kos_b.id, number="B1", tenant_id=tenant_b.id)
        db.add_all([room_a, room_a_empty, room_b])
        db.commit()
        return SimpleNamespace(**{k: v.id for k, v in dict(
            admin=admin, owner_a=owner_a, owner_b=owner_b, tenant_a=tenant_a, tenant_b=tenant_b,
            free=free, kos_a=kos_a, kos_b=kos_b, room_a=room_a, room_a_empty=room_a_empty,
            room_b=room_b).items()})
