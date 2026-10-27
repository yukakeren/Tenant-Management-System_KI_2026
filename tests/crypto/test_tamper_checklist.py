"""Naura. Every row of the tamper checklist in docs/implementation/testing.md, run against real vault files.

Each case edits a stored KSK1 file on disk (or the key) and expects IntegrityError from verify_item.
"""
import os
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import app.crypto  # noqa: F401  (registers the ciphers)
from app.crypto import vault
from app.crypto.base import IntegrityError
from app.crypto.keys import create_dek
from app.db import Base
from app.models import Role, SecretBlob, SecretItem, User

CIPHERS = ("aes", "des", "rc4")
# Where the ciphertext starts inside a record: DES records begin with the 8-byte IV
CT_OFFSET = {"aes": 0, "des": 8, "rc4": 0}
DATA = os.urandom((5 << 20) // 2)  # 2.5 MiB: three records, so swap/remove/append are meaningful


def parse(blob: bytes) -> tuple[bytes, list[bytes]]:
    pos = 12 + int.from_bytes(blob[10:12], "big")
    header, records = blob[:pos], []
    while pos < len(blob):
        length = int.from_bytes(blob[pos:pos + 4], "big")
        records.append(blob[pos + 4:pos + 4 + length])
        pos += 4 + length
    return header, records


def build(header: bytes, records: list[bytes]) -> bytes:
    return header + b"".join(len(r).to_bytes(4, "big") + r for r in records)


def flip(data: bytes, index: int) -> bytes:
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "settings", SimpleNamespace(storage_dir=tmp_path, read_cipher="aes"))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        a = User(email="a@test.test", password_hash="x", role=Role.tenant)
        b = User(email="b@test.test", password_hash="x", role=Role.tenant)
        db.add_all([a, b])
        db.flush()
        create_dek(a)
        create_dek(b)
        db.commit()
        vault.store_item(a, "ktp", BytesIO(DATA), "image/png", a)
        vault.store_item(a, "agreement", BytesIO(DATA[::-1]), "application/pdf", a)
        vault.store_item(b, "ktp", BytesIO(DATA), "image/png", b)
        yield SimpleNamespace(db=db, a=a, b=b)


def path_of(env, user: User, kind: str, cipher: str) -> Path:
    item = env.db.scalar(select(SecretItem).where(SecretItem.subject_id == user.id, SecretItem.kind == kind))
    return Path(env.db.scalar(select(SecretBlob.path).where(
        SecretBlob.item_id == item.id, SecretBlob.cipher == cipher)))


def edit_records(path: Path, change) -> None:
    header, records = parse(path.read_bytes())
    path.write_bytes(build(*change(header, records)))


def edit_first_record(offset_fn):
    def change(header, records):
        records[0] = flip(records[0], offset_fn(records[0]))
        return header, records
    return change


def tamper(env, case: str, cipher: str) -> None:
    ktp = path_of(env, env.a, "ktp", cipher)
    if case == "header byte":
        edit_records(ktp, lambda h, r: (flip(h, 9), r))  # chunk_size field
    elif case == "params byte":
        edit_records(ktp, lambda h, r: (flip(h, 12), r))
    elif case == "ciphertext byte":
        edit_records(ktp, edit_first_record(lambda rec: CT_OFFSET[cipher]))
    elif case == "tag byte":
        edit_records(ktp, edit_first_record(lambda rec: len(rec) - 1))
    elif case == "DES IV":
        edit_records(ktp, edit_first_record(lambda rec: 0))
    elif case == "swap two chunks":
        edit_records(ktp, lambda h, r: (h, [r[1], r[0], *r[2:]]))
    elif case == "remove last record":
        edit_records(ktp, lambda h, r: (h, r[:-1]))
    elif case == "cut last record in half":
        ktp.write_bytes(ktp.read_bytes()[:-len(parse(ktp.read_bytes())[1][-1]) // 2])
    elif case == "append copied record":
        edit_records(ktp, lambda h, r: (h, r + [r[-1]]))
    elif case == "move file to another tenant":
        # A's KTP copied over B's KTP; then we read B's
        path_of(env, env.b, "ktp", cipher).write_bytes(ktp.read_bytes())
    elif case == "swap KTP and agreement":
        agreement = path_of(env, env.a, "agreement", cipher)
        k, a = ktp.read_bytes(), agreement.read_bytes()
        ktp.write_bytes(a)
        agreement.write_bytes(k)
    elif case == "wrong key":
        env.a.wrapped_dek = None
        create_dek(env.a)  # a different DEK for the same user
    else:
        raise ValueError(case)


CASES = ["header byte", "params byte", "ciphertext byte", "tag byte", "DES IV", "swap two chunks",
         "remove last record", "cut last record in half", "append copied record",
         "move file to another tenant", "swap KTP and agreement", "wrong key"]


@pytest.mark.parametrize("cipher", CIPHERS)
def test_untouched_files_verify(env, cipher):
    vault.verify_item(env.a, "ktp", cipher, env.a)
    assert b"".join(vault.open_item(env.a, "ktp", cipher, env.a)) == DATA


@pytest.mark.parametrize("cipher", CIPHERS)
@pytest.mark.parametrize("case", CASES)
def test_tamper_checklist(env, case, cipher):
    if case == "DES IV" and cipher != "des":
        pytest.skip("only DES has a per-chunk IV")
    tamper(env, case, cipher)
    victim = env.b if case == "move file to another tenant" else env.a
    with pytest.raises(IntegrityError):
        vault.verify_item(victim, "ktp", cipher, victim)
    with pytest.raises(IntegrityError):
        b"".join(vault.open_item(victim, "ktp", cipher, victim))
