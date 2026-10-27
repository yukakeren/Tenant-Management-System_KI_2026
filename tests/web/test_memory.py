"""Naura. A 200 MiB video goes up and comes back down through a real uvicorn process
whose peak memory (VmHWM, Linux only) has to stay under the 100 MiB budget.

Run with: pytest -m slow -s tests/web/test_memory.py
"""
import hashlib
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.crypto.keys import create_dek
from app.db import Base
from app.models import Role, User

ROOT = Path(__file__).resolve().parents[2]
SIZE = 200 << 20
BUDGET_MIB = 100

pytestmark = [pytest.mark.slow,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")]


def mem_mib(pid: int, field: str) -> float:
    status = Path(f"/proc/{pid}/status").read_text()
    return int(re.search(rf"{field}:\s+(\d+) kB", status).group(1)) / 1024


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture
def server(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'mem.db'}"
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        user = User(email="video@test.test", password_hash=hash_password("video-password"),
                    role=Role.tenant, must_change_password=False)
        db.add(user)
        db.flush()
        create_dek(user)
        db.commit()
    engine.dispose()

    port = free_port()
    env = {**os.environ, "DATABASE_URL": db_url, "STORAGE_DIR": str(tmp_path / "blobs"), "DEBUG": "true"}
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port),
                             "--log-level", "warning"], cwd=ROOT, env=env)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            httpx.get(f"{base}/login")
            break
        except httpx.ConnectError:
            time.sleep(0.1)
    yield proc, base
    proc.terminate()
    proc.wait(10)


def test_200mib_upload_and_download_stay_under_budget(server, tmp_path):
    proc, base = server
    video = tmp_path / "video.mp4"
    with video.open("wb") as f:
        f.write(b"\x00\x00\x00\x18ftypisom")
        for _ in range(SIZE >> 20):  # random data, so nothing compresses or dedupes
            f.write(os.urandom(1 << 20))
        f.truncate(SIZE)

    with httpx.Client(base_url=base, timeout=600) as c:
        csrf = re.search(r'name="csrf" value="([^"]+)"', c.get("/login").text).group(1)
        r = c.post("/login", data={"email": "video@test.test", "password": "video-password", "csrf": csrf})
        assert r.status_code == 303, r.text
        csrf = re.search(r'name="csrf" value="([^"]+)"', c.get("/tenant/documents").text).group(1)
        # Login alone peaks at ~64 MiB extra (argon2id's memory cost), so reset the peak
        # counter here to measure only the upload and download
        Path(f"/proc/{proc.pid}/clear_refs").write_text("5")
        baseline = mem_mib(proc.pid, "VmRSS")

        start = time.perf_counter()
        with video.open("rb") as f:
            r = c.post("/tenant/documents/video", data={"csrf": csrf},
                       files={"file": ("video.mp4", f, "video/mp4")})
        assert r.status_code == 303, r.text
        upload_s = time.perf_counter() - start
        after_upload = mem_mib(proc.pid, "VmHWM")

        downloads = {}
        for cipher in ("aes", "des", "rc4"):
            start = time.perf_counter()
            h = hashlib.sha256()
            with c.stream("GET", f"/tenant/documents/video?cipher={cipher}") as r:
                assert r.status_code == 200
                for chunk in r.iter_bytes():
                    h.update(chunk)
            downloads[cipher] = (h.hexdigest(), time.perf_counter() - start, mem_mib(proc.pid, "VmHWM"))

    expected = sha256_file(video)
    print(f"\nserver RSS after startup+login (peak reset): {baseline:.1f} MiB")
    print(f"peak RSS after {SIZE >> 20} MiB upload (x3 ciphers): {after_upload:.1f} MiB in {upload_s:.1f} s")
    for cipher, (digest, seconds, peak) in downloads.items():
        print(f"peak RSS after {SIZE >> 20} MiB verify+download ({cipher}): {peak:.1f} MiB in {seconds:.1f} s")
        assert digest == expected, cipher
    assert peak < BUDGET_MIB, f"server peaked at {peak:.1f} MiB"
