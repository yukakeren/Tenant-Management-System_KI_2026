"""Intentionally corrupt a KSK1 blob for a controlled security demonstration.

Safe default: dry run. --yes writes and keeps a .bak for restoration.
Example: python scripts/tamper.py --tenant 3 --kind ktp --cipher rc4 --mode flip --yes
"""
# Allow direct execution from the repository root (python scripts/...).
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import argparse
import os
from pathlib import Path

from app.config import settings


def corrupt(data: bytes, mode: str) -> bytes:
    b = bytearray(data)
    if len(b) < 20:
        raise ValueError("file is too short")
    if mode == "flip":
        b[-1] ^= 1  # flip tag byte
    elif mode == "truncate":
        del b[-1:]
    elif mode == "append":
        b.extend(b"\x00\x00\x00\x01\x00")
    elif mode == "header":
        b[4] ^= 1
    else:
        raise ValueError("unsupported mode")
    return bytes(b)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tenant", type=int, required=True)
    p.add_argument("--item", type=int, required=True,
                   help="secret_items.id (not the tenant id)")
    p.add_argument("--kind", choices=["profile", "ktp", "agreement", "video"], required=True)
    p.add_argument("--cipher", choices=["aes", "des", "rc4"], required=True)
    p.add_argument("--mode", choices=["flip", "truncate", "append", "header"], required=True)
    p.add_argument("--yes", action="store_true", help="modify ciphertext on disk")
    p.add_argument("--restore", action="store_true", help="restore from backup")
    a = p.parse_args()
    if a.tenant <= 0 or a.item <= 0:
        p.error("tenant and item must be positive")
    path = settings.storage_dir.resolve() / str(a.tenant) / f"{a.item}.{a.cipher}.bin"
    backup = path.with_suffix(".bin.bak")
    if a.restore:
        if not backup.exists():
            p.error(f"backup missing: {backup}")
        os.replace(backup, path)
        print(f"Restored {path}")
        return
    if not path.is_file():
        p.error(f"file not found: {path}")
    if backup.exists():
        p.error(f"backup already exists: {backup} (restore it first)")
    if not a.yes:
        print(f"DRY RUN: would {a.mode} {path}. Add --yes to modify.")
        return
    original = path.read_bytes()
    backup.write_bytes(original)
    path.write_bytes(corrupt(original, a.mode))
    print(f"Tampered {path}; original backup: {backup}")
    print("Try downloading this cipher: expect HTTP 409 / IntegrityError")


if __name__ == "__main__":
    main()
