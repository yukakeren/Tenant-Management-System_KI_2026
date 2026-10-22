import base64
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

CIPHERS = ("aes", "des", "rc4")


def _key_from_env(name: str) -> bytes:
    raw = os.getenv(name, "")
    if not raw:
        raise RuntimeError(f"{name} is missing. Copy .env.example to .env and generate the keys.")
    try:
        key = base64.b64decode(raw, validate=True)
    except ValueError:
        raise RuntimeError(f"{name} is not valid base64") from None
    if len(key) != 32:
        raise RuntimeError(f"{name} must decode to exactly 32 bytes, got {len(key)}")
    return key


@dataclass(frozen=True)
class Settings:
    secret_key: bytes
    master_key: bytes
    database_url: str
    storage_dir: Path
    read_cipher: str
    debug: bool


def load_settings() -> Settings:
    read_cipher = os.getenv("READ_CIPHER", "aes")
    if read_cipher not in CIPHERS:
        raise RuntimeError(f"READ_CIPHER must be one of {CIPHERS}")
    return Settings(
        secret_key=_key_from_env("SECRET_KEY"),
        master_key=_key_from_env("MASTER_KEY"),
        database_url=os.getenv("DATABASE_URL", "sqlite:///./kosanku.db"),
        storage_dir=Path(os.getenv("STORAGE_DIR", "./storage/blobs")),
        read_cipher=read_cipher,
        debug=os.getenv("DEBUG", "false").lower() == "true",
    )


settings = load_settings()
