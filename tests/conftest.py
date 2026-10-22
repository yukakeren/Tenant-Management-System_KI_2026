import base64
import os

# Test-only keys. Set before anything imports app.config.
os.environ.setdefault("SECRET_KEY", base64.b64encode(b"s" * 32).decode())
os.environ.setdefault("MASTER_KEY", base64.b64encode(b"m" * 32).decode())
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("STORAGE_DIR", "./storage/test-blobs")
os.environ.setdefault("DEBUG", "true")
