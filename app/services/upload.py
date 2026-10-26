"""
Upload validation service: file types, MIME checks, and size limits.
"""

import os
import re
from fastapi import UploadFile, HTTPException, status

MAX_SIZE_KTP = 5 * 1024 * 1024         # 5 MB
MAX_SIZE_AGREEMENT = 10 * 1024 * 1024  # 10 MB
MAX_SIZE_VIDEO = 50 * 1024 * 1024      # 50 MB

DOCUMENT_SPECS = {
    "ktp": {
        "max_size": MAX_SIZE_KTP,
        "allowed_exts": {".jpg", ".jpeg", ".png", ".pdf"},
        "allowed_mimes": {"image/jpeg", "image/png", "application/pdf"},
        "magic_signatures": [
            (b"\xff\xd8\xff", 0),                # JPEG
            (b"\x89PNG\r\n\x1a\n", 0),           # PNG
            (b"%PDF-", 0),                       # PDF
        ],
    },
    "agreement": {
        "max_size": MAX_SIZE_AGREEMENT,
        "allowed_exts": {".pdf"},
        "allowed_mimes": {"application/pdf"},
        "magic_signatures": [
            (b"%PDF-", 0),                        # PDF
        ],
    },
    "video": {
        "max_size": MAX_SIZE_VIDEO,
        "allowed_exts": {".mp4", ".webm", ".mov"},
        "allowed_mimes": {"video/mp4", "video/webm", "video/quicktime"},
        "magic_signatures": [
            (b"ftyp", 4),                         # MP4 / MOV (offset 4 byte)
            (b"\x1a\x45\xdf\xa3", 0),             # WebM / Matroska
        ],
    },
}


def sanitize_filename(filename: str) -> str:
    base_name = os.path.basename(filename)
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "_", base_name)
    if not cleaned or cleaned.startswith("."):
        cleaned = f"upload_{cleaned}"
    return cleaned


def validate_magic_bytes(header: bytes, doc_type: str) -> bool:
    signatures = DOCUMENT_SPECS[doc_type]["magic_signatures"]
    for sig, offset in signatures:
        if len(header) >= offset + len(sig):
            if header[offset : offset + len(sig)] == sig:
                return True
    return False


async def validate_and_read_upload(
    upload_file: UploadFile,
    doc_type: str,
) -> tuple[str, bytes]:
    if doc_type not in DOCUMENT_SPECS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tipe dokumen '{doc_type}' tidak dikenali. Pilih: ktp, agreement, atau video.",
        )

    spec = DOCUMENT_SPECS[doc_type]
    raw_filename = upload_file.filename or "unknown_file"
    cleaned_name = sanitize_filename(raw_filename)

    _, ext = os.path.splitext(cleaned_name.lower())
    if ext not in spec["allowed_exts"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Format ekstensi '{ext}' tidak diizinkan untuk {doc_type}. Izinkan: {', '.join(spec['allowed_exts'])}",
        )

    content = await upload_file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Berkas yang diunggah kosong.",
        )

    if len(content) > spec["max_size"]:
        max_mb = spec["max_size"] // (1024 * 1024)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Ukuran berkas melebihi batas maksimum ({max_mb} MB) untuk {doc_type}.",
        )

    header_sample = content[:32]
    if not validate_magic_bytes(header_sample, doc_type):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Konten berkas tidak valid untuk tipe {doc_type} (header file tidak sesuai).",
        )

    return cleaned_name, content