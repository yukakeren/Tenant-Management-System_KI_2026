"""KosanKu encryption benchmark (direct container; no web server required).
Run: python scripts/bench.py --quick; python scripts/bench.py --memory
"""
# Allow direct execution from the repository root (python scripts/...).
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import argparse
import csv
import io
import statistics
import time
import tracemalloc
from pathlib import Path

import app.crypto  # registers cipher suites
from app.crypto.base import REGISTRY
from app.crypto.container import encrypt_stream, decrypt_stream

SIZES = [1024, 1 << 20, 10 << 20, 100 << 20, 200 << 20]


class RepeatedBytes(io.RawIOBase):
    def __init__(self, length):
        self.remaining = length
        self.block = b"A" * (1 << 20)

    def readable(self):
        return True

    def read(self, n=-1):
        if self.remaining == 0:
            return b""
        n = min(self.remaining, (1 << 20) if n < 0 else n)
        self.remaining -= n
        return self.block[:n]


def run(size, cipher):
    dek, context = b"B" * 32, b"kosanku|1|1|video"
    suite = REGISTRY[cipher]
    output = io.BytesIO()
    start = time.perf_counter()
    stats = encrypt_stream([suite], dek, context, RepeatedBytes(size), [output])[0]
    enc_s = time.perf_counter() - start
    output.seek(0)
    start = time.perf_counter()
    restored = sum(map(len, decrypt_stream(dek, context, output)))
    dec_s = time.perf_counter() - start
    assert restored == size
    mb = size / (1 << 20)
    return {"size_bytes": size, "cipher": cipher,
            "enc_MB_s": round(mb / enc_s, 3), "dec_MB_s": round(mb / dec_s, 3),
            "overhead_bytes": stats.ct_size - size}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="only 1 KB and 1 MB")
    parser.add_argument("--memory", action="store_true", help="measure Python heap on a 200 MB stream")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--out", default="bench.csv")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be >= 1")
    if args.memory:
        # BytesIO holds the entire ciphertext: this is NOT a valid low-memory
        # test of the vault. Use a temporary on-disk file instead.
        import tempfile
        suite = next(iter(REGISTRY.values()))
        with tempfile.TemporaryFile() as output:
            tracemalloc.start()
            encrypt_stream([suite], b"B" * 32, b"kosanku|1|1|video",
                           RepeatedBytes(200 << 20), [output])
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        print(f"Python peak allocated memory: {peak / (1 << 20):.2f} MiB (not process RSS)")
        return
    sizes = SIZES[:2] if args.quick else SIZES
    rows = []
    for size in sizes:
        for cipher in REGISTRY:
            runs = [run(size, cipher) for _ in range(args.runs)]
            result = {"size_bytes": size, "cipher": cipher,
                      **{k: round(statistics.median(r[k] for r in runs), 3)
                         for k in ("enc_MB_s", "dec_MB_s", "overhead_bytes")}}
            rows.append(result)
            print(result)
    with Path(args.out).open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Saved: {args.out}")


if __name__ == "__main__":
    main()
