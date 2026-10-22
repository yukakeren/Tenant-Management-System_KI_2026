# Person 4: Chunked Streaming Mode, Keys, Vault

**Cipher:** the chunked container. It's the "mode" that all three ciphers run inside: framing, chunk indexing, final-chunk binding, AAD, one-pass fan-out to three ciphers. Also key derivation and key wrapping.
**App:** the vault (the one module routes call for anything encrypted), streaming upload/download plumbing, crypto-shredding, benchmark and tamper scripts. You're also the integration/merge person.
**Branches:** `feat/crypto-core`, `feat/vault`, `feat/tooling`

## Files you own

```
app/crypto/{base.py, kdf.py, container.py, keys.py, vault.py}
scripts/bench.py, scripts/tamper.py
tests/crypto/{test_contract.py, test_container.py, test_keys.py, test_vault.py}
```

## Day 1: interface freeze (most important day for you)

1. `base.py` exactly as in [crypto-spec.md §2](crypto-spec.md#2-interface-appcryptobasepy).
2. `kdf.py`: `hkdf_sha256`, `hmac_sha256`.
3. A **dummy suite** for your own tests (`tests/crypto/_xor_suite.py`: XOR with a fixed byte + SHA-256 tag). This way you can build and test the container before the real ciphers exist.
4. `test_contract.py`, parametrized over `REGISTRY` so every new suite gets tested automatically once it registers:

```python
SIZES = [0, 1, 7, 8, 9, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 5]

@pytest.mark.parametrize("suite", REGISTRY.values(), ids=lambda s: s.name)
class TestContract:
    def test_roundtrip(self, suite, size): ...
    def test_flip_every_region(self, suite): ...   # header byte, params byte, first ct byte, last tag byte
    def test_swap_chunks(self, suite): ...
    def test_truncate_last_record(self, suite): ...
    def test_drop_last_record(self, suite): ...
    def test_append_record(self, suite): ...
    def test_wrong_context(self, suite): ...       # other subject_id
    def test_wrong_dek(self, suite): ...
    def test_fresh_params_each_file(self, suite): ...
    def test_only_integrity_error_escapes(self, suite): ...  # fuzz: 200 random byte flips
```

5. End of day 1: 30 minute meeting. Walk through the spec with everyone, everyone agrees, and then it's frozen.

## Day 2: `container.py`

Format and rules: [crypto-spec.md §3–4](crypto-spec.md#3-container-format-person-4-appcryptocontainerpy).

```python
def encrypt_stream(suites, dek, context, src, dsts):
    headers, sealers = [], []
    for s, dst in zip(suites, dsts):
        params = s.new_params()
        h = _header(s.id, CHUNK_SIZE, params)
        dst.write(h)
        headers.append(h)
        sealers.append(s.sealer(dek, params))

    index, cur = 0, src.read(CHUNK_SIZE)
    while True:
        nxt = src.read(CHUNK_SIZE)          # read-ahead: tells us if `cur` is the final chunk
        final = not nxt
        for h, sealer, dst in zip(headers, sealers, dsts):
            rec = sealer.seal(index, cur, _chunk_ad(h, context, index, final))
            dst.write(len(rec).to_bytes(4, "big") + rec)
        if final:
            break
        index, cur = index + 1, nxt
```

- `src.read(n)` can return fewer than `n` bytes before EOF on some streams. Write `_read_exact(src, n)` that loops until it has `n` or hits EOF. Otherwise "every non-final chunk is exactly chunk_size" breaks.
- Keep per-suite timing (`time.perf_counter` around `seal`) and return it as `EncStats(ct_size, enc_ms)`. This goes into `secret_blobs.enc_ms` and the report.
- `decrypt_stream` reads the header, looks up the suite by `cipher_id`, then reads records with one record of read-ahead to know `final`. Yields plaintext per chunk.
- Memory: at most 2 chunks of plaintext + 3 records alive at a time. Don't `b"".join` anything.

## Day 2 to 3: `keys.py`

```python
def load_master_key() -> bytes                  # from settings, must be 32 bytes, else crash at startup
def create_dek(user) -> None                    # 32 random bytes, wrap, store in user.wrapped_dek
def unwrap_dek(subject, actor) -> bytes         # access check FIRST, then unwrap
def destroy_dek(subject) -> None                # wrapped_dek = NULL
```

```python
def unwrap_dek(subject, actor):
    if actor.role == "admin" or not access.can_view_subject(actor, subject):
        raise PermissionError
    if subject.wrapped_dek is None:
        raise PermissionError                   # shredded or admin account
    blob = subject.wrapped_dek
    c = AES.new(load_master_key(), AES.MODE_GCM, nonce=blob[:12])
    c.update(b"dek|" + str(subject.id).encode())
    try:
        return c.decrypt_and_verify(blob[12:-16], blob[-16:])
    except ValueError:
        raise IntegrityError() from None
```

The `aad = user_id` means copying tenant A's `wrapped_dek` into tenant B's row in the DB doesn't give B's session access to A's key. Unwrap fails.

Until Person 2's `access.py` lands (day 4), stub `can_view_subject` as `actor.id == subject.id`.

## Day 3 to 5: `vault.py`

This is the only API that routes use. Routes never import `container` or a suite directly.

```python
CIPHERS = ("aes", "des", "rc4")

def store_item(subject, kind, src: BinaryIO, mime: str, actor) -> SecretItem
    # 1. dek = unwrap_dek(subject, actor)
    # 2. upsert secret_items row (need item.id for the context)
    # 3. open 3 tmp files in storage/blobs/<subject>/<item>.<cipher>.bin.tmp
    # 4. encrypt_stream([aes, des, rc4], dek, context, src, tmp_files)
    # 5. fsync, rename tmp → final (atomic), replace secret_blobs rows
    # 6. on any exception: delete tmp files, rollback, re-raise
def store_bytes(subject, kind, data: bytes, actor) -> SecretItem      # BytesIO wrapper, for profile

def verify_item(subject, kind, cipher, actor) -> SecretBlob             # pass 1
def open_item(subject, kind, cipher, actor) -> Iterator[bytes]          # pass 2 (generator, for StreamingResponse)
def load_bytes(subject, kind, actor, cipher=None) -> bytes | None       # small items: verify + decrypt in memory

def shred_user(subject, actor) -> None
    # delete all blob files (+ the directory), delete rows, destroy_dek. One transaction for the DB part.
```

- `cipher=None` means `settings.READ_CIPHER`.
- Also check that the `cipher_id` in the file header matches `secret_blobs.cipher`. If it doesn't, raise `IntegrityError`.
- Re-upload: write the new blobs fully first, then delete the old files. Never leave the tenant with zero copies if the upload fails halfway.
- Rule: plaintext never goes to disk from our code. The only exception is FastAPI's spooled upload temp file (noted in architecture.md).

## Day 5: streaming + memory test

- Wire up `StreamingResponse(vault.open_item(...), media_type=item.mime, headers={"Content-Disposition": 'attachment; filename="ktp.pdf"'})` with Person 2/3.
- Memory test: `scripts/bench.py --memory` generates a 200 MB random file, stores it through the vault, downloads it via the TestClient, and prints peak RSS (`resource.getrusage`). Target < 100 MB. Put the number in the report.

## Day 6: tooling

### `scripts/bench.py`
Uses the container directly, not HTTP. Sizes: 1 KB (profile-like), 1 MB, 10 MB, 100 MB, 200 MB. 5 runs each, median.

```
size     cipher  enc MB/s  dec MB/s  overhead
1 KB     aes     ...
1 KB     des     ...
...
```
Writes `bench.csv` too, so the report can make a chart.

### `scripts/tamper.py`
For the demo. `python scripts/tamper.py --tenant 3 --kind ktp --cipher rc4 --mode flip|swap|truncate|append|move-to-tenant-4`. It edits the blob on disk. Then download it in the browser → 409 page, and the admin audit log shows the `ok=False` row.

## Day 7: integration

- Run the full test suite on a clean clone (`rm -rf storage *.db && python scripts/seed.py && pytest`).
- Run the demo script in [testing.md](testing.md) end to end twice.
- Freeze `main` at 18:00, after that only fixes.

## Merge duty (all week)

- You review every PR that touches `app/crypto/`.
- Each evening: merge the green PRs, run `pytest`, post in the group what's merged and what's blocking.
- If someone is behind on their cipher by day 3 evening, pair with them on day 4 morning before integration.

## For the report

- Why chunking: memory, and why each chunk needs `index` + `final` in its AAD (without that, chunked AEAD is open to reorder/truncate attacks, which is the "STREAM" construction problem from Hoang–Reyhanitabar–Rogaway–Vizár 2015).
- Key hierarchy diagram and the crypto-shredding argument for UU PDP deletion.
- The honest limitations list: master key in `.env`, temp file during upload, a server compromise exposes everything.
- The benchmark table and the memory measurement.
