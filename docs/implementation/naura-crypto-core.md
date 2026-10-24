# Naura: Chunked File Mode, Keys, Vault

**Cipher:** the chunked file format that all three ciphers run inside. That covers splitting files into chunks, numbering them, marking the last one, what gets authenticated, and feeding each chunk to all three ciphers in one pass. Also key derivation and wrapping user keys.
**App:** the vault (the only module routes use for anything encrypted), streaming uploads and downloads, crypto-shredding, the benchmark and tamper scripts. I'm also in charge of merging.
**Branches:** `feat/crypto-core`, `feat/vault`, `feat/tooling`

## My files

```
app/crypto/base.py, kdf.py, container.py, keys.py, vault.py
scripts/bench.py, scripts/tamper.py
tests/crypto/test_contract.py, _xor_suite.py, test_container.py, test_keys.py, test_vault.py
```

## Day 1: agree on the interface (done)

- [x] `base.py`, following [crypto-spec.md](crypto-spec.md#the-interface)
- [x] `kdf.py`: `hkdf_sha256`, `hmac_sha256`
- [x] `tests/crypto/_xor_suite.py`: a fake cipher (XOR + HMAC), so I can build the container before the real ciphers exist
- [x] `tests/crypto/test_contract.py`: runs on the fake cipher plus every registered cipher. Covers round trips at edge sizes, flipped bytes, wrong key/params/context, swapped chunks, the "last chunk" flag, short records, and checks that only `IntegrityError` ever comes out (200 random edits).
- [ ] End-of-day meeting: go through the spec together, everyone agrees, and then we stop changing it.

The contract tests work on single chunks for now. Tests that need the full file (cutting off the end, adding a record, editing the header) go in `test_container.py` on day 2.

## Day 2: `container.py`

Format and rules: [crypto-spec.md](crypto-spec.md#file-format).

```python
def encrypt_stream(suites, dek, context, src, dsts):
    headers, sealers = [], []
    for s, dst in zip(suites, dsts):
        params = s.new_params()
        h = _header(s.id, CHUNK_SIZE, params)
        dst.write(h)
        headers.append(h)
        sealers.append(s.sealer(dek, params))

    index, cur = 0, _read_exact(src, CHUNK_SIZE)
    while True:
        nxt = _read_exact(src, CHUNK_SIZE)  # read one ahead so we know if `cur` is the last chunk
        final = not nxt
        for h, sealer, dst in zip(headers, sealers, dsts):
            rec = sealer.seal(index, cur, _chunk_ad(h, context, index, final))
            dst.write(len(rec).to_bytes(4, "big") + rec)
        if final:
            break
        index, cur = index + 1, nxt
```

- `src.read(n)` can give back fewer than `n` bytes before the end on some streams. That's why there's `_read_exact`: keep reading until you have `n` bytes or hit the end. Without it, "every chunk except the last is full size" can break.
- Time each cipher (`time.perf_counter` around `seal`) and return `EncStats(ct_size, enc_ms)`. It goes into `secret_blobs.enc_ms` and the report.
- `decrypt_stream`: read the header, find the cipher by `cipher_id`, then read records one ahead so you know which is last. Yield the plaintext chunk by chunk.
- Memory: at most 2 plaintext chunks and 3 records at a time. Never `b"".join` the whole file.
- `test_container.py`: cutting off the last record, cutting a record in half, adding a copied record, editing the header, a huge length value, an empty file, and sizes around the chunk boundary.

## Days 2 to 3: `keys.py`

```python
def load_master_key() -> bytes            # from settings (config.py already checks it's 32 bytes)
def create_dek(user) -> None              # 32 random bytes, wrap it, save to user.wrapped_dek
def unwrap_dek(subject, actor) -> bytes   # check access FIRST, then unwrap
def destroy_dek(subject) -> None          # wrapped_dek = NULL
```

```python
def unwrap_dek(subject, actor):
    if actor.role == Role.admin or not access.can_view_subject(actor, subject):
        raise PermissionError
    if subject.wrapped_dek is None:
        raise PermissionError                   # already shredded, or an admin account
    blob = subject.wrapped_dek
    c = AES.new(load_master_key(), AES.MODE_GCM, nonce=blob[:12])
    c.update(b"dek|" + str(subject.id).encode())
    try:
        return c.decrypt_and_verify(blob[12:-16], blob[-16:])
    except ValueError:
        raise IntegrityError() from None
```

Because the user id is in the AAD, copying tenant A's `wrapped_dek` into tenant B's row doesn't work. It just fails to unwrap.

Until Melvan's `access.py` is ready (day 4), use a stub: `can_view_subject = lambda actor, subject: actor.id == subject.id`.

## Days 3 to 5: `vault.py`

This is the only thing routes call. Routes never import `container` or a cipher directly.

```python
CIPHERS = ("aes", "des", "rc4")

def store_item(subject, kind, src, mime, actor) -> SecretItem
    # 1. dek = unwrap_dek(subject, actor)
    # 2. create or update the secret_items row (we need item.id for the context)
    # 3. open 3 temp files: storage/blobs/<subject>/<item>.<cipher>.bin.tmp
    # 4. encrypt_stream([aes, des, rc4], dek, context, src, tmp_files)
    # 5. fsync, rename the temp files to their real names, replace the secret_blobs rows
    # 6. if anything fails: delete the temp files, roll back, re-raise
def store_bytes(subject, kind, data, actor) -> SecretItem             # wraps data in BytesIO, for the profile

def verify_item(subject, kind, cipher, actor) -> SecretBlob            # first pass
def open_item(subject, kind, cipher, actor) -> Iterator[bytes]         # second pass, for StreamingResponse
def load_bytes(subject, kind, actor, cipher=None) -> bytes | None      # small items: verify and decrypt in memory

def shred_user(subject, actor) -> None
    # delete all blob files and the folder, delete the rows, destroy_dek. The database part is one transaction.
```

- `cipher=None` means use `settings.read_cipher`.
- Check that the `cipher_id` in the file header matches `secret_blobs.cipher`. If it doesn't, raise `IntegrityError`.
- When re-uploading, write the new files completely before deleting the old ones. If an upload fails halfway, the tenant should still have their old copy.
- Our code never writes plaintext to disk. The only exception is FastAPI's temp file for uploads (it's in the architecture doc).

## Day 5: streaming and memory test

- Hook up `StreamingResponse(vault.open_item(...), media_type=item.mime, headers={"Content-Disposition": 'attachment; filename="ktp.pdf"'})` together with Melvan and Ajil.
- Memory test: `scripts/bench.py --memory` makes a random 200 MB file, stores it through the vault, downloads it with the TestClient, and prints the peak memory (`resource.getrusage`). It should stay under 100 MB. Put the number in the report.

## Day 6: scripts

### `scripts/bench.py`
Calls the container directly, no HTTP. Sizes: 1 KB (about a profile), 1 MB, 10 MB, 100 MB, 200 MB. Run each 5 times and take the median.

```
size     cipher  enc MB/s  dec MB/s  overhead
1 KB     aes     ...
1 KB     des     ...
...
```
Also save it to `bench.csv` so we can make a chart for the report.

### `scripts/tamper.py`
For the demo: `python scripts/tamper.py --tenant 3 --kind ktp --cipher rc4 --mode flip|swap|truncate|append|move-to-tenant-4`. It edits the file on disk. Downloading it in the browser should then give the 409 page, and the admin audit log should show a row with `ok=False`.

## Day 7: putting it together

- Run everything on a clean clone: `rm -rf storage *.db && python scripts/seed.py && pytest`.
- Go through the demo in [testing.md](testing.md) from start to finish, twice.
- Freeze `main` at 18:00. After that, only fixes.

## Merging (all week)

- I review every PR that touches `app/crypto/`.
- Every evening: merge the PRs that pass, run `pytest`, and post in the group what got merged and what's stuck.
- If someone's cipher still isn't working by the evening of day 3, I pair with them on the morning of day 4, before we start integrating.

## For the report

- Why we use chunks: memory. Also why each chunk needs its index and the "last chunk" flag in the AAD. Without them, chunked encryption can be reordered or cut short without anyone noticing (this is the problem the STREAM construction from Hoang, Reyhanitabar, Rogaway and Vizár, 2015, solves).
- A diagram of the keys, and why destroying the key counts as deleting the data under UU PDP.
- The list of known limitations: the master key in `.env`, the temp file during upload, and a hacked server exposing everything.
- The benchmark table and the memory number.
