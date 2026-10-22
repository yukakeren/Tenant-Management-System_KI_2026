# Testing and Demo

## Test layers

| Layer | File | Owner | What it proves |
|-------|------|-------|----------------|
| Known-answer | `test_aes_gcm.py`, `test_des_cbc.py`, `test_rc4.py` | P1, P2, P3 | We call the primitive correctly (NIST / textbook / RFC 6229 vectors) |
| Contract | `test_contract.py` | P4 | Every suite round-trips at all edge sizes and rejects every kind of tampering with `IntegrityError` only |
| Container | `test_container.py` | P4 | Header parsing, length guard, read-ahead/final logic, multi-suite single pass |
| Keys | `test_keys.py` | P4 | Wrap/unwrap, swapped `wrapped_dek` between users fails, admin always `PermissionError` |
| Vault | `test_vault.py` | P4 | 3 blobs per item, atomic replace, shred removes files + key |
| Auth | `test_auth.py` | P1 | Login, roles, CSRF required on every POST, inactive user blocked |
| Access | `test_access.py` | P2 | IDOR matrix: owner A vs owner B ids, admin vs tenant/owner routes |
| Tenant flow | `test_tenant_flow.py` | P3 | Upload validation, edge sizes through HTTP, re-upload |

Run: `pytest -q`. The 200 MB tests are marked `@pytest.mark.slow` and skipped by default. Run them with `pytest -m slow` on day 5 and day 7.

## Tamper matrix (must be all red → `IntegrityError`)

| | AES | DES | RC4 |
|---|---|---|---|
| Flip 1 byte in header | ☐ | ☐ | ☐ |
| Flip 1 byte in params | ☐ | ☐ | ☐ |
| Flip 1 byte in ciphertext | ☐ | ☐ | ☐ |
| Flip 1 byte in tag | ☐ | ☐ | ☐ |
| Flip DES IV | n/a | ☐ | n/a |
| Swap two chunks | ☐ | ☐ | ☐ |
| Drop last record | ☐ | ☐ | ☐ |
| Cut last record in half | ☐ | ☐ | ☐ |
| Append a copied record | ☐ | ☐ | ☐ |
| Blob moved to another tenant | ☐ | ☐ | ☐ |
| Blob moved to another kind (KTP ↔ agreement) | ☐ | ☐ | ☐ |
| Wrong DEK | ☐ | ☐ | ☐ |

Tick these on day 7 from the test output and paste the table into the report.

## Demo script (~8 minutes)

1. **Login as tenant** (seeded). Fill the profile, upload a KTP image and a ~150 MB room video. Point out that the upload takes a few seconds because it's encrypted three times.
2. **Show the disk:** `ls -la storage/blobs/<id>/` → three files per item, `xxd | head` → random bytes, `KSK1` magic visible, no JPEG header.
3. **Login as owner.** Open the tenant: profile is readable. Download the KTP via AES, DES, and RC4 → `sha256sum` of all three downloads match the original.
4. **Login as another owner** → the tenant isn't listed. Paste the first owner's URL → 404.
5. **Login as admin** → user list with email/role/room only. No document routes exist. Show `unwrap_dek` refusing admin in the code.
6. **Tamper:** `python scripts/tamper.py --kind ktp --cipher rc4 --mode flip` → download via RC4 → 409. Then AES still works (only the RC4 copy was damaged). Admin audit log shows the failure.
7. **Malleability slide:** run the RC4 malleability test from `test_rc4.py`, which shows why the MAC is needed.
8. **Deletion:** tenant requests deletion → owner approves → blob dir gone, `wrapped_dek` is NULL in SQLite.
9. **Benchmark table** from `bench.csv`.

## Report checklist

- [ ] Architecture + key hierarchy diagram (P4)
- [ ] AES-GCM section (P1)
- [ ] DES-CBC + HMAC section (P2)
- [ ] RC4 section (P3)
- [ ] Chunked mode + tamper matrix (P4)
- [ ] Access control + IDOR results (P2)
- [ ] UU PDP mapping: data classification, controller/subject/operator roles, deletion = crypto-shredding (P3 + P1)
- [ ] Benchmark + memory results (P4)
- [ ] Limitations and what we'd do with more time (everyone)
