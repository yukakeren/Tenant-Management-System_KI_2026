# Testing and Demo

## Tests

| What | File | Who | What it checks |
|------|------|-----|----------------|
| Known answers | `test_aes_gcm.py`, `test_des_cbc.py`, `test_rc4.py` | Ata, Melvan, Ajil | We call each cipher correctly (GCM spec, textbook DES, RFC 6229 vectors) |
| Contract | `test_contract.py` | Naura | Every cipher round-trips at edge sizes and only ever fails with `IntegrityError` when data is changed |
| Container | `test_container.py` | Naura | Reading the header, the length limit, finding the last chunk, all three ciphers in one pass |
| Keys | `test_keys.py` | Naura | Wrapping and unwrapping, swapping `wrapped_dek` between users fails, admin always gets `PermissionError` |
| Vault | `test_vault.py` | Naura | 3 files per item, safe replacing, shredding removes the files and the key |
| Login | `test_auth.py` | Ata | Login, roles, CSRF on every POST, inactive users blocked, forced password change |
| Access | `test_access.py` | Melvan | Owner A can't use owner B's ids, admin can't open tenant or owner routes |
| Tenant flow | `test_tenant_flow.py` | Ajil | Upload checks, edge sizes over HTTP, re-uploading |

Run everything with `pytest -q`. The 200 MB tests are marked `@pytest.mark.slow` and skipped by default. Run those with `pytest -m slow` on day 5 and day 7.

## Tamper checklist

Every one of these should end in `IntegrityError`:

| | AES | DES | RC4 |
|---|---|---|---|
| Change 1 byte in the header | ☐ | ☐ | ☐ |
| Change 1 byte in the params | ☐ | ☐ | ☐ |
| Change 1 byte in the ciphertext | ☐ | ☐ | ☐ |
| Change 1 byte in the tag | ☐ | ☐ | ☐ |
| Change the DES IV | n/a | ☐ | n/a |
| Swap two chunks | ☐ | ☐ | ☐ |
| Remove the last record | ☐ | ☐ | ☐ |
| Cut the last record in half | ☐ | ☐ | ☐ |
| Add a copied record at the end | ☐ | ☐ | ☐ |
| Move the file to another tenant | ☐ | ☐ | ☐ |
| Swap KTP and agreement | ☐ | ☐ | ☐ |
| Wrong key | ☐ | ☐ | ☐ |

Tick these off on day 7 from the test results and copy the table into the report.

## Demo (about 8 minutes)

1. **Log in as a tenant** (from the seed). Fill in the profile, upload a KTP photo and a room video of about 150 MB. Mention that the upload takes a few seconds because it's being encrypted three times.
2. **Show the files on disk:** `ls -la storage/blobs/<id>/` shows three files per item. `xxd | head` shows random-looking bytes and our `KSK1` header, with no JPEG header anywhere.
3. **Log in as the owner.** Open the tenant and show the profile can be read. Download the KTP with AES, DES and RC4, and show that `sha256sum` matches the original for all three.
4. **Log in as a different owner.** The tenant isn't in the list, and pasting the first owner's URL gives 404.
5. **Log in as admin.** The user list only shows email, role and room. There are no document pages. Show in the code that `unwrap_dek` refuses admin.
6. **Tamper:** run `python scripts/tamper.py --kind ktp --cipher rc4 --mode flip`, then download with RC4 and get 409. AES still works, since only the RC4 copy was damaged. The admin audit log shows the failure.
7. **Bit-flipping slide:** run the RC4 bit-flipping test from `test_rc4.py` to show why the MAC is needed.
8. **Deletion:** the tenant asks for deletion, the owner approves, the tenant's folder is gone, and `wrapped_dek` is NULL in SQLite.
9. **Benchmark table** from `bench.csv`.

## Report checklist

- [ ] Architecture and key diagram (Naura)
- [ ] AES-GCM section (Ata)
- [ ] DES-CBC + HMAC section (Melvan)
- [ ] RC4 section (Ajil)
- [ ] Chunked mode and the tamper checklist (Naura)
- [ ] Access control and the access test results (Melvan)
- [ ] UU PDP: data classification, the roles (controller, subject, operator), deletion through crypto-shredding (Ajil and Ata)
- [ ] Benchmark and memory results (Naura)
- [ ] Limitations and what we'd do with more time (everyone)
