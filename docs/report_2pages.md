# KosanKu: Secure Tenant Management System
**Course:** Cryptography & Information Security (KI) | **Platform:** FastAPI, SQLite, PyCryptodome  
**Team:** Ata (AES-GCM), Melvan (DES-CBC), Ajil (RC4), Naura (Container & Vault)

---

### 1. Scenario & Practical Motivation
Managing a medium-to-large boarding house (kos) with 50+ rooms involves collecting sensitive personal identification data (KTP identity cards, NIK, family emergency contacts, stamped rental agreements) and large media assets (room walkthrough inspection videos). In standard boarding house operations, these documents are exchanged over WhatsApp or stored in unencrypted Google Drive folders. This manual practice suffers from severe vulnerabilities:
1. **Privacy & Regulatory Violations:** Under Indonesia’s Personal Data Protection Act (**UU No. 27/2022**), KTP facial images and room videos constitute specific/biometric data (Elucidation Art. 4(2)(b)). Unencrypted storage violates controller security mandates (**UU PDP Art. 35 & 38**).
2. **Operational Vulnerability:** When managing 50 tenants, manual file tracking causes lost records, unauthenticated document swaps, and unauthorized access by facility operators.
3. **Move-out Non-compliance:** Tenants who leave the facility have the legal right to data erasure (**UU PDP Art. 8 & Art. 39(1)(d)**), which is virtually impossible when files reside on owner phones and unmanaged chat backups.

**KosanKu** solves this by establishing a zero-trust tenant onboarding vault where all tenant data is automatically stored three times under distinct cryptographic suites (AES-256-GCM, DES-CBC+HMAC, RC4+HMAC), with chunk-level integrity and crypto-shredding upon move-out.

---

### 2. Analysis Performed & Justification
To rigorously evaluate the system under the 50-room boarding house operational profile, we evaluated three practical dimensions rather than synthetic micro-benchmarks:

1. **Throughput Across Practical File Distributions:** We evaluated container performance across 5 payload tiers: 1 KB (profile JSON), 1 MB & 10 MB (KTP scans and PDF contracts), and 100 MB & 200 MB (Full HD room condition videos). Measurements were taken using median values of 5 independent runs to eliminate OS caching artifacts.
2. **Tamper Resilience (Active Adversary Testing):** A tenant management system is susceptible to active forgery (e.g., modifying rent numbers or altering NIKs). We executed a 12-point active tampering checklist covering header corruption, IV bit-flipping, ciphertext modification, tag tampering, chunk reordering, truncation, splicing, and cross-tenant file injection.
3. **Memory Footprint under Multi-tenant Load:** We monitored peak resident set size (RSS) during concurrent 200 MB uploads and downloads to verify that 50 active tenants would not crash the host server via memory exhaustion.

**Why this analysis fits the scenario:** A boarding house server typically runs on low-cost hardware or a modest cloud instance. Demonstrating bounded memory (<85 MiB) and deterministic failure (HTTP 409 Conflict) upon tampering proves the platform remains stable and legally defensible during heavy move-in seasons.

---

### 3. Justification of Significant Design Decisions

#### A. Architecture & Role Isolation
- **Role Model:** The Tenant is the *Data Subject*, the Kos Owner is the *Data Controller*, and the Admin is the *Processor/Operator*.
- **Query-Level Scoping:** All lookups filter on `Kos.owner_id == me.id` at the SQL level. If an authorization check is omitted in code, the database query returns empty rather than leaking neighbor data.
- **Anti-Enumeration via HTTP 404:** Accessing another owner’s tenant or room yields HTTP 404 rather than 403, preventing attackers from mapping out facility occupancy.
- **Admin Document Blindness:** Admins handle account lifecycle and password resets but are cryptographically denied access to tenant documents (`PermissionError` in `unwrap_dek`). Changing passwords does not touch encryption keys, ensuring admin compromises do not compromise tenant identity vaults.

#### B. Cipher Modes & Authentication
- **AES-256-GCM (AEAD):** Selected for high-throughput default access. GCM combines counter mode encryption with Galois field authentication (GHASH) over a 96-bit nonce (unique 8-byte file salt + 4-byte chunk index). AAD covers file context, ensuring single-pass confidentiality and authenticity without padding oracle risks.
- **DES-CBC with Encrypt-then-MAC:** Standard DES has an obsolete 56-bit key space and a 64-bit block size vulnerable to Sweet32 birthday collisions after 32 GiB. We mitigate this by generating a fresh 16-byte salt per file and enforcing odd parity. To prevent Vaudenay padding oracle attacks and IV manipulation, we apply **Encrypt-then-MAC** (`HMAC-SHA256` over `ad || iv || ciphertext`). The tag is verified in constant time *before* decryption or unpadding occurs.
- **RC4 with 3072 Drop & HMAC-SHA256:** Raw RC4 is vulnerable to early keystream biases (Fluhrer-Mantin-Shamir) and bit-flipping. We eliminate keystream reuse by generating a per-file key via `HMAC-SHA256(DEK, nonce)`, discarding the first 3072 bytes of keystream via PyCryptodome's `drop=3072`, and binding each chunk with `HMAC-SHA256`.

#### C. Key Management & Crypto-Shredding (UU PDP Compliance)
- **Envelope Encryption:** A 256-bit `MASTER_KEY` stored in `.env` wraps individual tenant Data Encryption Keys (DEKs) using AES-256-GCM with associated data `aad = "dek|" + user_id`.
- **Crypto-Shredding:** Under **UU PDP Art. 8, 39, and 43**, deleting records from SSD storage or rolling database backups cannot guarantee physical bit erasure. When an owner approves a move-out deletion request, KosanKu executes crypto-shredding: the tenant’s `wrapped_dek` is set to `NULL` and file blobs are deleted. Without the DEK, all existing replicas and backup snapshots become permanently undecryptable.

#### D. Chunked Storage Container (`KSK1`) & Streaming
- Files are processed in 1 MiB chunks within a custom binary container (`KSK1`). Each chunk binds context metadata into its AAD:
  $$\text{AAD} = \text{header} + \text{"kosanku|" + subject\_id + "|" + item\_id + "|" + kind} + \text{chunk\_index} + \text{is\_last}$$
- This structure solves the STREAM authentication problem: truncating the file, swapping chunks 2 and 3, or copying tenant A’s KTP over tenant B’s file immediately causes `IntegrityError`.
- Downloads use a **verify-then-stream (two-pass)** approach: verifying all chunk tags before releasing plaintext bytes prevents partial data leaks to the browser.

---

### 4. Empirical Evaluation & Cipher Comparison

Container benchmarking on identical hardware yielded the following practical comparison:

| Payload Size | Metric | AES-256-GCM | DES-CBC + HMAC | RC4 (drop 3072) + HMAC |
| :--- | :--- | :--- | :--- | :--- |
| **1 KB** (Profile) | Speed (Enc / Dec)<br>Container Overhead | 7.6 / 9.7 MB/s<br>**40 B** | 6.3 / 7.2 MB/s<br>**80 B** | 11.3 / 14.7 MB/s<br>**64 B** |
| **10 MB** (Agreement) | Speed (Enc / Dec)<br>Container Overhead | 661.3 / 1,105.4 MB/s<br>**220 B** | 31.1 / 33.1 MB/s<br>**548 B** | 272.7 / 332.3 MB/s<br>**388 B** |
| **200 MB** (Room Video) | Speed (Enc / Dec)<br>Container Overhead | **830.8 / 1,073.3 MB/s**<br>**4,020 B** (0.002%) | **30.9 / 32.5 MB/s**<br>**10,428 B** (0.005%) | **299.5 / 326.0 MB/s**<br>**7,228 B** (0.003%) |

#### Interpretation of Results:
1. **Hardware Acceleration Dominates:** AES-GCM achieves >1 GB/s decryption because x86/ARM CPUs execute AES rounds and Galois polynomial multiplication in hardware (AES-NI and PCLMULQDQ). It is the only cipher capable of near-instantaneous video streaming.
2. **The Software Feistel Penalty of DES:** DES is ~28x slower than AES. Its 8-byte block size and 16 software Feistel permutations with bit-level transposition impose a heavy CPU burden. Encrypting a 200 MB walkthrough video with DES takes over 6.5 seconds, proving why DES is obsolete for high-throughput media.
3. **The Hidden Cost of Stream Cipher Integrity:** While raw RC4 byte generation is computationally trivial, ensuring integrity requires computing HMAC-SHA256 across every chunk, which bounds its throughput to ~300 MB/s.
4. **Memory Stability:** Peak resident memory remained strictly at **84.1 MiB** during the 200 MB streaming lifecycle, remaining well within the 100 MiB server budget.

### 5. Conclusion
For a multi-tenant boarding house, **AES-256-GCM** provides the optimal balance of confidentiality, hardware-accelerated throughput, and unified AEAD integrity. While legacy ciphers (DES-CBC and RC4) can be hardened using per-file keys, padding oracle defenses (Encrypt-then-MAC), and keystream truncation, the additional computational and container overhead demonstrates the overwhelming superiority of modern authenticated ciphers.
