# KosanKu-Tenant-Management-System
**Scope**: Collecting, storing and returning onboarding data (profile, emergency contact, KTP scan, rental agreement, move-in video).

**Security**: Login, ownership-based access control, and encryption with AES, DES and RC4. Tenant deletion requests after move-out.

## Details

A web app where Kosan owners collect and store tenants information. It replaces the common practice of sending it via Whatsapp. However, it often faces problems such as expired message or mislocated tenant data resulting in lost information.

Tenant data that needs protection:
- PII: Full name, relative, emergency contact. 
- KTP: Contains personal identification data
- Video of current room condition used to claim deposit

One owner can manage many Kosan, but one tenant only occupy one Kosan room.

## Actors and Use Case

**Actors**:
1. Tenant: Data subject
2. Owner: Data controller
3. Admin: Manage account


<p align="center">
  <img src="assets/use-case-diagram.png" alt="Use Case Diagram" width="500">
</p>

## Crypthography Plan

Each stored item is encrypted under AES, DES and RC4, and every ciphertext carries an integrity check so tampered data is rejected rather than returned.

| Cipher | Mode          | Key                                                |
|--------|---------------|----------------------------------------------------|
| AES    | GCM           | 256-bit                                            |
| DES    | CBC           | 56-bit effective                                   |
| RC4    | Stream Cipher | Per-file key = HMAC-SHA256(user key, random nonce) |

- RC4 never reuses a key. RC4 has no IV, so the same key on two files would reuse the keystream and leak both plaintexts. A fresh per-file key prevents that.
- Keys are not stored next to the data. Each user gets random data keys, wrapped by a server master key kept outside the database.
- Passwords are hashed, not encrypted, with Argon2id.
- Large video is encrypted in chunks so a 200 MB file never sits fully in memory.
- "Intact" is verified twice: the tag or HMAC must pass, and a SHA-256 of the decrypted file must match the hash recorded at upload.

Benchmarking (throughput, memory, ciphertext overhead per file type) gets its own doc once the crypto module works.
