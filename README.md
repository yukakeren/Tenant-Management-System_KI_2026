# KosanKu-Tenant-Management-System

## Details

A web app where Kosan owners collect and store tenants information. It replaces the common practice of sending it via Whatsapp. However, it often faces problems such as expired message or mislocated tenant data resulting in lost information.

**Scope**: ollecting, storing and returning onboarding data; login; ownership-based access control; encryption with AES, DES and RC4; deletion requests after move-out. Out of scope: rent payment, room booking, chat, digital signing, face recognition.

**Security**: Login, ownership-based access control, and encryption with AES, DES and RC4. Tenant deletion requests after move-out.

One owner can manage many Kosan, but one tenant only occupy one Kosan room.

## Actors and Use Case

|Actor|	Role under UU PDP	| Can do|
|-----------|-----------------|-----------------------------|
|Tenant	|Data subject	| Fill profile and emergency contact, upload KTP / rental agreement / room video, view and download own documents, request deletion|
|Owner|	Data controller|	Manage kos and rooms, assign tenants, view documents of own tenants only|
|Admin|	Operator	|Manage accounts; has no way to decrypt documents|


<p align="center">
  <img src="assets/use-case-diagram.png" alt="Use Case Diagram" width="500">
</p>

## Data Classification

UU PDP (UU No. 27/2022) Art. 4 splits personal data into specific (health, biometric, genetic, criminal records, child data, personal financial data) and general (name, sex, nationality, religion, marital status, and data combined to identify a person). The elucidation of Art. 4(2)(b) names a facial image as biometric data.

Each stored item is encrypted under AES, DES and RC4, and every ciphertext carries an integrity check so tampered data is rejected rather than returned.

| Cipher | Mode          | Key                                                |
|--------|---------------|----------------------------------------------------|
| AES    | GCM           | 256-bit                                            |
| DES    | CBC           | 56-bit effective                                   |
| RC4    | Stream Cipher | Per-file key = HMAC-SHA256(user key, random nonce) |

- Large video is encrypted in chunks so a 200 MB file never sits fully in memory.

## Development

Requires Python 3.12. Implementation plan: [docs/implementation](docs/implementation/README.md).

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./scripts/setup_tailwind.sh                       # downloads Tailwind CLI into bin/

cp .env.example .env                              # then fill SECRET_KEY and MASTER_KEY:
python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"

bin/tailwindcss -i app/static/input.css -o app/static/app.css --watch   # terminal 1
uvicorn app.main:app --reload                                            # terminal 2
pytest -q                                                                # tests
```
