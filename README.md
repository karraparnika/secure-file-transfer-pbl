# Secure File Transfer using Cryptography and Socket Programming

PBL project, Department of CSE (Cyber Security), Geethanjali College of Engineering and Technology (Autonomous).

A client sends a file to a server over a TCP socket. An eavesdropper on the network sees only ciphertext, and any tampering is detected.

## How it works
1. Client connects over TCP; the server sends its **RSA-2048** public key.
2. Client generates a random **AES-256** session key and sends it encrypted with RSA-OAEP.
3. Client computes the **SHA-256** hash of the file and encrypts it with **AES-256-GCM** (fresh nonce per file).
4. Server decrypts the session key and the file, verifies the GCM tag and recomputes the SHA-256 hash.
5. Hash matches: file is saved in `received/`. Mismatch: file is rejected.

| Goal | Technique |
|---|---|
| Confidentiality | AES-256-GCM |
| Secure key exchange | RSA-2048 (OAEP) |
| Integrity | SHA-256 + GCM authentication tag |
| Multiple clients | Python `threading` |

## Setup
```bash
pip install -r requirements.txt
```

## Run
```bash
# Terminal 1
python server.py --port 5000

# Terminal 2
python client.py path/to/file.pdf --host 127.0.0.1 --port 5000

# Tamper test (should be rejected)
python client.py path/to/file.pdf --tamper
```

## Structure
```
server.py   receiver          client.py   sender
common.py   socket framing    received/   saved files
docs/       presentation source and your screenshots
```

## Demo evidence
Add screenshots to `docs/`: terminal run, Wireshark capture of unreadable ciphertext, and the rejected tampered file.

## Team
Add names and roll numbers here.
