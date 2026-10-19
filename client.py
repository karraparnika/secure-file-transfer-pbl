"""Secure file sender: hashes, encrypts with AES-256-GCM, protects the key with RSA-OAEP."""
import argparse, hashlib, json, os, socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from common import recv_msg, send_msg

def main():
    p = argparse.ArgumentParser()
    p.add_argument("file")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--tamper", action="store_true", help="flip a byte to demo rejection")
    a = p.parse_args()

    data = open(a.file, "rb").read()
    digest = hashlib.sha256(data).hexdigest()
    aes_key = get_random_bytes(32)                                  # AES-256 session key
    cipher = AES.new(aes_key, AES.MODE_GCM)                         # fresh nonce per file
    ciphertext, tag = cipher.encrypt_and_digest(data)
    if a.tamper:
        ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

    with socket.create_connection((a.host, a.port)) as s:
        server_pub = RSA.import_key(recv_msg(s))
        send_msg(s, PKCS1_OAEP.new(server_pub).encrypt(aes_key))
        send_msg(s, json.dumps({"filename": os.path.basename(a.file), "sha256": digest,
                                "nonce": cipher.nonce.hex(), "tag": tag.hex()}).encode())
        send_msg(s, ciphertext)
        print("[Client] Result:", "SUCCESS" if recv_msg(s) == b"OK" else "FILE REJECTED")

if __name__ == "__main__":
    main()
