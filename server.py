"""Secure file receiver: RSA-2048 key exchange, AES-256-GCM decryption, SHA-256 check."""
import argparse, hashlib, json, os, socket, threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from common import recv_msg, send_msg

OUT_DIR = "received"

def handle(conn, addr, key):
    print(f"[Server] Client connected: {addr}")
    try:
        send_msg(conn, key.publickey().export_key())               # 1. public key
        enc_session_key = recv_msg(conn)                           # 2. AES key (RSA encrypted)
        aes_key = PKCS1_OAEP.new(key).decrypt(enc_session_key)
        print("[Server] Session key received (RSA decrypted)")
        header = json.loads(recv_msg(conn))                        # 3. metadata
        ciphertext = recv_msg(conn)                                # 4. encrypted file
        name = os.path.basename(header["filename"])                # block path traversal
        print(f"[Server] Receiving {name} ... done")
        try:
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=bytes.fromhex(header["nonce"]))
            data = cipher.decrypt_and_verify(ciphertext, bytes.fromhex(header["tag"]))
        except ValueError:
            print("[Server] REJECTED: authentication tag failed (file tampered)")
            send_msg(conn, b"FAIL")
            return
        if hashlib.sha256(data).hexdigest() != header["sha256"]:
            print("[Server] REJECTED: SHA-256 mismatch")
            send_msg(conn, b"FAIL")
            return
        print("[Server] SHA-256 verified: MATCH")
        os.makedirs(OUT_DIR, exist_ok=True)
        with open(os.path.join(OUT_DIR, name), "wb") as f:
            f.write(data)
        print("[Server] File saved securely")
        send_msg(conn, b"OK")
    except Exception as e:
        print(f"[Server] Error: {e}")
    finally:
        conn.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5000)
    a = p.parse_args()
    key = RSA.generate(2048)
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((a.host, a.port))
        s.listen()
        print(f"[Server] Listening on port {a.port}...")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle, args=(conn, addr, key), daemon=True).start()

if __name__ == "__main__":
    main()
