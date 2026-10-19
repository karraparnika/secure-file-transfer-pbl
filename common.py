"""Shared helpers: length-prefixed framing over a TCP socket."""
import struct

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError("Connection closed early")
        buf += chunk
    return buf

def send_msg(sock, data: bytes):
    sock.sendall(struct.pack(">Q", len(data)) + data)

def recv_msg(sock) -> bytes:
    (n,) = struct.unpack(">Q", recv_exact(sock, 8))
    return recv_exact(sock, n)
