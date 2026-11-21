"""Message framing for crypto_message_spec_v2.md section 3."""
import json
import struct

HEADER_LEN_MAX = 1000


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed before n bytes received")
        buf += chunk
    return bytes(buf)


def send_message(sock, header: dict, payload: bytes = b""):
    header = dict(header, payload_len=len(payload))
    hb = json.dumps(header, separators=(",", ":")).encode("utf-8")
    if len(hb) > HEADER_LEN_MAX:
        raise ValueError(f"header is {len(hb)} bytes, exceeds the {HEADER_LEN_MAX}-byte limit")
    sock.sendall(struct.pack(">I", len(hb)) + hb + payload)


def recv_message(sock):
    (header_len,) = struct.unpack(">I", recv_exact(sock, 4))
    header = json.loads(recv_exact(sock, header_len))
    payload = recv_exact(sock, header.get("payload_len", 0))
    return header, payload
