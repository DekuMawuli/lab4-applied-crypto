"""Request/reply pairs for crypto_message_spec_v2.md section 4, built on
protocol.py's framing. One connection per request (section 2's recommended pattern)."""
import base64
import socket

from crypto_client.protocol import send_message, recv_message


class ServerError(Exception):
    """A well-formed {"type":"error"} reply. Distinct from a FAILED verify_result,
    which is a valid outcome, not an error (spec section 4.3)."""


def _check_reply(header: dict, expected_type: str) -> dict:
    if header.get("type") == "error":
        raise ServerError(header.get("detail", "unknown error"))
    if header.get("type") != expected_type:
        raise ServerError(f"expected {expected_type!r}, got {header.get('type')!r}")
    return header


def get_key(sock, username: str) -> bytes:
    send_message(sock, {"type": "get_key", "username": username})
    header, _ = recv_message(sock)
    header = _check_reply(header, "key_result")
    return base64.b64decode(header["key"])


def decrypt(sock, username: str, key: bytes, encrypted_bytes: bytes) -> bytes:
    send_message(
        sock,
        {"type": "decrypt", "username": username, "key": base64.b64encode(key).decode()},
        payload=encrypted_bytes,
    )
    header, payload = recv_message(sock)
    _check_reply(header, "decrypt_result")
    return payload


def verify_hmac(sock, username: str, key: bytes, mac: bytes, file_bytes: bytes) -> str:
    send_message(
        sock,
        {
            "type": "verify_hmac",
            "username": username,
            "key": base64.b64encode(key).decode(),
            "hmac": base64.b64encode(mac).decode(),
        },
        payload=file_bytes,
    )
    header, _ = recv_message(sock)
    header = _check_reply(header, "verify_result")
    return header["result"]


def connect(host: str, port: int, timeout: float = 30.0):
    return socket.create_connection((host, port), timeout=timeout)
