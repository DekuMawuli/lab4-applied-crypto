import base64
import json
import struct

import pytest

from crypto_client.net import get_key, decrypt, verify_hmac, ServerError


class ScriptedSocket:
    """Replays one canned reply and records the single request sent,
    for testing net.py's request-building/response-parsing in isolation
    from any real socket or server."""

    def __init__(self, reply_header: dict, reply_payload: bytes = b""):
        hb = json.dumps(reply_header, separators=(",", ":")).encode("utf-8")
        self._to_read = struct.pack(">I", len(hb)) + hb + reply_payload
        self.sent = b""
        self.closed = False

    def sendall(self, data: bytes):
        self.sent += data

    def recv(self, n):
        take = min(n, len(self._to_read))
        out, self._to_read = self._to_read[:take], self._to_read[take:]
        return out

    def close(self):
        self.closed = True


def _sent_header(sock: ScriptedSocket) -> dict:
    (hlen,) = struct.unpack(">I", sock.sent[:4])
    return json.loads(sock.sent[4:4 + hlen])


def test_get_key_returns_32_raw_key_bytes():
    key_b64 = base64.b64encode(bytes(range(32))).decode()
    sock = ScriptedSocket({"type": "key_result", "key": key_b64, "payload_len": 0})

    key = get_key(sock, "student01")

    assert key == bytes(range(32))
    assert _sent_header(sock) == {"type": "get_key", "username": "student01", "payload_len": 0}


def test_decrypt_sends_key_and_payload_returns_decrypted_bytes():
    sock = ScriptedSocket({"type": "decrypt_result", "payload_len": 5}, b"hello")

    result = decrypt(sock, "student01", key=bytes(range(32)), encrypted_bytes=b"ciphertext-bytes")

    sent = _sent_header(sock)
    assert sent["type"] == "decrypt"
    assert base64.b64decode(sent["key"]) == bytes(range(32))
    assert result == b"hello"


def test_verify_hmac_returns_result_string():
    sock = ScriptedSocket({"type": "verify_result", "result": "VERIFIED", "payload_len": 0})

    result = verify_hmac(sock, "student01", key=bytes(range(32)), mac=b"\x00" * 32, file_bytes=b"x")

    assert result == "VERIFIED"


def test_error_reply_raises_server_error_not_confused_with_failed_verify():
    sock = ScriptedSocket({"type": "error", "detail": "username not recognized", "payload_len": 0})

    with pytest.raises(ServerError, match="username not recognized"):
        get_key(sock, "nobody")
