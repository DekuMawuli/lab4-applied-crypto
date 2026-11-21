"""A local test double for the real crypto server: implements spec section 3
framing and canned replies on 127.0.0.1, so the client can be exercised without
the real network. Does NOT prove correctness of AES-GCM or the HMAC construction
(the section 9 vectors and the real server do that) — only that framing, the
decrypt round trip, and the HMAC-verify round trip agree with the client's own
implementation, and that a few error paths are reachable."""
import base64
import socketserver
import threading

from crypto_client.crypto_ops import custom_hmac, decrypt_local
from crypto_client.protocol import recv_message, send_message

BAD_USERNAME = "__bad__"
MAX_TEST_PAYLOAD = 64


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            header, payload = recv_message(self.request)
        except Exception:
            return

        username = header.get("username")
        if username == BAD_USERNAME:
            send_message(self.request, {"type": "error", "detail": "username not recognized"})
            return
        if header.get("payload_len", 0) > MAX_TEST_PAYLOAD:
            send_message(self.request, {"type": "error", "detail": "payload too large"})
            return

        msg_type = header.get("type")
        if msg_type == "get_key":
            import os
            key = os.urandom(32)
            send_message(self.request, {"type": "key_result", "key": base64.b64encode(key).decode()})
        elif msg_type == "decrypt":
            key = base64.b64decode(header["key"])
            try:
                plaintext = decrypt_local(key, payload)
            except Exception:
                send_message(self.request, {"type": "error", "detail": "decryption failed"})
                return
            send_message(self.request, {"type": "decrypt_result"}, payload=plaintext)
        elif msg_type == "verify_hmac":
            key = base64.b64decode(header["key"])
            mac = base64.b64decode(header["hmac"])
            result = "VERIFIED" if custom_hmac(key, payload) == mac else "FAILED"
            send_message(self.request, {"type": "verify_result", "result": result})
        elif msg_type == "get_certificate":
            certificates = getattr(self.server, "certificates", {})
            cert_bytes = certificates.get(header.get("cert_username"))
            if cert_bytes is None:
                send_message(self.request, {"type": "error", "detail": "no certificate for that user"})
            else:
                send_message(self.request, {"type": "certificate_result"}, payload=cert_bytes)
        else:
            send_message(self.request, {"type": "error", "detail": "unsupported type"})


class FakeServer:
    """Use as a context manager: `with FakeServer() as (host, port): ...`"""

    def __init__(self, certificates: dict[str, bytes] | None = None):
        self._certificates = certificates or {}

    def __enter__(self):
        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
        self._server.certificates = self._certificates
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self._server.server_address

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
