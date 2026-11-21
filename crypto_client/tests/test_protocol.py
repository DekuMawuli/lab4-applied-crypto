import json
import struct

from crypto_client.protocol import recv_exact, send_message, recv_message


class FakeSocket:
    """Minimal socket stand-in that returns data in small, uneven chunks,
    so recv_exact is forced to loop rather than get lucky with one recv()."""

    def __init__(self, data: bytes, chunk: int = 3):
        self._data = data
        self._chunk = chunk
        self._sent = bytearray()

    def recv(self, n):
        take = min(n, self._chunk, len(self._data))
        out, self._data = self._data[:take], self._data[take:]
        return out

    def sendall(self, data: bytes):
        self._sent += data


def test_get_key_request_matches_spec_section_9_vector():
    sock = FakeSocket(b"")
    send_message(sock, {"type": "get_key", "username": "student01"})

    header_len = struct.unpack(">I", sock._sent[:4])[0]
    header = json.loads(sock._sent[4:4 + header_len])

    assert header_len == 57
    assert header == {"type": "get_key", "username": "student01", "payload_len": 0}
    assert len(sock._sent) == 4 + header_len  # no payload bytes appended


def test_recv_exact_loops_until_n_bytes_received():
    sock = FakeSocket(b"0123456789", chunk=3)
    assert recv_exact(sock, 10) == b"0123456789"


def test_recv_message_reads_header_and_payload():
    header = {"type": "key_result", "key": "abc", "payload_len": 5}
    hb = json.dumps(header).encode("utf-8")
    wire = struct.pack(">I", len(hb)) + hb + b"hello"
    sock = FakeSocket(wire, chunk=4)

    got_header, got_payload = recv_message(sock)

    assert got_header == header
    assert got_payload == b"hello"
