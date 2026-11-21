import pytest

from crypto_client.crypto_ops import encrypt_file, custom_hmac
from crypto_client.fake_server import FakeServer, BAD_USERNAME, MAX_TEST_PAYLOAD
from crypto_client.net import connect, get_key, decrypt, verify_hmac, ServerError


def test_get_key_then_decrypt_round_trip_returns_original_bytes():
    plaintext = b"round trip through the fake server"
    with FakeServer() as (host, port):
        with connect(host, port) as sock:
            key = get_key(sock, "student01")
        encrypted = encrypt_file(key, plaintext)
        with connect(host, port) as sock:
            result = decrypt(sock, "student01", key, encrypted)

    assert result == plaintext


def test_get_key_then_verify_hmac_round_trip_verifies_then_fails_on_tamper():
    file_bytes = b"a file to authenticate"
    with FakeServer() as (host, port):
        with connect(host, port) as sock:
            key = get_key(sock, "student01")
        mac = custom_hmac(key, file_bytes)

        with connect(host, port) as sock:
            result = verify_hmac(sock, "student01", key, mac, file_bytes)
        assert result == "VERIFIED"

        tampered = file_bytes[:-1] + bytes([file_bytes[-1] ^ 0x01])
        with connect(host, port) as sock:
            result = verify_hmac(sock, "student01", key, mac, tampered)
        assert result == "FAILED"


def test_bad_username_raises_server_error_not_a_failed_result():
    with FakeServer() as (host, port):
        with connect(host, port) as sock:
            with pytest.raises(ServerError):
                get_key(sock, BAD_USERNAME)


def test_oversized_payload_raises_server_error():
    with FakeServer() as (host, port):
        with connect(host, port) as sock:
            with pytest.raises(ServerError):
                decrypt(sock, "student01", key=bytes(32), encrypted_bytes=b"x" * (MAX_TEST_PAYLOAD + 1))
