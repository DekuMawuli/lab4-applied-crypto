import base64
import os

from crypto_client.elgamal import encrypt_uint32, decrypt_uint32, encode_b64_string, decode_b64_lines

# A synthetic keypair for tests only -- NOT this project's real course keypair
# (which lives in the gitignored keypair.txt and must never appear in source).
_TEST_PRIV = 12345
P, ALPHA = 4294967291, 1000005
_TEST_PUB = pow(ALPHA, _TEST_PRIV, P)


def test_encrypt_decrypt_uint32_round_trip():
    m = 0x41424344
    sigma, y2 = encrypt_uint32(m, _TEST_PUB, P, ALPHA)
    assert decrypt_uint32(sigma, y2, _TEST_PRIV, P) == m


def test_encode_b64_string_produces_11_lines_of_12_chars():
    aes_key_b64 = "A" * 43 + "="  # 44-char placeholder, well-formed base64 shape
    lines = encode_b64_string(aes_key_b64, _TEST_PUB, P, ALPHA)
    assert len(lines) == 11
    assert all(len(line) == 12 for line in lines)


def test_encode_decode_b64_string_round_trip():
    original = base64.b64encode(os.urandom(32)).decode("ascii")
    lines = encode_b64_string(original, _TEST_PUB, P, ALPHA)
    recovered = decode_b64_lines(lines, _TEST_PRIV, P)
    assert recovered == original
