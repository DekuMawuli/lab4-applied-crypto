import base64

from crypto_client.crypto_ops import encrypt_file, decrypt_local, custom_hmac, generate_aes_key_b64

KEY = bytes(range(32))  # 00 01 02 ... 1f, the spec's section 9 vector key
NONCE = bytes(range(12))  # 00 01 02 ... 0b, the spec's section 9 vector nonce

EXPECTED_ENCRYPTED_FILE_HEX = (
    "000102030405060708090a0b"  # the nonce itself, unchanged
    "2f67ba77aac5b574ff2df305301c56437e2377b98ef3961c271928"
)


def test_encrypt_file_matches_spec_section_9_vector_with_fixed_nonce():
    plaintext = b"hello world"

    encrypted = encrypt_file(KEY, plaintext, nonce=NONCE)

    assert encrypted == bytes.fromhex(EXPECTED_ENCRYPTED_FILE_HEX)
    assert len(encrypted) == len(plaintext) + 28  # 12-byte nonce + 16-byte tag


def test_encrypt_file_uses_a_fresh_random_nonce_by_default():
    a = encrypt_file(KEY, b"hello world")
    b = encrypt_file(KEY, b"hello world")

    assert a[:12] != b[:12], "nonce must not be reused across calls"


def test_decrypt_local_reverses_encrypt_file():
    plaintext = b"round trip me"

    encrypted = encrypt_file(KEY, plaintext)

    assert decrypt_local(KEY, encrypted) == plaintext


def test_custom_hmac_matches_spec_section_9_hello_world_vector():
    expected = base64.b64decode("WFxl5t64uHbtdCIsWWQGDnBxkt+M6bkbYZjeFz+//y4=")

    assert custom_hmac(KEY, b"hello world") == expected


def test_custom_hmac_matches_spec_section_9_empty_file_vector():
    expected = bytes.fromhex(
        "bb7a30c41398c718904264ee91bc9ea48a36493f9e5a5577f53a1408a6ffa5b3"
    )

    assert custom_hmac(KEY, b"") == expected


def test_custom_hmac_changes_when_file_contents_change():
    base = custom_hmac(KEY, b"hello world")
    changed = custom_hmac(KEY, b"Hello world")  # one byte flipped

    assert base != changed


def test_generate_aes_key_b64_is_well_formed():
    s = generate_aes_key_b64()
    assert len(s) == 44
    assert len(base64.b64decode(s)) == 32


def test_generate_aes_key_b64_is_random():
    assert generate_aes_key_b64() != generate_aes_key_b64()
