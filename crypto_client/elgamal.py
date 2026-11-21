"""Chunked El Gamal encryption of a base64-encoded AES key (Lab 4 handout +
Requirements_v1.md item 7): the 44-character base64 string is split into 11
groups of 4 ASCII characters, each group read as one big-endian 32-bit
unsigned integer and El Gamal-encrypted independently with a fresh ephemeral
value per group."""
import base64
import secrets

GROUP_LEN = 4
B64_KEY_LEN = 44


def encrypt_uint32(m: int, recipient_public_key: int, p: int, alpha: int) -> tuple[int, int]:
    b = secrets.randbelow(p - 2) + 1  # 1 <= b <= p-2
    sigma = pow(alpha, b, p)
    delta = pow(recipient_public_key, b, p)
    y2 = (delta * m) % p
    return sigma, y2


def decrypt_uint32(sigma: int, y2: int, private_key: int, p: int) -> int:
    delta = pow(sigma, private_key, p)
    return (pow(delta, p - 2, p) * y2) % p  # Fermat inverse, p prime


def encode_b64_string(b64_text: str, recipient_public_key: int, p: int, alpha: int) -> list[str]:
    assert len(b64_text) == B64_KEY_LEN
    lines = []
    for i in range(0, B64_KEY_LEN, GROUP_LEN):
        group = b64_text[i:i + GROUP_LEN].encode("ascii")
        m = int.from_bytes(group, "big")
        sigma, y2 = encrypt_uint32(m, recipient_public_key, p, alpha)
        packed = sigma.to_bytes(4, "big") + y2.to_bytes(4, "big")
        lines.append(base64.b64encode(packed).decode("ascii"))
    return lines


def decode_b64_lines(lines: list[str], private_key: int, p: int) -> str:
    out = bytearray()
    for line in lines:
        raw = base64.b64decode(line)
        sigma, y2 = int.from_bytes(raw[:4], "big"), int.from_bytes(raw[4:], "big")
        m = decrypt_uint32(sigma, y2, private_key, p)
        out += m.to_bytes(4, "big")
    return out.decode("ascii")
