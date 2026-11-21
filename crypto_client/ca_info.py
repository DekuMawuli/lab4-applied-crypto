"""Loads p, alpha, and the CA's public RSA key from Pre_installed_CA_information.txt
(spec section 13: the CA key is not in the certificate, it's given separately)."""
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization


@dataclass(frozen=True)
class CaInfo:
    p: int
    alpha: int
    public_key: object


def _line_value(text: str, prefix: str) -> str:
    for line in text.splitlines():
        if line.strip().startswith(prefix):
            return line.split("=", 1)[1].strip()
    raise ValueError(f"no line starting with {prefix!r} found")


def _extract_pem_block(text: str) -> bytes:
    start = text.index("-----BEGIN PUBLIC KEY-----")
    end = text.index("-----END PUBLIC KEY-----") + len("-----END PUBLIC KEY-----")
    return text[start:end].encode("ascii")


def load_ca_info(path) -> CaInfo:
    text = Path(path).read_text()
    p = int(_line_value(text, "p ="))
    alpha = int(_line_value(text, "alpha ="))
    pem = _extract_pem_block(text)
    public_key = serialization.load_pem_public_key(pem)
    return CaInfo(p=p, alpha=alpha, public_key=public_key)
