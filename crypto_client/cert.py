"""Certificate parsing and RSA-PSS verification (crypto_message_spec_v3.md section 13)."""
import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from crypto_client.ca_info import CaInfo

DIVIDER = "-" * 40


class CertificateError(Exception):
    """Any failure in parsing or verifying a certificate (spec section 13.3)."""


@dataclass(frozen=True)
class Certificate:
    p: int
    alpha: int
    username: str
    public_key: int


def _check_fields(p: int, alpha: int, username: str, public_key: int, expected_username: str, ca_info: CaInfo) -> None:
    """Spec 13.3 steps 3-5, split out so each can be unit-tested directly:
    a p/alpha mismatch and an out-of-range public key can't otherwise both be
    exercised in the same certificate, since a mismatched p/alpha already
    fails before the range check (which is bounded by ca_info.p) is reached."""
    if username != expected_username:
        raise CertificateError("certificate username does not match requested user")
    if p != ca_info.p or alpha != ca_info.alpha:
        raise CertificateError("certificate p/alpha do not match this course's parameters")
    if not (1 <= public_key <= ca_info.p - 1):
        raise CertificateError("public key out of range")


def verify_certificate(cert_bytes: bytes, expected_username: str, ca_info: CaInfo) -> Certificate:
    try:
        text = cert_bytes.decode("ascii")
    except UnicodeDecodeError as e:
        raise CertificateError("certificate is not ASCII") from e

    lines = text.split("\r\n")
    if len(lines) != 7 or lines[6] != "" or lines[4] != DIVIDER:
        raise CertificateError("malformed certificate")

    signed = ("\r\n".join(lines[:5]) + "\r\n").encode("ascii")
    try:
        signature = base64.b64decode(lines[5], validate=True)
    except Exception as e:
        raise CertificateError("signature is not valid base64") from e

    try:
        ca_info.public_key.verify(
            signature,
            signed,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except InvalidSignature as e:
        raise CertificateError("signature does not verify") from e

    try:
        p = int(lines[0].split("=", 1)[1])
        alpha = int(lines[1].split("=", 1)[1])
        username = lines[2].split("=", 1)[1].strip()
        public_key = int(lines[3].split("=", 1)[1])
    except (IndexError, ValueError) as e:
        raise CertificateError("malformed certificate fields") from e

    _check_fields(p, alpha, username, public_key, expected_username, ca_info)

    return Certificate(p=p, alpha=alpha, username=username, public_key=public_key)
