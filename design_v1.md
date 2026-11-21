# Design v1 – Crypto Client (Certificates + El Gamal), extending Lab 3

Implements `requirements_v2.md`. Python 3, tkinter, `cryptography` package for AES-GCM, SHA-256, and RSA-PSS verification.

## 1. Approach in one paragraph
Lab 3's split between pure modules (`protocol.py`, `crypto_ops.py`, `net.py`, `config.py`, `companions.py`) and a thin tkinter shell (`ui.py`) carries over unchanged. Two new pure modules join them: `ca_info.py` (loads `p`/`alpha`/CA public key once) and `cert.py` (parses and RSA-PSS-verifies a certificate against spec section 13), plus `elgamal.py` (the chunked encode/decode described in `requirements_v2.md`). `net.py` gains one function, `get_certificate`. The UI becomes a `ttk.Notebook` with two frames; the thread/queue/status plumbing lab3 wrote once inline is lifted into a small `ui_common.WorkerPanel` base class so both tabs reuse it instead of duplicating it.

## 2. Module layout
```
crypto_client/
  main.py            # entry point
  ui.py               # ttk.Notebook; Lab3Tab + Lab4Tab frames; only module importing tkinter
  ui_common.py        # WorkerPanel: thread/queue/status plumbing shared by both tabs
  config.py           # unchanged from lab3
  protocol.py          # unchanged from lab3
  companions.py         # unchanged from lab3
  crypto_ops.py          # lab3's AES-GCM/custom HMAC + new generate_aes_key_b64()
  net.py                # lab3's get_key/decrypt/verify_hmac + new get_certificate()
  ca_info.py             # loads p, alpha, CA public key from Pre_installed_CA_information.txt
  cert.py                 # Certificate dataclass + verify_certificate() (spec section 13)
  elgamal.py               # encrypt_uint32/decrypt_uint32 + encode_b64_string/decode_b64_lines
  fake_server.py            # lab3's fake server + get_certificate support
  tests/
    test_protocol.py, test_crypto_ops.py, test_net.py, test_fake_server.py   # lab3's, extended
    test_ca_info.py            # loads the real Pre_installed_CA_information.txt correctly
    test_cert.py                 # spec section 13.5 vector + tamper/username/param-mismatch cases
    test_elgamal.py                # round trip with this project's own keypair
    test_ui_common.py                # WorkerPanel queue/thread plumbing
config.example.json
Pre_installed_CA_information.txt
requirements.txt    # cryptography
```

## 3. `ca_info.py`
```python
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization

@dataclass(frozen=True)
class CaInfo:
    p: int
    alpha: int
    public_key: object   # an RSAPublicKey

def load_ca_info(path) -> CaInfo:
    text = Path(path).read_text()
    p = int(_line_value(text, "p ="))
    alpha = int(_line_value(text, "alpha ="))
    pem = _extract_pem_block(text)
    return CaInfo(p=p, alpha=alpha, public_key=serialization.load_pem_public_key(pem))
```
Loaded once at startup; `cert.py` and `elgamal.py` calls both take the resulting `CaInfo`'s fields rather than re-reading the file.

## 4. `cert.py` (spec section 13)
```python
import base64
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class CertificateError(Exception):
    pass

@dataclass(frozen=True)
class Certificate:
    p: int
    alpha: int
    username: str
    public_key: int

def verify_certificate(cert_bytes: bytes, expected_username: str, ca_info: CaInfo) -> Certificate:
    lines = cert_bytes.decode("ascii").split("\r\n")
    if len(lines) != 7 or lines[4] != "-" * 40:
        raise CertificateError("malformed certificate")
    signed = ("\r\n".join(lines[:5]) + "\r\n").encode("ascii")
    signature = base64.b64decode(lines[5], validate=True)
    try:
        ca_info.public_key.verify(
            signature, signed,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except InvalidSignature:
        raise CertificateError("signature does not verify")
    p = int(lines[0].split("=")[1])
    alpha = int(lines[1].split("=")[1])
    username = lines[2].split("=")[1].strip()
    pub = int(lines[3].split("=")[1])
    if username != expected_username:
        raise CertificateError("certificate username does not match requested user")
    if p != ca_info.p or alpha != ca_info.alpha:
        raise CertificateError("certificate p/alpha do not match this course's parameters")
    if not (1 <= pub <= ca_info.p - 1):
        raise CertificateError("public key out of range")
    return Certificate(p=p, alpha=alpha, username=username, public_key=pub)
```
Order matches `requirements_v2.md` item 13: format, then signature, then username, then p/alpha, then range — each its own `CertificateError`, each its own test case against the spec section 13.5 vector and a tampered copy of it.

## 5. `elgamal.py`
```python
import secrets, base64

def encrypt_uint32(x: int, beta: int, p: int, alpha: int) -> tuple[int, int]:
    b = secrets.randbelow(p - 2) + 1          # 1 <= b <= p-2
    sigma = pow(alpha, b, p)
    delta = pow(beta, b, p)
    y2 = (delta * x) % p
    return sigma, y2

def decrypt_uint32(sigma: int, y2: int, a: int, p: int) -> int:
    delta = pow(sigma, a, p)
    return (pow(delta, p - 2, p) * y2) % p     # Fermat inverse, p prime

def encode_b64_string(b64_text: str, beta: int, p: int, alpha: int) -> list[str]:
    assert len(b64_text) == 44
    lines = []
    for i in range(0, 44, 4):
        group = b64_text[i:i + 4].encode("ascii")
        x = int.from_bytes(group, "big")
        sigma, y2 = encrypt_uint32(x, beta, p, alpha)
        packed = sigma.to_bytes(4, "big") + y2.to_bytes(4, "big")
        lines.append(base64.b64encode(packed).decode("ascii"))
    return lines

def decode_b64_lines(lines: list[str], a: int, p: int) -> str:
    out = bytearray()
    for line in lines:
        raw = base64.b64decode(line)
        sigma, y2 = int.from_bytes(raw[:4], "big"), int.from_bytes(raw[4:], "big")
        x = decrypt_uint32(sigma, y2, a, p)
        out += x.to_bytes(4, "big")
    return out.decode("ascii")
```
`encode_b64_string` is the only one of these four wired to the UI (requirement 9 — this client never decrypts an incoming file); `decrypt_uint32`/`decode_b64_lines` exist purely so `test_elgamal.py` can prove a round trip before any certificate ever reaches the real server.

## 6. `net.py` addition
```python
def get_certificate(sock, username: str, cert_username: str) -> bytes | None:
    send_message(sock, {"type": "get_certificate", "username": username, "cert_username": cert_username})
    header, payload = recv_message(sock)
    if header.get("type") == "error" and header.get("detail") == "no certificate for that user":
        return None
    header = _check_reply(header, "certificate_result")
    return payload
```
Mirrors `verify_hmac`'s pattern: a well-formed-but-negative outcome (no such certificate) is a normal return value, not a raised `ServerError`; any other error still raises.

## 7. `crypto_ops.py` addition
```python
def generate_aes_key_b64() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")
```

## 8. `ui_common.WorkerPanel`
Lifted directly from lab3's `ui.py` (its `_queue`/`_run_in_background`/`_worker`/`_poll_queue`/`_set_status`/`_STATUS_COLORS`), generalized to a `(kind, text)` 2-tuple result (lab3 also threaded a `key_status` label through; here each tab manages any extra labels itself) and to find its root via `self.winfo_toplevel()` instead of assuming `self.root`.

## 9. UI layout
```
+----------------------------------------------------------------+
| Server IP  [____________]        Port [8080]                   |
| Username   [____________]                                      |
+----------------------------------------------------------------+
| [ Lab 3 ] [ Lab 4 ]                            <- ttk.Notebook  |
+----------------------------------------------------------------+
| Lab 3 tab:                                                      |
|   [Get Key]  <status: "No key fetched yet.">                    |
|   Base file [___________________________] [Browse...]           |
|   [Encrypt] [Decrypt] [Compute HMAC] [Verify HMAC]                |
|   [=========== progress ===========]                              |
|   Ready.                                                           |
+----------------------------------------------------------------+
| Lab 4 tab:                                                       |
|   Recipient Andrew ID [____________]  [Get Certificate]           |
|   <status: "Verified: mperkin2, pubkey=1034503561">               |
|   [Generate AES Key]  <status: "Key written -> aes_key.b64.txt">    |
|   [Encrypt Key for Recipient]                                       |
|   [=========== progress ===========]                                |
|   Ready.                                                              |
+----------------------------------------------------------------+
```
Both tabs' `root.after(50, ...)` polling loops are scheduled from `CryptoClientApp.__init__` by calling each tab's `_poll_queue` once per tick, since the two tabs' queues are independent of each other regardless of whether polling is scheduled from one loop or two.

## 10. Testing (tests/, pytest)
- `test_ca_info.py`: loading the real `Pre_installed_CA_information.txt` yields `p=4294967291`, `alpha=1000005`, a 2048-bit RSA public key.
- `test_cert.py`: the spec section 13.5 test certificate verifies; a 1-byte tamper in lines 1–4 or the divider fails; a request for a different username than the certificate's own fails even though the signature is valid; a `p`/`alpha` mismatch against `ca_info` fails.
- `test_elgamal.py`: `encrypt_uint32`/`decrypt_uint32` round trip for a known value; `encode_b64_string` produces exactly 11 lines of 12 characters each; a full `encode_b64_string` → `decode_b64_lines` round trip with this project's own keypair reproduces a random 44-character base64 string exactly.
- `test_net.py`: `get_certificate` returns bytes on `certificate_result`, returns `None` (not an exception) on `"no certificate for that user"`, and raises `ServerError` on any other error — exercised against an extended `fake_server.py`.
- `test_ui_common.py`: `WorkerPanel._run_in_background` moves a `(kind, text)` result from a worker thread to `status` via the queue.
- Lab 3 tab is checked manually to confirm no regression: Get Key, Encrypt, Decrypt, Compute HMAC, Verify HMAC all still behave as in lab3.
- Lab 4 tab is checked manually against the real server: Get Certificate for a classmate's Andrew ID, Generate AES Key, Encrypt Key for Recipient; the output file is visually confirmed to have 11 CRLF-terminated 12-character lines.

## 11. Build order (per spec section 11 / crypto_message_spec_v3.md)
1. Port lab3's unchanged modules + their tests; confirm the baseline still passes with no networking.
2. `ca_info.py`, tested against the real `Pre_installed_CA_information.txt`. No networking yet.
3. `cert.py`, tested against the spec section 13.5 vector and its tampered variants. No networking yet.
4. `net.get_certificate` + `fake_server.py` support, tested offline.
5. `crypto_ops.generate_aes_key_b64`.
6. `elgamal.py`, tested as a local round trip with this project's own keypair. No networking yet.
7. `ui_common.WorkerPanel`, extracted from lab3's `ui.py` pattern.
8. `ui.py` + `main.py`: the Lab 3 tab first (prove no regression), then the Lab 4 tab.
9. Manual round trip against the real server: fetch and verify a classmate's real certificate, generate a key, encrypt it for them.

## 12. Risks and decisions
- **Why El Gamal encodes the base64 *text* and not the raw 32 key bytes:** the Lab 4 handout is explicit that the 44-character base64 string is what gets chunked (11 groups of 4 ASCII characters), not the underlying 32 bytes — doing it the other way would produce a different, incompatible, 8-group encoding that the recipient's client (expecting 11 lines) couldn't parse.
- **Why a fresh `b` per group, never reused:** reusing the same ephemeral `b` across two groups would let anyone who recovers one group's plaintext (e.g. by breaking one weak key) also recover every other group encrypted with that same `b`, since `sigma` would repeat and the shared secret `delta` would be identical across groups — it would also leak the XOR/ratio relationship between any two groups' `y2` values even without recovering `delta` at all.
- **Why certificate checks run in a fixed order, format → signature → username → params → range, and stop at the first failure:** checking the signature before anything else is meaningless if the format is already malformed (there may be no line 6 to even extract); checking username/p/alpha after the signature matters because a validly-signed certificate for the *wrong* person or the *wrong* course parameters must still be rejected — the CA's signature alone does not imply "this is the certificate I asked for."
- **Why `decode_b64_lines`/`decrypt_uint32` exist but aren't wired to any button:** they cost nothing to write once `encrypt_uint32` exists (it's the same math, run in reverse) and they are the only way to write an automated test that proves the encode side is correct without a second human and a second real keypair — `test_elgamal.py`'s round trip is what catches a sign error or an off-by-one in the chunking before it ever reaches a classmate's real certificate.
- **Risk — ephemeral key reuse across runs:** mitigated by drawing `b` fresh via `secrets.randbelow` inside `encrypt_uint32` itself (not passed in), so every call — even for the same recipient and the same AES key — produces different ciphertext, following the same "fresh randomness per encryption" principle as lab3's GCM nonce.
- **Risk — trusting an unverified certificate:** mitigated by `cert.verify_certificate` being the *only* path by which a `Certificate`/public key object is produced at all in this codebase; there is no second code path in `ui.py` that reads `user public key =` directly off unverified bytes.
