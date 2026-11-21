# Requirements v2

## Overview
The project extends the lab3 TCP client to implement `crypto_message_spec_v3.md`'s new pieces for Applied Cryptography Lab 4 ("El Gamal and Certificates"): fetching and verifying a classmate's certificate from the course cloud server, then El Gamal-encrypting a freshly generated AES-256 key's base64 text for that verified recipient, 4 bytes (32 bits) at a time. The lab3 AES-GCM/HMAC functionality is kept exactly as it was; the UI gains a second tab rather than replacing the first. Certificate verification and El Gamal encryption both happen locally in the client — the server only stores and hands out certificate files, it does not check them.

## Project Requirements

### General
1. The code shall be written in Python 3, reusing lab3's `crypto_client` package (`protocol.py`, `net.py`, `crypto_ops.py`, `config.py`, `companions.py`, `fake_server.py`) unchanged, extending only `net.py` and `crypto_ops.py` where the new spec requires it.
2. Two new pure modules shall hold the lab4-specific logic, neither importing tkinter, so both are testable headless: `cert.py` (certificate parsing/verification) and `elgamal.py` (chunked encode/decode).
3. A small `ca_info.py` module shall load `p`, `alpha`, and the CA's public RSA key once from `Pre_installed_CA_information.txt`, so every other module receives these as already-parsed values rather than re-parsing the file itself.

### UI
4. The user interface shall use tkinter with a `ttk.Notebook` holding two tabs: "Lab 3" (the existing Get Key / Encrypt / Decrypt / Compute HMAC / Verify HMAC workflow, unmodified in behavior) and "Lab 4" (certificate + El Gamal workflow).
5. Server IP, port, and username fields shall sit above the notebook and be shared by both tabs, loaded from `config.local.json` the same way lab3 did.
6. The Lab 4 tab shall have: an Andrew ID entry for the recipient, a "Get Certificate" button, a "Generate AES Key" button, and an "Encrypt Key for Recipient" button. "Encrypt Key for Recipient" shall be inert (or show an inline error) until both a verified certificate and a generated key exist for the current recipient.
7. Each tab shall show its own progress indicator and status line, since the two tabs' actions are independent and a student may run one while the other is idle (resolves open question 3 from Requirements v1 in favor of separate status areas, since lab3's own status-line requirement was "distinguish outcomes clearly," which is easier per-tab than shared).
8. Getting a certificate and generating/encrypting the AES key remain two separate actions/buttons rather than one combined step (resolves open question 2), so a failure at the certificate stage is visibly distinct from a failure at the encryption stage, consistent with lab3's requirement that different outcomes must look different.
9. The client only ever encrypts an AES key *for* someone else; it does not decrypt an incoming El Gamal file using the local private key (resolves open question 1 — the handout's requirement list only asks for the sending side). The corresponding decrypt function is still implemented and tested (requirement 22 below) for local round-trip verification, just not exposed as a UI action.

### Certificates (spec section 13)
10. `get_certificate` is sent with the entered Andrew ID as `cert_username`; the reply's `"no certificate for that user"` error is caught and shown as its own status message, not as a program error — the same FAILED-vs-error distinction lab3 made for `verify_hmac`.
11. A certificate is parsed as exactly 6 ASCII lines, each ending CRLF, with line 5 exactly 40 hyphens; a certificate that doesn't match this shape is rejected before any signature check is attempted.
12. The signed data is lines 1–5 joined by CRLF (including the trailing CRLF after line 5); line 6 is the base64 RSA-PSS signature (SHA-256, MGF1-SHA256, salt length 32) verified against the CA's public key from `ca_info.py`.
13. After the signature verifies, the certificate's `username` line must equal the requested `cert_username`, its `p`/`alpha` lines must equal `ca_info`'s values, and its public key must be an integer in `1..p-1` — in that order, each a separate rejection reason. Only when every check passes is the public key trusted and stored for use.

### El Gamal key transport (spec + Lab 4 PDF)
14. A new 256-bit AES key is generated locally per lab4 PDF requirement 3 (`os.urandom(32)`, base64-encoded to 44 characters) and written to a file; it is never fetched from the server.
15. The 44-character base64 string's ASCII bytes are split into 11 groups of 4 bytes each; each group is read as one big-endian 32-bit unsigned integer `x`.
16. Each group is El Gamal-encrypted independently with a fresh random `b` per group (`1 <= b <= p-2`): `sigma = alpha^b mod p`, `delta = beta^b mod p` (`beta` = the verified recipient's public key), `y2 = delta * x mod p`.
17. Each group's `(sigma, y2)` pair is packed as two 4-byte big-endian unsigned integers (8 bytes total), base64-encoded to a 12-character line, and written CRLF-terminated; the output file has exactly 11 such lines and nothing else.
18. A matching `decrypt` function (`delta = sigma^a mod p`, `x = delta^-1 * y2 mod p` via `pow(delta, p-2, p)`) is implemented for testing: encoding a key with a test keypair's public half and decoding it with that keypair's private half must reproduce the original 44-character string exactly (requirement 22 below).

### Verification before using the real server
19. The certificate verifier is checked against `crypto_message_spec_v3.md` section 13.5's test certificate (must verify) and against copies with a single byte changed in lines 1–4 or the divider (must fail), before any `get_certificate` call is made against the real server.
20. The El Gamal encode/decode round trip is checked locally — encode then decode with a matching keypair reproduces the original base64 string — before it is wired into the "Encrypt Key for Recipient" button.

### Security hygiene
21. `keypair.txt` (the private El Gamal key) and `config.local.json` (server IP/username) are both gitignored and never printed, logged, or sent to the server — the same rule lab3 applied to its AES/HMAC keys.
22. The Lab 3 tab's behavior must remain unchanged by this work — no regression in Get Key / Encrypt / Decrypt / Compute HMAC / Verify HMAC.

## Open decisions (defaults assumed, please check)
- **Per-tab status, not shared:** each tab gets its own `WorkerPanel`-style progress bar and status line (item 7); a shared single status row was considered but rejected since the two tabs can be mid-action independently.
- **No UI decrypt path:** `elgamal.decode_b64_lines` exists and is tested, but there is no "Decrypt" button in the Lab 4 tab, since the handout only specifies the sending side (item 9). If the lecturer's updated instructions later ask for the receiving side too, this is a small additive change (one more button calling the already-tested decode function).
- **Certificate caching:** a verified certificate is held in memory for the current recipient only (not cached to disk), so switching the Andrew ID field and clicking "Get Certificate" again always re-fetches and re-verifies rather than trusting a stale result.
