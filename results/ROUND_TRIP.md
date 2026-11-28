# Round-trip evidence — real server (18.225.10.8:8080, user mdeku)

Run 2026-11-28. `sample.txt` is the evidence file; its companion files (`.enc`,
`.key`, `.hmac`, `.hmackey`) are generated locally and are gitignored, since
the keys must never be committed.

## Lab 3 regression (unchanged tab)

- `get_key` → 32-byte key.
- Local `encrypt_file` → `sample.txt.enc` (67 bytes = 39-byte plaintext + 28-byte overhead).
- Server `decrypt` reply, written to `sample.txt.dec`.
- **Result: `sample.txt.dec` is byte-for-byte identical to `sample.txt`.**
- `get_key` → 32-byte key, local `custom_hmac` → `sample.txt.hmac`.
- Server `verify_hmac` on the unmodified file → **`VERIFIED`**.
- Same key and HMAC, file with its last byte flipped (`sample_tampered_demo.txt`) → **`FAILED`**
  (not an `error` — confirms the two outcomes are distinguished correctly, per spec section 4.3).

Confirms the Lab 3 tab still works exactly as it did in the lab3 submission after
being wrapped into the new two-tab UI.

## Lab 4: certificate fetch + verify + El Gamal key transport

Two real round trips against the server, one per recipient, each:
`get_certificate` → `cert.verify_certificate` → `crypto_ops.generate_aes_key_b64`
→ `elgamal.encode_b64_string`.

| Recipient | Certificate verified | Public key | Output file | Format |
|---|---|---|---|---|
| `mperkin2` | Yes | `1034503561` (matches spec section 13.5's published test vector) | `mperkin2_mdeku_AES_enc_key.txt` | 11 lines, 154 bytes, CRLF-terminated |
| `oobed` | Yes | `3312833251` | `oobed_mdeku_AES_enc_key.txt` | 11 lines, 154 bytes, CRLF-terminated |

Both output files were uploaded to the shared `CryptoFall2026` Google Drive folder
following the `<recipient>_<sender>_<description>` naming convention, and the
plaintext AES key for each was sent out-of-band (email/message) to the
recipient for independent confirmation after they decrypt it with their own
private key. The encrypted files themselves are not committed to this
repository (gitignored, regenerated per run — same policy as lab3's `.enc`
files) since they're one-off artifacts for the Drive exchange, not source.

## Automated test suite

`.venv/bin/python -m pytest crypto_client/ --ignore=crypto_client/tests/test_ui_common.py`
→ **45 passed**, covering the spec's section 9 framing/AES-GCM/HMAC vectors,
certificate parsing/verification (including the section 13.5 test vector and
tamper/substitution/parameter-mismatch rejections), the chunked El Gamal
encode/decode round trip, and the tabbed UI. `test_ui_common.py` passes in
isolation (1 passed) but can't run in the same pytest process as `test_ui.py`
in this sandboxed environment — see the implementation ledger for why; it's a
tkinter/display limitation, not a code issue.
