# Applied Cryptography Lab 4 — El Gamal and Certificates

A tkinter client implementing `crypto_message_spec_v3.md`'s certificate fetch/verify
and El Gamal key transport, on top of lab3's unchanged AES-256-GCM encrypt/decrypt
and custom HMAC compute/verify, against the instructor's server. The UI is a
two-tab notebook: Lab 3's workflow unchanged in one tab, the new certificate +
El Gamal workflow in the other.

Source repository: <https://github.com/DekuMawuli/lab4-applied-crypto>

## Workflow (lineage visible in git history)

1. `Requirements_v1.md` — student-authored, committed before any AI involvement.
2. `requirements_v2.md`, `design_v1.md` — AI-assisted refinement.
3. `crypto_client/` — source and tests.
4. `interrogation.md` — design/implementation Q&A.

## Where to find the results

- `crypto_client/tests/` — automated tests, including the spec's section 13.5
  certificate test vector (and its tamper/substitution/parameter-mismatch
  rejections), the chunked El Gamal encode/decode round trip, and an offline
  round trip against `fake_server.py`.
- Run them: `.venv/bin/python -m pytest crypto_client/ --ignore=crypto_client/tests/test_ui_common.py`
  (45 passing as of the last commit; `test_ui_common.py` passes separately, 1
  passing — see `results/ROUND_TRIP.md` for why it can't run in the same
  process here).
- `results/ROUND_TRIP.md` — evidence of all four round trips against the real
  server (`18.225.10.8:8080`, user `mdeku`): AES-GCM encrypt/decrypt matches
  the original file byte-for-byte, HMAC verify returns `VERIFIED` then
  `FAILED` after a one-byte tamper (both unchanged from lab3), and two real
  certificate fetch + verify + El Gamal key encryptions, for `mperkin2` and a
  classmate (`oobed`). Key material is never committed (`.key`/`.hmackey`/
  `keypair.txt`/`config.local.json`/the El Gamal-encrypted key exchange files
  are all gitignored).
