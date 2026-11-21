# Lab 4 — Interrogation

Questions asked after reviewing the implementation (`crypto_client/ca_info.py`,
`cert.py`, `elgamal.py`, `net.py`, `ui.py`), and the answers given, demonstrating
understanding of the design and implementation. See `Requirements_v1.md`,
`requirements_v2.md`, and `design_v1.md` for the full requirements/design record.

---

## Q: The spec's certificate check (section 13.3) lists five steps in a specific order: format, signature, username, p/alpha, range. Why does that order matter, rather than checking them in whatever order is convenient?

Each earlier check protects the ones after it from acting on garbage. Format
has to come first because the signature check needs `lines[:5]` to exist and
`lines[5]` to be valid base64 at all — there's nothing to verify a signature
*of* if the certificate isn't even six CRLF-terminated lines. The signature
has to come before username/p/alpha/range because those four fields are
*read from the same bytes the signature covers* — if the signature hasn't
verified yet, an attacker could hand over a certificate with a forged
`username = mperkin2` line and a forged high-range public key, and the code
would have no reason to distrust any of it. Only once RSA-PSS confirms the
CA actually signed exactly this text does it become safe to trust what the
fields say. `cert.py`'s `verify_certificate` function enforces this by
raising immediately inside each `if`/`try` block rather than collecting all
failures and reporting them together — the first failing step is fatal, and
nothing after it runs. `test_valid_certificate_verifies` only passes once
every step in order succeeds; `test_tampered_byte_in_body_fails` is the test
that would catch a regression where the signature check got skipped or
moved after the field checks.

## Q: Why does `verify_certificate` check that the certificate's *own* `username` field matches the Andrew ID that was requested, given that the signature has already proven the CA really signed this certificate?

Because the signature only proves the CA vouches for *this exact text* — it
says nothing about whether this text is the certificate the caller actually
asked for. Imagine the crypto server (or a man-in-the-middle on this
teaching server, which the spec explicitly warns sends everything
unencrypted) substitutes a different, equally validly-signed certificate —
say, the attacker's own — in place of the one requested for `mperkin2`. The
signature on the attacker's certificate verifies just fine, because the CA
really did sign it for *them*. Without the username comparison, the client
would happily accept the attacker's public key under the belief that it
belongs to `mperkin2`, and then El Gamal-encrypt the AES key for the
attacker instead of the real recipient. `_check_fields` checks
`username != expected_username` before even looking at `p`/`alpha`/range,
and `test_wrong_requested_username_rejected` is the test that would fail if
this check were ever removed — it uses the real, validly-signed test
certificate for `mperkin2` and asks `verify_certificate` to accept it for
`"someoneelse"`, which must still fail.

## Q: `encrypt_uint32` in `elgamal.py` picks a brand-new random `b` every single time it's called — once per 4-byte group, so 11 times per AES key. Why not reuse one `b` for the whole key? It would be faster.

Reusing `b` would mean every group shares the exact same `sigma = alpha^b mod p`
and the exact same shared secret `delta = beta^b mod p`. That turns the
scheme into basically a stream cipher with a *single* keystream value
(`delta`) applied to all 11 groups via multiplication mod p, which breaks in
two ways. First, it's directly visible: `sigma` would be identical on every
line of the output file, which immediately tells an eavesdropper "these 11
groups all used the same ephemeral key" even before touching the math.
Second, and worse, knowing *any one* group's plaintext (say, the attacker
guesses the first group is likely `"XXXX"` some standard base64 lead-in, or
a different compromised message reused the same `b`) would let them recover
`delta` for that group, and because `delta` is identical across all 11
groups, that one recovered value decrypts every other group in the file
instantly — the whole 256-bit AES key falls, not just one 32-bit chunk of
it. `encrypt_uint32` draws `b = secrets.randbelow(p - 2) + 1` fresh on every
call using the cryptographic RNG, specifically so that compromising one
group's secret can't cascade into the rest — the same "never reuse a nonce"
principle as lab3's GCM encryption, applied to El Gamal's ephemeral exponent
instead of an AES-GCM nonce.

## Q: Why does El Gamal-encrypt the *44 ASCII characters of the base64 text* of the AES key, instead of encrypting the 32 raw key bytes directly, which would only need 8 groups instead of 11?

Because that's what the Lab 4 handout specifies, and getting it wrong would
make this client's output file unreadable by anyone else's correctly-built
client (and vice versa) even though the math would still "work" in
isolation — the two clients would just disagree about how many groups there
are and what each group's bytes mean. There's also a subtler reason tied to
El Gamal's own constraint: the message being encrypted has to be an integer
strictly less than `p` (4294967291, just under 2^32). A raw 32-byte AES key
split into 8 groups of 4 *raw* bytes could, in principle, produce a 4-byte
group whose big-endian integer value is close to 2^32 — safely still less
than `p` in this case since `p` is close to 2^32 too, but the base64 *text*
encoding sidesteps the question entirely, since every base64 character is
one of 64 printable ASCII values (so every 4-character group's big-endian
integer is well below `p` by construction, bounded by `0x7A7A7A7A` at most
for the valid base64 alphabet) — comfortably under `p` with room to spare.
`test_encode_b64_string_produces_11_lines_of_12_chars` pins down the "11
lines" half of this; the `assert len(b64_text) == B64_KEY_LEN` guard in
`encode_b64_string` is what would catch a caller trying to pass the 32 raw
bytes (or anything not already base64-encoded to exactly 44 characters) by
mistake.

## Q: The fix after the independent review cleared `self._verified_cert` at the very start of `_on_get_certificate`, before the network call even happens, rather than only updating it once a new certificate successfully verifies. Why does the *order* of that matter?

Because the bug wasn't "the UI shows an old certificate" — it was "the UI
*uses* an old certificate's public key to encrypt a file for someone it was
never actually verified for." Before the fix, `self._verified_cert` was
only ever assigned on a *successful* verification inside `work()`, and
otherwise simply left alone. That meant: verify Alice successfully, then
type Bob's Andrew ID and click Get Certificate — if the fetch for Bob fails
(no certificate, rejected signature, wrong p/alpha, anything), `work()`
returns an error status, but `self._verified_cert` still silently holds
Alice's certificate from before. Nothing in the UI prevented clicking
"Encrypt Key for Recipient" right after that failure, which would happily
use Alice's public key while writing the output to a file named after Bob
(worse still, the original code named that file from the *live text field*,
`self.cert_username.get()`, not from the certificate that was actually
verified — so the filename itself lied about whose key was used). Clearing
`self._verified_cert = None` synchronously, on the main thread, the instant
a *new* fetch begins — before the background thread even starts — closes
this window completely: there is no point in time after a new fetch begins
where a stale certificate for a different person is still considered
trusted. `test_get_certificate_clears_stale_verified_cert_before_fetching`
checks exactly this: it preloads a stale "verified" certificate for Alice,
triggers a fetch for Bob that is made to fail, and asserts
`_verified_cert is None` — proving the clear happened regardless of whether
the fetch succeeds, not just as a side effect of a successful one.

## Q: Why is `net.get_certificate` returning `None` for `"no certificate for that user"` instead of raising an exception, when every other failure case raises `ServerError`?

Because the spec is explicit that this is a different *kind* of outcome,
not a program error — it's the server correctly answering "this well-formed
request has no certificate to give you," which is a normal, expected
possibility (not every Andrew ID has registered a key with the CA yet).
This is the same distinction lab3 already drew for `verify_hmac`'s `FAILED`
result: a `FAILED` HMAC check is a valid, informative answer, not a crash,
and conflating it with a malformed-request `error` would hide from the
student whether their HMAC math is wrong or their request itself was
broken. Here, if `get_certificate` raised `ServerError` for *both*
"malformed request" and "no certificate for that user," the Lab 4 tab's
`_on_get_certificate` would have no way to show the user the specific,
actionable message the spec requires ("no certificate for that user")
instead of a generic "error: error processing request." `test_get_certificate_returns_none_when_absent`
and `test_get_certificate_raises_on_other_error` are the two tests that pin
this distinction down — one proves the specific case returns normally as
`None`, the other proves every *other* error still raises, so a future
change that accidentally swallowed real errors into silent `None` returns
would be caught immediately.
