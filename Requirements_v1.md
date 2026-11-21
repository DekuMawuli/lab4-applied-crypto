# Lab 4 — Requirements v1

## Overview

This project is a TCP client for Applied Cryptography Lab 4. We are adding certificate verification and El Gamal encryption to the work already done in Lab 3. The program will request another user's certificate from the crypto server, verify that the certificate was signed by the course CA, and then use the public key from that certificate to encrypt a randomly generated 256-bit AES key. The base64 version of the AES key is what will be encrypted.

The lecturer said we should reuse the Lab 3 interface. For this reason, the program will have two tabs. The first tab will keep the Lab 3 AES and HMAC functions, while the second tab will contain the new Lab 4 work.

## Project Requirements

1. The code will be written in Python 3.
2. The user interface will use tkinter and will have two tabs.
3. The first tab will keep the Lab 3 functions: Get Key, Encrypt, Decrypt, Compute HMAC, and Verify HMAC.
4. The second tab will allow the user to enter the Andrew ID of the person they want to send an AES key to.
5. The program will request that user's certificate from the crypto server using the `get_certificate` message described in `crypto_message_spec_v3.md`.
6. If the server returns `no certificate for that user`, the program must show that message to the user. This should not be treated as a program crash.
7. The CA information will be read from `Pre_installed_CA_information.txt`. This includes the prime number `p`, the primitive element `alpha`, and the CA's public RSA key. The user should not have to type these values into the program.
8. The certificate must be checked before its public key can be used. The program must verify all of the following:
   - The certificate has the correct 6-line format and uses CRLF line endings.
   - The signature covers lines 1 through 5, including the CRLF ending on each line.
   - The RSA signature is valid using RSA-PSS with SHA-256, MGF1 with SHA-256, and a salt length of 32 bytes.
   - The username inside the certificate matches the Andrew ID that was requested.
   - The certificate's `p` and `alpha` values match the values in `Pre_installed_CA_information.txt`.
   - The public key is between 1 and `p - 1`.
9. If any certificate check fails, the certificate must be rejected and the public key inside it must not be used.
10. After a certificate has been verified, the program will randomly generate a 256-bit AES key on the local computer.
11. The AES key will be converted to standard base64. The result should be 44 characters long and must be saved to a text file.
12. The program will encrypt the 44-character base64 AES key using El Gamal and the verified public key of the person receiving it.
13. The base64 AES key will be divided into 11 groups of 4 characters. Each group will be read as one 32-bit unsigned integer in big-endian order.
14. A new random El Gamal value `b` between 1 and `p - 2` must be generated for every group. The same value must not be reused for another group.
15. For each group, the program will calculate `sigma = alpha^b mod p`, `delta = public_key^b mod p`, and `y2 = delta * message mod p`.
16. For each encrypted group, `sigma` and `y2` will each be stored as a 4-byte big-endian unsigned integer. The 8 bytes will then be base64 encoded into one 12-character line.
17. The El Gamal output file will contain 11 lines in the correct order. Every line must end with CRLF and the file must not contain any other text.
18. Network requests must not run on the tkinter UI thread because the window needs to stay responsive while waiting for the server.
19. The server IP, port, and my username will continue to come from the local `config.local.json` file used for Lab 3. This file must not be committed to the shared repository.
20. The private El Gamal key in `keypair.txt` must not be displayed, logged, sent to the server, or committed to the shared repository.
21. Before using the real server, certificate verification must be tested with the certificate example in `crypto_message_spec_v3.md`. The correct certificate must pass, while a certificate with changed information must fail.
22. The El Gamal code must also be tested locally by encrypting and decrypting a sample key with a matching key pair. The decrypted result must be the same as the original 44-character base64 AES key.

## Constraints and Important Details

- The public key can only be trusted after the certificate has passed every verification check.
- We are encrypting the 44 ASCII characters of the base64 AES key, not the original 32 raw key bytes.
- The order of the 11 groups must not change.
- A fresh random value `b` is required for each of the 11 groups.
- The Lab 3 functions should still work after the Lab 4 functions are added.
- The CA information is public information, but `keypair.txt` and `config.local.json` contain private information and must remain local.

## Open Questions

1. Does the Lab 4 program only need to encrypt an AES key for another user, or should it also allow me to decrypt an El Gamal file that somebody sends to me? If decryption is required, the program will need a safe way to read my private key and choose an encrypted input file.
2. Should fetching and verifying the certificate be one action, followed by a separate action for generating and encrypting the AES key? Keeping them separate will make it easier to see which step failed, but one combined button would make the workflow shorter.
3. Should each tab have its own progress bar and status message, or should both tabs share one? Separate status areas may make errors clearer when switching between the Lab 3 and Lab 4 work.
