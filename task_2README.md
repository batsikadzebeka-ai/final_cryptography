
# Task 2 – Secure File Exchange Using RSA + AES

## Scenario
Alice wants to send Bob a secret file securely using a hybrid RSA + AES encryption scheme.

## Steps Implemented

1. **RSA Key Generation (Bob)**
   - A 2048-bit RSA key pair is generated for Bob.
   - `public.pem` – Bob's RSA public key (shared with Alice).
   - `private.pem` – Bob's RSA private key (kept secret by Bob).

2. **Alice Creates Plaintext File**
   - Alice writes her message into `alice_message.txt`.

3. **AES-256 Key and IV Generation**
   - Alice generates a random 256-bit AES key and a 128-bit IV.

4. **File Encryption with AES-256 (CBC mode)**
   - `alice_message.txt` is padded using PKCS#7 and encrypted with AES-256 in CBC mode.
   - Output is stored in `encrypted_file.bin` as **IV || ciphertext**.

5. **Encrypt AES Key with Bob's RSA Public Key**
   - The AES key is encrypted using Bob's `public.pem` with RSA-OAEP (SHA-256).
   - Encrypted key is stored in `aes_key_encrypted.bin`.

6. **Bob Decrypts AES Key**
   - Bob uses his RSA private key (`private.pem`) to decrypt `aes_key_encrypted.bin`.

7. **Bob Decrypts the Encrypted File**
   - Bob recovers the IV and ciphertext from `encrypted_file.bin`.
   - Using the decrypted AES key and IV, he decrypts the file to produce `decrypted_message.txt`.

8. **Integrity Verification Using SHA-256**
   - SHA-256 hash is computed for both:
     - `alice_message.txt`
     - `decrypted_message.txt`
   - The hashes are compared.
   - The result (PASS/FAIL) is recorded in `integrity_check.txt`.

## Files in This Folder

- `alice_message.txt` – Original plaintext file from Alice
- `encrypted_file.bin` – File encrypted with AES-256 (IV + ciphertext)
- `aes_key_encrypted.bin` – AES key encrypted with Bob's RSA public key
- `decrypted_message.txt` – Final decrypted output by Bob
- `public.pem` – Bob's RSA public key
- `private.pem` – Bob's RSA private key
- `integrity_check.txt` – SHA-256 integrity check results
- `secure_file_exchange.py` – Python implementation for Task 2

## Result

- Integrity check: **PASS**
- The SHA-256 hashes of the original and decrypted files match.
