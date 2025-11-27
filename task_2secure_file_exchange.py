"""
Task 2 – Secure File Exchange Using RSA + AES

This script implements the full protocol described in the assignment:
- RSA key pair generation for Bob
- AES-256 encryption of Alice's file
- RSA encryption of the AES key
- Decryption and integrity verification using SHA-256
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
import os

def sha256_file(path):
    h = sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    # 1. Generate RSA key pair for Bob
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open("public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    with open("private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 2. Alice creates plaintext file
    alice_message = b"This is a secret file that Alice is securely sending to Bob using RSA + AES hybrid encryption."
    with open("alice_message.txt", "wb") as f:
        f.write(alice_message)

    # 3. Generate AES-256 key and IV
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # 4. Encrypt file with AES-256-CBC
    with open("alice_message.txt", "rb") as f:
        plaintext = f.read()

    padder = sym_padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    with open("encrypted_file.bin", "wb") as f:
        f.write(iv + ciphertext)

    # 5. Encrypt AES key with Bob's public RSA key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(encrypted_aes_key)

    # 6. Bob decrypts AES key
    decrypted_aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 7. Bob decrypts the file
    with open("encrypted_file.bin", "rb") as f:
        data = f.read()

    iv_stored = data[:16]
    ciphertext_stored = data[16:]

    cipher_dec = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv_stored), backend=default_backend())
    decryptor = cipher_dec.decryptor()
    padded_decrypted = decryptor.update(ciphertext_stored) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_plaintext = unpadder.update(padded_decrypted) + unpadder.finalize()

    with open("decrypted_message.txt", "wb") as f:
        f.write(decrypted_plaintext)

    # 8. Integrity check with SHA-256
    original_hash = sha256_file("alice_message.txt")
    decrypted_hash = sha256_file("decrypted_message.txt")

    integrity_ok = (original_hash == decrypted_hash)

    with open("integrity_check.txt", "w") as f:
        f.write("SHA-256 Integrity Check for Task 2\n")
        f.write(f"Original (alice_message.txt):  {original_hash}\n")
        f.write(f"Decrypted (decrypted_message.txt): {decrypted_hash}\n")
        f.write(f"Result: {{'PASS' if integrity_ok else 'FAIL'}}\n")

    print("Task 2 complete.")
    print("Integrity check:", "PASS" if integrity_ok else "FAIL")

if __name__ == "__main__":
    main()
