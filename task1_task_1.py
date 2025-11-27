from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.backends import default_backend
import os

# ===========================
# Step 0: Create message.txt
# ===========================
plaintext = b"Hi I am Beka"
with open("message.txt", "wb") as file:
    file.write(plaintext)

# ===========================
# Step 1: RSA Key Pair (User A)
# ===========================
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

with open("public.pem", "wb") as f:
    f.write(public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

with open("private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

# ===========================
# Step 2: AES-256 Encryption (User B)
# ===========================
aes_key = os.urandom(32)
aes_iv = os.urandom(16)

padder = aes_padding.PKCS7(128).padder()
padded = padder.update(plaintext) + padder.finalize()

cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded) + encryptor.finalize()

with open("encrypted_message.bin", "wb") as f:
    f.write(aes_iv + ciphertext)

# ===========================
# Encrypt the AES Key using RSA Public Key
# ===========================
encrypted_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

# ===========================
# Step 3: Decryption (User A)
# ===========================
# Decrypt AES Key
restored_key = private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# AES decrypt message
cipher_dec = Cipher(algorithms.AES(restored_key), modes.CBC(aes_iv), backend=default_backend())
decryptor = cipher_dec.decryptor()
unpadded_msg = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = aes_padding.PKCS7(128).unpadder()
final_plain = unpadder.update(unpadded_msg) + unpadder.finalize()

with open("decrypted_message.txt", "wb") as f:
    f.write(final_plain)

print("Task 1 complete with message: 'Hi I am Beka'")
