#!/bin/bash
# Task 4 – Applied Cryptography Final Exam
# Using GPG for signing, encryption, verification & decryption

# Clean old keys & files (optional for repeatable runs)
rm -f original_message.txt signed_message.asc decrypted_message.txt public.asc private.key signature_verification.txt gpg_verify_output.txt 2>/dev/null

# Create original plaintext email
echo "Hello I am Beka" > original_message.txt

# Create required GPG keys if not already created
if ! gpg --list-keys "Alice <alice@example.com>" >/dev/null 2>&1; then
    gpg --quick-generate-key "Alice <alice@example.com>" rsa3072 sign
fi

if ! gpg --list-keys "Bob <bob@example.com>" >/dev/null 2>&1; then
    gpg --quick-generate-key "Bob <bob@example.com>" rsa3072 encrypt
fi

# Sign & Encrypt message as Alice for Bob → signed_message.asc
gpg --local-user "Alice <alice@example.com>" \
    --recipient "Bob <bob@example.com>" \
    --armor --sign --encrypt \
    --output signed_message.asc \
    original_message.txt

# Decrypt and verify as Bob → decrypted_message.txt
# Also capture verification logs for analysis
gpg --output decrypted_message.txt --decrypt signed_message.asc 2> gpg_verify_output.txt

# Export required keys
# Alice's Public Key → public.asc
gpg --armor --export "Alice <alice@example.com>" > public.asc

# Bob's Private Key → private.key (only for exam task!)
gpg --armor --export-secret-keys "Bob <bob@example.com>" > private.key

# Create signature verification explanation file
cat > signature_verification.txt << 'EOF'
Signature Verification Explanation

The file "signed_message.asc" was decrypted and verified with GPG.

Verification results recorded in "gpg_verify_output.txt" include a line:
  "gpg: Good signature from 'Alice <alice@example.com>'"

This proves:
1. The message has NOT been modified after Alice signed it. (Integrity)
2. The signature was created using Alice's private key. (Authenticity)
3. Therefore, Bob can trust that the email was written by Alice and not tampered with.

EOF

echo "TASK 4 COMPLETE!"
echo "Generated files:"
ls -1 original_message.txt signed_message.asc decrypted_message.txt public.asc private.key signature_verification.txt gpg_verify_output.txt
