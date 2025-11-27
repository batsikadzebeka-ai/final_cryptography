import hashlib
import json
import os

# ======= Step 1: Create Original File =======
original_file = "original.txt"
with open(original_file, "w") as f:
    f.write("Hello I am Beka")

print("✔ Created original.txt")

# Function to compute hashes
def compute_hashes(file_path):
    hashes = {
        "SHA256": hashlib.sha256(),
        "SHA1": hashlib.sha1(),
        "MD5": hashlib.md5()
    }

    with open(file_path, "rb") as f:
        data = f.read()
        for algo in hashes.values():
            algo.update(data)

    return {name: algo.hexdigest() for name, algo in hashes.items()}


# ======= Step 2: Compute and Store Hashes =======
hashes = compute_hashes(original_file)

with open("hashes.json", "w") as f:
    json.dump(hashes, f, indent=4)

print("✔ Hashes stored in hashes.json")


# ======= Step 3: Create Tampered File =======
tampered_file = "tampered.txt"
with open(tampered_file, "w") as f:
    f.write("Hello I am Beko")  # small change: last letter changed!

print("✔ Created tampered.txt")


# ======= Step 4: Recompute Hashes and Check Integrity =======
new_hashes = compute_hashes(tampered_file)

print("\n🔍 Integrity Check Results")
print("--------------------------")

integrity_ok = True

for algo in hashes:
    match = hashes[algo] == new_hashes[algo]
    print(f"{algo}: {'MATCH' if match else 'MISMATCH'}")
    if not match:
        integrity_ok = False

if integrity_ok:
    print("\n✔ PASS: File remains unchanged.")
else:
    print("\n❌ FAIL: File has been tampered with!")


# ======= End =======
print("\n🎯 Task 5 Complete!")

