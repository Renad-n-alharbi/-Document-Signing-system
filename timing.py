import time
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

RUNS = 100

print("=== Performance Measurement (Using Real Diploma) ===\n")

# Ask user for a real diploma file
diploma_file = input("Enter diploma filename to test performance: ").strip()

# Load diploma
with open(diploma_file, "r") as f:
    diploma = json.load(f)

# Extract content and signature
content = json.dumps(diploma["document"], sort_keys=True).encode()
signature_b64 = diploma["signature"]["value"]
signature = base64.b64decode(signature_b64)

# Ask for public key file
pub_key_file = input("Enter the verifying University public key file: ").strip()

with open(pub_key_file, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# === Key Generation ===
start = time.perf_counter()
for _ in range(RUNS):
    private_key = ec.generate_private_key(ec.SECP256R1())
keygen_ms = (time.perf_counter() - start) / RUNS * 1000
print(f"Key Generation   : {keygen_ms:.3f} ms")

# === Signing ===
start = time.perf_counter()
for _ in range(RUNS):
    sig = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
sign_ms = (time.perf_counter() - start) / RUNS * 1000
print(f"Signing          : {sign_ms:.3f} ms")

# === Verification ===
start = time.perf_counter()
for _ in range(RUNS):
    public_key.verify(signature, content, ec.ECDSA(hashes.SHA256()))
verify_ms = (time.perf_counter() - start) / RUNS * 1000
print(f"Verification     : {verify_ms:.3f} ms")

# === Full Workflow ===
start = time.perf_counter()
for _ in range(RUNS):
    pk = ec.generate_private_key(ec.SECP256R1())
    s = pk.sign(content, ec.ECDSA(hashes.SHA256()))
    pk.public_key().verify(s, content, ec.ECDSA(hashes.SHA256()))
full_ms = (time.perf_counter() - start) / RUNS * 1000
print(f"Full Workflow    : {full_ms:.3f} ms")

# === Sizes ===
print("\nSignature size   :", len(signature), "bytes")
print("Diploma size     :", len(content), "bytes")
