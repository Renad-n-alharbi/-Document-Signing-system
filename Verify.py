import json, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

print(" Diploma Verification ")
filename = input("Enter diploma filename (e.g. diploma_445003558.json): ").strip()

with open(filename, "r") as f:
    diploma = json.load(f)

print("\n--- Diploma Details ---")
print(f"Student Name : {diploma['document']['student_name']}")
print(f"Student ID   : {diploma['document']['student_id']}")
print(f"Degree       : {diploma['document']['degree']}")
print(f"University   : {diploma['document']['Issuing Institution']}")
print(f"Issued At    : {diploma['document']['TimeStamp']}")
print(f"Document ID  : {diploma['document']['document_id']}")

try:
    signature = base64.b64decode(diploma['signature']['value'])
except Exception:
    print("ERROR: Signature is corrupted or not valid Base64.")
    exit()

content = json.dumps(diploma['document'], sort_keys=True).encode()

uni_key = input("Enter the verifying University key file (e.g., uqu_public_key.pem): ").strip()
with open(uni_key, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

print("\n--- Verification ---")
try:
    public_key.verify(signature, content, ec.ECDSA(hashes.SHA256()))
    print("Diploma is VALID and authentic, Signature matches.")
except InvalidSignature:
    print("Diploma is INVALID, the Signature does not match.")
