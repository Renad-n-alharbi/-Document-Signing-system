import json, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timezone
import uuid
import getpass
print("=== University Diploma Signing System ===\n")

TheDiploma = {
    "student_name": input("Student Name: ").strip(),
    "student_id": input("Student ID: ").strip(),
    "degree": input("Degree: ").strip(),
    "Issuing Institution": input("Institution: ").strip(),
    "TimeStamp": datetime.now(timezone.utc).isoformat(),
    "document_id": "CERT-" + str(uuid.uuid4())[:8].upper()
}
content = json.dumps(TheDiploma, sort_keys=True).encode()

uni_key = input("Enter the path to the university's private key file (e.g., uqu_private_key.pem): ")
with open(uni_key, "rb") as f:
    password = getpass.getpass("Enter the private key password: ").encode()
    private_key = serialization.load_pem_private_key(f.read(), password=password)

signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))

signed_diploma = {
    "document": TheDiploma,
    "signature": {
        "algorithm": "ECDSA-SHA256",
        "value": base64.b64encode(signature).decode()
    }
}
filename = f"diploma_{TheDiploma['student_id']}.json"
with open(filename, "w") as f:
    json.dump(signed_diploma, f, indent=2)

print(f"Signed diploma saved as {filename}")
