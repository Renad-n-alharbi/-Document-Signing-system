from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os
import getpass

uni_name = input("Enter University Name (e.g., UQU, KAU): ").strip().lower()
PRIVATE_KEY_FILE = f"{uni_name}_private_key.pem"
PUBLIC_KEY_FILE = f"{uni_name}_public_key.pem"
password = getpass.getpass("Enter a password to encrypt the private key: ").encode()
try:
    # Generate key pair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Save private key
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        ))

    # Save public key
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("ECC key pair generated and securely stored.")
except Exception as e:
    print("Error generating keys:", e)
