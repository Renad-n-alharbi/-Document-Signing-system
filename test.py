import json, base64, subprocess, os
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timezone
import uuid



def generate_university_keys(uni_name: str, password: bytes):
    private_key = ec.generate_private_key(ec.SECP256R1())
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{uni_name}_private_key.pem", "wb") as f:
        f.write(priv_bytes)
    with open(f"{uni_name}_public_key.pem", "wb") as f:
        f.write(pub_bytes)
    return private_key, private_key.public_key()


def build_and_sign(student_name, student_id, degree,
                   institution, private_key):
    doc = {
        "student_name":        student_name,
        "student_id":          student_id,
        "degree":              degree,
        "Issuing Institution": institution,
        "TimeStamp":           datetime.now(timezone.utc).isoformat(),
        "document_id":         "CERT-" + str(uuid.uuid4())[:8].upper(),
    }
    content   = json.dumps(doc, sort_keys=True).encode()
    signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
    return {
        "document":  doc,
        "signature": {
            "algorithm": "ECDSA-SHA256",
            "value":     base64.b64encode(signature).decode()
        }
    }


def verify(signed_diploma: dict, public_key) -> bool:
    sig     = base64.b64decode(signed_diploma["signature"]["value"])
    content = json.dumps(signed_diploma["document"],
                         sort_keys=True).encode()
    try:
        public_key.verify(sig, content, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


@pytest.fixture(scope="module")
def uqu_keys():

    return generate_university_keys("uqu", b"uqu-secret")


@pytest.fixture(scope="module")
def kau_keys():
    return generate_university_keys("kau", b"kau-secret")


@pytest.fixture
def uqu_diploma(uqu_keys):
    priv, pub = uqu_keys
    diploma = build_and_sign(
        "Renad Naser Alharbi", "445004662",
        "Bachelor of Computer Science",
        "Umm Al-Qura University", priv
    )
    return diploma, pub


@pytest.fixture
def kau_diploma(kau_keys):
    priv, pub = kau_keys
    diploma = build_and_sign(
        "Sara AlGhamdi", "438001234",
        "Bachelor of Cybersecurity",
        "King Abdulaziz University", priv
    )
    return diploma, pub


class TestFunctionality:

    def test_valid_diploma_uqu(self, uqu_diploma):
        diploma, pub = uqu_diploma
        assert verify(diploma, pub) == True

    def test_valid_diploma_kau(self, kau_diploma):
        diploma, pub = kau_diploma
        assert verify(diploma, pub) == True

    def test_multiple_diplomas_same_key(self, uqu_keys):
        """ sign multiple documents with same key"""
        priv, pub = uqu_keys
        d1 = build_and_sign(
            "Jana AlObidy", "445002016",
            "Bachelor of Computer Science",
            "Umm Al-Qura University", priv
        )
        d2 = build_and_sign(
            "Rania Mohammed", "445003558",
            "Bachelor of Computer Science",
            "Umm Al-Qura University", priv
        )
        assert verify(d1, pub) == True
        assert verify(d2, pub) == True

    
class TestSecurity:

    # ── Security Test 1: Substitution Attack ─────────
  
    def test_substitution_attack(self, uqu_keys):
        """
        Attacker steals signature from Student A's diploma
        and pastes it into Student B's diploma.
        """
        priv, pub = uqu_keys
        diploma_a = build_and_sign(
            "Renad Naser Alharbi", "445004662",
            "Bachelor of Computer Science",
            "Umm Al-Qura University", priv
        )
        diploma_b = build_and_sign(
            "Fake Student", "999999999",
            "Bachelor of Computer Science",
            "Umm Al-Qura University", priv
        )
        # Steal signature from A and attach to B
        diploma_b["signature"] = diploma_a["signature"]
        assert verify(diploma_b, pub) == False



    # ── Security Test 2: Content Tampering Attack ─────
 

    def test_tampered_degree(self, uqu_diploma):
    
        diploma, pub = uqu_diploma
        diploma["document"]["degree"] = "PhD of Computer Science"
        assert verify(diploma, pub) == False

    def test_tampered_student_name(self, uqu_diploma):
        """
        Attacker changes student name after signing.
        Any metadata modification must break the signature.
        """
        diploma, pub = uqu_diploma
        diploma["document"]["student_name"] = "HACKED NAME"
        assert verify(diploma, pub) == False


    # ── Security Test 3: Forgery Attack ──────────────


    def test_fake_signature(self, uqu_diploma):
        """
        Attacker replaces signature with a random base64 string.
        Must fail — cannot forge ECDSA without private key.
        Probability of success: 2^-128.
        """
        diploma, pub = uqu_diploma
        diploma["signature"]["value"] = base64.b64encode(
            b"totallyfakeECDSAsignature123456"
        ).decode()
        assert verify(diploma, pub) == False

   
    # ── Security Test 4: Wrong University Key ─────────

    def test_wrong_university_key(self, uqu_diploma, kau_keys):
        """
        UQU diploma verified against KAU public key must fail.
        """
        diploma, _ = uqu_diploma
        _, kau_pub = kau_keys
        assert verify(diploma, kau_pub) == False


    # ── Security Test 5: Private Key Password Bypass ──


    def test_wrong_password_rejected(self):
        """
        Attacker obtains private key file but uses wrong password.
    
        """
        with open("uqu_private_key.pem", "rb") as f:
            raw = f.read()
        with pytest.raises(Exception):
            serialization.load_pem_private_key(
                raw, password=b"wrongpassword"
            )
