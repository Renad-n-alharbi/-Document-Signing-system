import json, base64, time, statistics
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timezone
import uuid

# This script performs timing measurements for the key operations in our diploma signing system:
RUNS = 100

# Same structure as sign.py produces
THE_DIPLOMA = {
    "student_name":        "Renad Naser Alharbi",
    "student_id":          "445004662",
    "degree":              "Bachelor of Computer Science",
    "Issuing Institution": "Umm Al-Qura University",
    "TimeStamp":           datetime.now(timezone.utc).isoformat(),
    "document_id":         "CERT-" + str(uuid.uuid4())[:8].upper(),
}
CONTENT = json.dumps(THE_DIPLOMA, sort_keys=True).encode()

print("=" * 55)
print("   PERFORMANCE MEASUREMENT")
print("   Scenario: University Diploma Signing System")
print(f"   Averaging over {RUNS} runs per operation")
print("=" * 55)

# ── Operation 1: Key Generation (mirrors keygen.py) ──
times = []
for _ in range(RUNS):
    t0 = time.perf_counter()
    private_key = ec.generate_private_key(ec.SECP256R1())
    times.append((time.perf_counter() - t0) * 1000)
keygen_avg = statistics.mean(times)
keygen_std = statistics.stdev(times)
print(f"\n[1] Key Generation (keygen.py)")
print(f"    Average : {keygen_avg:.3f} ms")
print(f"    Std dev : {keygen_std:.3f} ms")
print(f"    Note    : Run once per university — one-time cost")

# ── Operation 2: Diploma Signing (mirrors sign.py) ───
# Reuse one stable key — same as sign.py loads from pem file
stable_private = ec.generate_private_key(ec.SECP256R1())
stable_public  = stable_private.public_key()

times = []
last_sig = None
for _ in range(RUNS):
    t0  = time.perf_counter()
    sig = stable_private.sign(CONTENT, ec.ECDSA(hashes.SHA256()))
    times.append((time.perf_counter() - t0) * 1000)
    last_sig = sig
sign_avg = statistics.mean(times)
sign_std = statistics.stdev(times)
print(f"\n[2] Diploma Signing (sign.py)")
print(f"    Average : {sign_avg:.3f} ms")
print(f"    Std dev : {sign_std:.3f} ms")

# ── Operation 3: Signature Verification (mirrors verify.py) ──
times = []
for _ in range(RUNS):
    t0 = time.perf_counter()
    stable_public.verify(last_sig, CONTENT, ec.ECDSA(hashes.SHA256()))
    times.append((time.perf_counter() - t0) * 1000)
verify_avg = statistics.mean(times)
verify_std = statistics.stdev(times)
print(f"\n[3] Signature Verification (verify.py)")
print(f"    Average : {verify_avg:.3f} ms")
print(f"    Std dev : {verify_std:.3f} ms")

# ── Operation 4: Full Workflow ────────────────────────
times = []
for _ in range(RUNS):
    t0   = time.perf_counter()
    # keygen
    priv = ec.generate_private_key(ec.SECP256R1())
    pub  = priv.public_key()
    # sign
    s    = priv.sign(CONTENT, ec.ECDSA(hashes.SHA256()))
    # verify
    pub.verify(s, CONTENT, ec.ECDSA(hashes.SHA256()))
    times.append((time.perf_counter() - t0) * 1000)
full_avg = statistics.mean(times)
full_std = statistics.stdev(times)
print(f"\n[4] Full Workflow (keygen + sign + verify)")
print(f"    Average : {full_avg:.3f} ms")
print(f"    Std dev : {full_std:.3f} ms")

# ── Sizes ─────────────────────────────────────────────
signed_package = {
    "document":  THE_DIPLOMA,
    "signature": {
        "algorithm": "ECDSA-SHA256",
        "value":     base64.b64encode(last_sig).decode()
    }
}
package_bytes  = len(json.dumps(signed_package).encode())
content_bytes  = len(CONTENT)
sig_bytes      = len(last_sig)

print(f"\n[5] Sizes")
print(f"    Diploma content (JSON)     : {content_bytes} bytes")
print(f"    ECDSA signature (DER)      : {sig_bytes} bytes")
print(f"    Full signed package (JSON) : {package_bytes} bytes")

print("\n" + "=" * 55)
print("   SUMMARY TABLE")
print("=" * 55)
print(f"   {'Operation':<35} {'Avg (ms)':>10}")
print(f"   {'-'*45}")
print(f"   {'Key Generation (one-time)':<35} {keygen_avg:>10.3f}")
print(f"   {'Diploma Signing':<35} {sign_avg:>10.3f}")
print(f"   {'Signature Verification':<35} {verify_avg:>10.3f}")
print(f"   {'Full Workflow':<35} {full_avg:>10.3f}")
print("=" * 55)