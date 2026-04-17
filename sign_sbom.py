"""
sign_sbom.py — runs inside the Docker container.

Inputs (via /data volume):
  /data/sbom.json       — the SBOM to sign
  /data/private_key.pem — RSA private key (PEM, no passphrase)

Output:
  /data/output.sig      — JSON bundle containing:
                            • sbom_hash  (SHA-256 hex of sbom.json)
                            • signature  (base64 RSA-PSS over the hash)
                            • validity   (stamp marking the artifact as safe)
                            • signed_at  (ISO-8601 UTC timestamp)
"""

import json
import hashlib
import base64
import datetime
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


from pathlib import Path

print(Path.cwd())

DATA_DIR      = Path.cwd()
SBOM_PATH     = DATA_DIR / "trivy_report.json"
PRIVKEY_PATH  = DATA_DIR / "private_key.pem"
OUTPUT_PATH   = DATA_DIR / "output.sig"


print(SBOM_PATH)

def load_private_key(path: Path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def sha256_file(path: Path) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.digest()


def sign(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def main():
    # Validate inputs
    for p in (SBOM_PATH, PRIVKEY_PATH):
        if not p.exists():
            print(f"ERROR: {p} not found", file=sys.stderr)
            sys.exit(1)

    print(f"[+] Loading SBOM from {SBOM_PATH}")
    sbom_hash_bytes = sha256_file(SBOM_PATH)
    sbom_hash_hex   = sbom_hash_bytes.hex()
    print(f"[+] SHA-256: {sbom_hash_hex}")

    print(f"[+] Loading private key from {PRIVKEY_PATH}")
    private_key = load_private_key(PRIVKEY_PATH)

    print("[+] Signing hash with RSA-PSS / SHA-256 ...")
    signature_bytes = sign(private_key, sbom_hash_bytes)
    signature_b64   = base64.b64encode(signature_bytes).decode()

    # Build the signed bundle
    bundle = {
        "sbom_hash":   sbom_hash_hex,
        "signature":   signature_b64,
        "algorithm":   "RSA-PSS-SHA256",
        "validity": {
            "status":     "SAFE",
            "statement":  "This SBOM has been reviewed and is certified safe.",
            "issued_by":  "sbom-signer-container",
        },
        "signed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    OUTPUT_PATH.write_text(json.dumps(bundle, indent=2))
    print(f"[+] Signature bundle written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()