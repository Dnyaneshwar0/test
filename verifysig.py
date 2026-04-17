"""
verify_sig.py — verify an output.sig file produced by the Docker signing container.
change 1
Usage:
    python verify_sig.py output.sig sbom.json public_key.pem

Or import and call verify() directly from your own code.
"""

import json
import hashlib
import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


# ── Public API ────────────────────────────────────────────────────────────────

def verify(
    sig_path: str | Path,
    sbom_path: str | Path,
    pubkey_path: str | Path,
) -> dict:
    """
    Verify a .sig bundle against the original SBOM and a public key.

    Parameters
    ----------
    sig_path    : path to the .sig JSON bundle produced by the Docker container
    sbom_path   : path to the original sbom.json that was signed
    pubkey_path : path to the RSA public key in PEM format

    Returns
    -------
    dict with keys:
        valid        (bool)   — True if signature and hash both check out
        sbom_hash    (str)    — SHA-256 hex of the sbom.json on disk
        validity     (dict)   — the validity stamp from the bundle
        signed_at    (str)    — ISO-8601 timestamp from the bundle
        error        (str)    — present only when valid is False

    Raises
    ------
    FileNotFoundError  if any input file is missing
    ValueError         if the .sig bundle is malformed
    """
    sig_path    = Path(sig_path)
    sbom_path   = Path(sbom_path)
    pubkey_path = Path(pubkey_path)

    for p in (sig_path, sbom_path, pubkey_path):
        if not p.exists():
            raise FileNotFoundError(f"File not found: {p}")

    # ── 1. Load the bundle ────────────────────────────────────────────────────
    bundle = json.loads(sig_path.read_text())
    for field in ("sbom_hash", "signature", "algorithm", "validity", "signed_at"):
        if field not in bundle:
            raise ValueError(f"Malformed .sig bundle: missing field '{field}'")

    if bundle["algorithm"] != "RSA-PSS-SHA256":
        raise ValueError(f"Unsupported algorithm: {bundle['algorithm']}")

    # ── 2. Re-hash the SBOM ───────────────────────────────────────────────────
    h = hashlib.sha256()
    with open(sbom_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    actual_hash = h.hexdigest()

    if actual_hash != bundle["sbom_hash"]:
        return {
            "valid":     False,
            "sbom_hash": actual_hash,
            "validity":  bundle.get("validity", {}),
            "signed_at": bundle.get("signed_at", ""),
            "error":     (
                f"Hash mismatch — SBOM may have been tampered with.\n"
                f"  Expected : {bundle['sbom_hash']}\n"
                f"  Computed : {actual_hash}"
            ),
        }

    # ── 3. Load the public key and verify RSA-PSS signature ──────────────────
    with open(pubkey_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    signature_bytes = base64.b64decode(bundle["signature"])
    hash_bytes      = bytes.fromhex(actual_hash)

    try:
        public_key.verify(
            signature_bytes,
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return {
            "valid":     False,
            "sbom_hash": actual_hash,
            "validity":  bundle.get("validity", {}),
            "signed_at": bundle.get("signed_at", ""),
            "error":     "Signature verification FAILED — key mismatch or bundle tampered.",
        }

    # ── 4. All checks passed ──────────────────────────────────────────────────
    return {
        "valid":     True,
        "sbom_hash": actual_hash,
        "validity":  bundle["validity"],
        "signed_at": bundle["signed_at"],
    }


# ── CLI entry point ────────────────────────────────────────────────────────────

def _cli():
    if len(sys.argv) != 4:
        print("Usage: python verify_sig.py <output.sig> <sbom.json> <public_key.pem>")
        sys.exit(1)

    result = verify(sys.argv[1], sys.argv[2], sys.argv[3])

    if result["valid"]:
        print("✓  Signature VALID")
        print(f"   SBOM hash  : {result['sbom_hash']}")
        print(f"   Signed at  : {result['signed_at']}")
        v = result["validity"]
        print(f"   Status     : {v.get('status', '—')}")
        print(f"   Statement  : {v.get('statement', '—')}")
    else:
        print("✗  Signature INVALID")
        print(f"   {result['error']}")
        sys.exit(2)


if __name__ == "__main__":
    _cli()