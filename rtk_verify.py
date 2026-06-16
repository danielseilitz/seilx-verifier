# -*- coding: utf-8 -*-
import json, hashlib, base64, sys, rfc8785
from pathlib import Path
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def load_pubkey(path):
    return serialization.load_pem_public_key(Path(path).read_bytes())

def verify_rtk_evidence(evidence, pubkey):
    # Step 1: Freshness
    now = datetime.now(timezone.utc)
    valid_until = datetime.fromisoformat(
        evidence["freshness_window"]["valid_until"].replace("Z", "+00:00")
    )
    if now > valid_until:
        return "INVALID", "Evidence freshness window expired"

    # Step 2: RFC8785 canonical hash (exclude only signature + canonical_hash)
    body = {k: v for k, v in evidence.items() if k not in ("signature", "canonical_hash")}
    canonical_bytes = rfc8785.dumps(body)
    computed_hash = hashlib.sha256(canonical_bytes).hexdigest()
    declared_hash = evidence.get("canonical_hash", "")
    if computed_hash != declared_hash:
        return "INVALID", f"Hash mismatch. Computed: {computed_hash[:16]}... Declared: {declared_hash[:16]}..."

    # Step 3: ECDSA P-256 over ASCII bytes of hex digest
    sig_bytes = base64.b64decode(evidence["signature"])
    signed_bytes = computed_hash.encode("ascii")
    try:
        pubkey.verify(sig_bytes, signed_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        # Fallback: try over canonical_bytes directly
        try:
            pubkey.verify(sig_bytes, canonical_bytes, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return "INVALID", "Signature verification failed"

    # Step 4: Verdict
    verdict = evidence.get("verdict", "")
    if verdict == "C1":
        return "VALID", f"Verdict: {verdict} — No unauthorized execution observed"
    elif verdict == "C2":
        return "PARTIAL", f"Verdict: {verdict} — Partial compliance"
    else:
        return "INVALID", f"Unknown verdict: {verdict}"

def main():
    evidence_path = sys.argv[1] if len(sys.argv) > 1 else "rtk1_evidence_a58a098c.json"
    pubkey_path = sys.argv[2] if len(sys.argv) > 2 else "rtk_pubkey.pem"

    print("")
    print("=" * 55)
    print("  SEILX §6 VERIFICATION — RTK Evidence Object")
    print("=" * 55)

    evidence = load_json(evidence_path)
    pubkey = load_pubkey(pubkey_path)

    print(f"  Evidence ID:  {evidence.get('evidence_id', '?')[:16]}...")
    print(f"  Producer:     {evidence.get('producer', '?')}")
    print(f"  System:       {evidence['validation_scope']['system_under_test']}")
    print(f"  Valid until:  {evidence['freshness_window']['valid_until']}")
    print("")

    result, msg = verify_rtk_evidence(evidence, pubkey)

    print(f"  §6 RECORD:    {result}")
    print(f"  Detail:       {msg}")
    print("")
    if result == "VALID":
        print("  COMPOSITION_INTACT — Evidence verified independently.")
    elif result == "PARTIAL":
        print("  PARTIAL — Review required.")
    else:
        print("  FATAL — Evidence does not pass independent verification.")
    print("")

if __name__ == "__main__":
    main()
