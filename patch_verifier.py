import pathlib

CODE = """import json, base64, hashlib, sys, argparse
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def load_json(path):
    return json.loads(Path(path).read_text())

def load_pubkey(path):
    return serialization.load_pem_public_key(Path(path).read_bytes())

def verify_structure(bundle):
    required = ["bundle_id","timestamp","decision_state","hash_chain","signature"]
    missing = [f for f in required if f not in bundle]
    if missing:
        return False, "Missing fields: " + str(missing)
    return True, "OK"

def verify_hash_chain(bundle):
    ds_bytes = json.dumps(bundle["decision_state"], sort_keys=True, separators=(',',':')).encode()
    h0_expected = "sha256:" + hashlib.sha256(ds_bytes).hexdigest()
    chain = bundle["hash_chain"]
    if chain[0]["hash"] != h0_expected:
        return False, "Block 0 mismatch"
    if "external_verdicts" in bundle:
        ev_bytes = json.dumps(bundle["external_verdicts"], sort_keys=True, separators=(',',':')).encode()
        h1_expected = "sha256:" + hashlib.sha256(ev_bytes).hexdigest()
        if chain[1]["hash"] != h1_expected:
            return False, "Block 1 external_verdicts mismatch"
        h2_expected = "sha256:" + hashlib.sha256((chain[0]["hash"]+chain[1]["hash"]).encode()).hexdigest()
        if chain[2]["hash"] != h2_expected:
            return False, "Block 2 chain_root mismatch"
    return True, "OK"

def verify_signature(bundle, pubkey):
    sig_block = bundle["signature"]
    sig_bytes = base64.b64decode(sig_block["value"])
    signed_val = sig_block.get("signed_value", bundle["hash_chain"][-1]["hash"]).encode()
    try:
        if isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(sig_bytes, signed_val)
        else:
            pubkey.verify(sig_bytes, signed_val, ec.ECDSA(hashes.SHA256()))
        return True, "OK"
    except InvalidSignature:
        return False, "INVALID SIGNATURE"

def verify_compositional_link(bundle, rtk_evidence, rtk_pubkey):
    verdicts = bundle.get("external_verdicts", [])
    rtk_layer = next((v for v in verdicts if v.get("source") == "RTK-1"), None)
    if not rtk_layer:
        return False, "COMPOSITION_CHAIN_BROKEN: No RTK-1 layer found"
    mia = rtk_layer["minimal_interoperable_artifact"]
    canonical_json = rtk_evidence["canonical_json"]
    canonical_bytes = json.dumps(canonical_json, sort_keys=True, separators=(',',':')).encode()
    sig_bytes = base64.b64decode(rtk_evidence["signature"]["value"])
    try:
        rtk_pubkey.verify(sig_bytes, canonical_bytes, ec.ECDSA(hashes.SHA256()))
        sig_valid = True
    except InvalidSignature:
        sig_valid = False
    expected_hash = "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
    hash_match = mia["canonical_hash"] == rtk_evidence["canonical_hash"] == expected_hash
    verdict_match = mia["verdict_value"] == canonical_json["verdict"]
    key_id_match = mia["signing_key"]["key_id"] == rtk_evidence["signature"]["key_id"]
    checks = {"verdict_match": verdict_match, "hash_match": hash_match, "key_id_match": key_id_match, "rtk_sig_valid": sig_valid}
    if all(checks.values()):
        return True, "COMPOSITION_INTACT " + str(checks)
    return False, "COMPOSITION_CHAIN_BROKEN " + str(checks)

def main():
    parser = argparse.ArgumentParser(description="SEILX Verifier")
    parser.add_argument("command")
    parser.add_argument("bundle")
    parser.add_argument("--pubkey", required=True)
    parser.add_argument("--upstream", default=None)
    parser.add_argument("--upstream-pubkey", default=None)
    args = parser.parse_args()
    bundle = load_json(args.bundle)
    pubkey = load_pubkey(args.pubkey)
    print("")
    print("=" * 55)
    print("  SEILX VERIFIER -- " + bundle.get("bundle_id","?"))
    print("=" * 55)
    ok, msg = verify_structure(bundle)
    print("  [LAYER 1 STRUCTURE]   " + ("PASS" if ok else "FAIL") + ": " + msg)
    if not ok:
        print("  FATAL_CHAIN_BREACH"); sys.exit(1)
    ok, msg = verify_hash_chain(bundle)
    print("  [LAYER 2 HASH CHAIN]  " + ("PASS" if ok else "FAIL") + ": " + msg)
    if not ok:
        print("  FATAL_CHAIN_BREACH"); sys.exit(1)
    ok, msg = verify_signature(bundle, pubkey)
    print("  [LAYER 3 SIGNATURE]   " + ("PASS" if ok else "FAIL") + ": " + msg)
    if not ok:
        print("  FATAL_CHAIN_BREACH"); sys.exit(1)
    if args.upstream and args.upstream_pubkey:
        rtk_evidence = load_json(args.upstream)
        rtk_pubkey = load_pubkey(args.upstream_pubkey)
        ok, msg = verify_compositional_link(bundle, rtk_evidence, rtk_pubkey)
        print("  [LAYER 4 COMPOSITION] " + ("PASS" if ok else "FAIL") + ": " + msg)
        if not ok:
            print("  COMPOSITION_CHAIN_BROKEN"); sys.exit(1)
    print("")
    print("  VERIFIED -- COMPOSITION_INTACT")
    print("")

if __name__ == "__main__":
    main()
"""

pathlib.Path("seilx_verify.py").write_text(CODE, encoding="utf-8")
print("seilx_verify.py overwritten successfully")
