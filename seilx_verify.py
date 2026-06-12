# -*- coding: utf-8 -*-
import json, base64, hashlib, sys, argparse
from pathlib import Path
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def load_pubkey(path):
    return serialization.load_pem_public_key(Path(path).read_bytes())

def load_privkey(path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)

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

def sign_bundle(bundle, privkey):
    sig = bundle.get("signature", {})
    if sig.get("value"):
        return False, "SIGNING_REFUSED -- Decision state locked at T0. No post-hoc modification permitted."
    chain = bundle["hash_chain"]
    top_hash = chain[-1]["hash"].encode()
    sig_bytes = privkey.sign(top_hash, ec.ECDSA(hashes.SHA256()))
    bundle["signature"]["value"] = base64.b64encode(sig_bytes).decode()
    return True, "SIGNED -- Bundle sealed at T0."

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
    checks = {
        "verdict_match": verdict_match,
        "hash_match": hash_match,
        "key_id_match": key_id_match,
        "rtk_sig_valid": sig_valid
    }
    if all(checks.values()):
        return True, "COMPOSITION_INTACT " + str(checks)
    return False, "COMPOSITION_CHAIN_BROKEN " + str(checks)

def write_executive_report(args, results):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    verified = results["verified"]
    composition = results.get("composition")
    has_upstream = composition is not None
    if verified:
        status = "VERIFIED"
        admissible = "YES"
        comp_state = "INTACT" if composition else "N/A"
        l3_line = "Layer 3 (SEILX Post-Decision):    PASS -- Ed25519 verified"
        summary = ("The decision-state container has been deterministically cross-examined\n"
            "against the authorized upstream governance mandate. The evidence chain\n"
            "is independently verifiable, cryptographically bound, and forensically\n"
            "admissible under external challenge.")
        action = "No action required. Evidence integrity confirmed."
    else:
        status = "INVALID"
        admissible = "NO"
        comp_state = "BROKEN" if has_upstream else "N/A"
        l3_line = "Layer 3 (SEILX Post-Decision):    FAIL -- FATAL_CHAIN_BREACH"
        summary = ("The evidence container has been forensically compromised. Hash chain\n"
            "integrity failed, indicating post-decision tampering. The bundle\n"
            "cannot be validated, signed, or admitted as evidence.")
        action = "REGENERATE_FROM_ORIGIN_RUNTIME. Do not attempt to repair or re-sign."
    sep = "=" * 70
    lines = [sep, "           SEILX FORENSIC VERIFICATION REPORT", sep, "",
        "Timestamp:     " + ts, "Bundle:        " + args.bundle,
        "Verifier:      SEILX v0.1.0", "", "[COMPLIANCE VERDICT]",
        "Status:        " + status, "Composition:   " + comp_state,
        "Admissible:    " + admissible, "", "[FORENSIC EVIDENCE TRAIL]"]
    if has_upstream:
        l1 = "PASS -- ECDSA P-256 verified" if composition else "FAIL -- TAMPERED OR INVALID"
        lines.append("Layer 1 (RTK-1 Pre-Deployment):   " + l1)
    lines.append(l3_line)
    if has_upstream:
        lines.append("Cross-Reference:                  " + ("INTACT -- Minimal Interoperable Artifact matches" if composition else "BROKEN -- Artifact mismatch detected"))
    lines += ["", "[EXECUTIVE SUMMARY]", summary, "", "RECOMMENDED ACTION: " + action, sep]
    Path("seilx_report.txt").write_text("\n".join(lines), encoding="utf-8")
    print("\nExecutive report saved to: seilx_report.txt")

def main():
    parser = argparse.ArgumentParser(description="SEILX Verifier")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # verify subcommand
    vp = subparsers.add_parser("verify")
    vp.add_argument("bundle")
    vp.add_argument("--pubkey", required=True)
    vp.add_argument("--upstream", default=None)
    vp.add_argument("--upstream-pubkey", default=None)
    vp.add_argument("--report", default=None, choices=["executive"])

    # sign subcommand
    sp = subparsers.add_parser("sign")
    sp.add_argument("bundle")
    sp.add_argument("--privkey", required=True)
    sp.add_argument("--out", default=None)

    args = parser.parse_args()

    if args.command == "sign":
        bundle = load_json(args.bundle)
        privkey = load_privkey(args.privkey)
        print("")
        print("=" * 55)
        print("  SEILX SIGNER -- " + bundle.get("bundle_id","?"))
        print("=" * 55)
        ok, msg = sign_bundle(bundle, privkey)
        print("  " + msg)
        if ok:
            out_path = args.out or args.bundle.replace(".seilx", "-signed.seilx")
            Path(out_path).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
            print("  Saved: " + out_path)
        print("")
        return

    # verify flödet
    bundle = load_json(args.bundle)
    pubkey = load_pubkey(args.pubkey)
    results = {"verified": False, "composition": None}
    print("")
    print("=" * 55)
    print("  SEILX VERIFIER -- " + bundle.get("bundle_id","?"))
    print("=" * 55)
    ok, msg = verify_structure(bundle)
    print("  [LAYER 1 STRUCTURE]   " + ("PASS" if ok else "FAIL") + ": " + msg)
    if not ok:
        print("  FATAL_CHAIN_BREACH")
        if args.report == "executive": write_executive_report(args, results)
        sys.exit(1)
    ok, msg = verify_hash_chain(bundle)
    print("  [LAYER 2 HASH CHAIN]  " + ("PASS" if ok else "FAIL") + ": " + msg)
    if not ok:
        print("  FATAL_CHAIN_BREACH")
        if args.report == "executive": write_executive_report(args, results)
        sys.exit(1)
    ok, msg = verify_signature(bundle, pubkey)
    print("  [LAYER 3 SIGNATURE]   " + ("PASS" if ok else "FAIL") + ": " + msg)
    if not ok:
        print("  FATAL_CHAIN_BREACH")
        if args.report == "executive": write_executive_report(args, results)
        sys.exit(1)
    results["verified"] = True
    if args.upstream and args.upstream_pubkey:
        rtk_evidence = load_json(args.upstream)
        rtk_pubkey = load_pubkey(args.upstream_pubkey)
        ok, msg = verify_compositional_link(bundle, rtk_evidence, rtk_pubkey)
        print("  [LAYER 4 COMPOSITION] " + ("PASS" if ok else "FAIL") + ": " + msg)
        results["composition"] = ok
        if not ok:
            print("  COMPOSITION_CHAIN_BROKEN")
            if args.report == "executive":
                results["verified"] = False
                write_executive_report(args, results)
            sys.exit(1)
    print("")
    print("  VERIFIED -- COMPOSITION_INTACT")
    print("")
    if args.report == "executive":
        write_executive_report(args, results)

if __name__ == "__main__":
    main()
