# SEILX Verifier

Cryptographic evidence integrity verifier for AI decision-state bundles.
Detects post-decision tampering via a multi-layer hash chain and signature verification.
Supports compositional verification across sovereign governance layers (Layer 1 × Layer 3).

Designed for independent verification under external challenge.

## Architecture

```
Layer 1  RTK-1 Pre-Deployment Testing    ECDSA P-256
         adversarial red-team evidence
              |
              | Minimal Interoperable Artifact (7 fields, Art. 1.3)
              |
Layer 3  SEILX Post-Decision Integrity   Ed25519
         decision-state bundle
```

Manipulation at any layer produces an irreversible FATAL_CHAIN_BREACH.
A compromised bundle cannot be re-signed or repaired.

## Installation

```bash
pip install cryptography
git clone https://github.com/danielseilitz/seilx-verifier
cd seilx-verifier
```

## Usage

### Standalone Verification

```bash
py seilx_verify.py verify examples/sample-bundle.seilx --pubkey test_keys/seilx_test_public.pem
```

### Compositional Verification (RTK-1 x SEILX)

```bash
py seilx_verify.py verify examples/seilx-bundle-with-upstream.seilx --pubkey test_keys/seilx_test_public.pem --upstream examples/rtk-evidence-mock.json --upstream-pubkey test_keys/rtk_mock_public.pem
```

### Executive Report Output

```bash
py seilx_verify.py verify examples/seilx-bundle-with-upstream.seilx --pubkey test_keys/seilx_test_public.pem --upstream examples/rtk-evidence-mock.json --upstream-pubkey test_keys/rtk_mock_public.pem --report executive
```

Writes `seilx_report.txt` — readable by CISO, Legal, or external auditor.

## Expected Output

**Valid bundle:**
```
=======================================================
  SEILX VERIFIER -- bundle-002
=======================================================
  [LAYER 1 STRUCTURE]   PASS: OK
  [LAYER 2 HASH CHAIN]  PASS: OK
  [LAYER 3 SIGNATURE]   PASS: OK
  [LAYER 4 COMPOSITION] PASS: COMPOSITION_INTACT

  VERIFIED -- COMPOSITION_INTACT
```

**Tampered bundle:**
```
  [LAYER 2 HASH CHAIN]  FAIL: Block 0 mismatch
  FATAL_CHAIN_BREACH
```

**Tampered upstream (RTK-1):**
```
  [LAYER 4 COMPOSITION] FAIL: COMPOSITION_CHAIN_BROKEN
  {'verdict_match': False, 'hash_match': False, 'rtk_sig_valid': False}
```

## Test Scenarios

| Scenario | Command | Expected |
|---|---|---|
| Clean chain | `verify seilx-bundle-with-upstream.seilx --upstream rtk-evidence-mock.json` | COMPOSITION_INTACT |
| Tampered SEILX bundle | modify `decision_state`, re-run verify | FATAL_CHAIN_BREACH |
| Tampered RTK-1 upstream | modify `canonical_json` verdict, re-run verify | COMPOSITION_CHAIN_BROKEN |

## Mock Evidence

- `examples/rtk-evidence-mock.json` — RTK-1 compatible evidence object (ECDSA P-256, mock key)
- `examples/seilx-bundle-with-upstream.seilx` — SEILX bundle with upstream reference (Ed25519)
- `test_keys/rtk_mock_public.pem` — Mock RTK-1 public key
- `test_keys/seilx_test_public.pem` — SEILX test public key

All mock files are clearly labelled. Do not use mock keys in production.

## Compliance Mappings

RTK-1 evidence objects support the following compliance frameworks:
- EU AI Act Art. 9, 14, 15
- NIST AI RMF GOVERN
- OWASP LLM01

## Contract Reference

Compositional verification implements the Minimal Interoperable Artifact specification
per RTK-SEILX Bilateral Agreement Art. 1.3 and Art. 3.1.
