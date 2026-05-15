# SEILX Verifier

SEILX Verifier is a deterministic CLI verification utility for `.seilx` Decision Evidence Bundles.

Verifies structural integrity, hash chain consistency, and external artifact integrity. Detects manipulation at the evidence layer.

## Installation

```
pip install -r requirements.txt
```

## Usage

```
py seilx_verify.py verify examples/sample-bundle.seilx
py seilx_verify.py verify examples/tampered-bundle.seilx
```

## Example Output

**Valid bundle:**
```
✓ Structure validation: PASSED
✓ Hash chain verification: PASSED
○ Signature verification: PENDING
Status: VALID
```

**Tampered bundle:**
```
✓ Structure validation: PASSED
✗ Hash chain verification: FAILED — MANIPULATION DETECTED
○ Signature verification: PENDING
Status: INVALID
```

## Verification States

| State | Meaning |
|---|---|
| `VALID` | Bundle integrity confirmed. Hash chain verified. |
| `INVALID` | Hash chain mismatch. Manipulation detected. |
| `PARTIAL` | Bundle integrity OK. One or more external artifacts pending. |

## Sample Bundles

- `examples/sample-bundle.seilx` — Valid bundle
- `examples/tampered-bundle.seilx` — Manipulated bundle (demonstrates detection)

## Integration

See `SEILX_Integration_Spec_v0.1.md` for RTK-1 alignment.