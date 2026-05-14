# SEILX Integration Specification v0.1

**Document ID:** SEILX-INT-SPEC-v0.1  
**Date:** May 14, 2026  
**Authored by:** SEILX Group OÜ (Daniel Seilitz)  
**Audience:** RTK Security Labs (Ramon Loya)  
**Status:** Draft — pre-pilot  
**Companion document:** RTK-1/SEILX Integration Spec v1.0 (RTK Security Labs)

---

## §1 — Purpose and Scope

This document defines how SEILX ingests, binds, preserves, and exposes externally generated evidentiary artifacts within a SEILX Decision Evidence Bundle (`.seilx`).

SEILX operates as an evidence composer, not an evidence producer. Where a third-party system such as RTK-1 produces a signed verdict artifact, SEILX binds that artifact into the decision-time evidence chain without alteration, re-derivation, or override.

The resulting bundle is designed to support independent verification of evidentiary integrity without requiring trust in the originating operational system.

---

## §2 — Trust Boundary

RTK-1 establishes evidence regarding whether an AI system's boundary held under adversarial conditions at test-time.

SEILX establishes evidence regarding the execution-fixed state of the system at the moment a decision was produced.

Neither party re-derives or overrides the other's evidentiary output. Each layer remains authoritative for its respective evidentiary scope. The composed bundle preserves both layers as cryptographically distinct artifacts.

SEILX must not alter, normalize, reinterpret, or recompute properties received from an external evidence producer. Where verification cannot be completed, the discrepancy must be surfaced explicitly rather than silently modified, excluded, or replaced.

---

## §3 — Evidence Object Schema

A SEILX Decision Evidence Bundle (`.seilx`) contains structured evidence regarding:

- the decision context,
- execution-time state,
- integrity metadata,
- and externally sourced evidentiary artifacts.

```json
{
  "version": "string",
  "bundle_id": "uuid-v4",
  "created_at": "ISO-8601",
  "decision_context": {
    "decision_type": "string",
    "decision_timestamp": "ISO-8601",
    "input_hash": "sha256-hex",
    "output_ref": "object-reference"
  },
  "evidence": {
    "t0_state": {},
    "execution_trace": [],
    "overrides": [],
    "external_verdicts": []
  },
  "integrity": {
    "chain_hash": "sha256-hex",
    "signature_status": "verified | pending | failed"
  }
}
```

The `external_verdicts` collection preserves third-party evidentiary artifacts in their original form. SEILX stores these artifacts as received and associates them with bundle-level integrity metadata without altering the originating payload.

```json
{
  "source": "RTK-1",
  "received_at": "ISO-8601",
  "verification_status": "verified | failed | pending",
  "payload_hash": "sha256-hex",
  "raw_payload_ref": "object-reference"
}
```

---

## §4 — Verification Procedure

SEILX performs verification at two levels:

- bundle-level integrity verification
- external evidentiary artifact verification

### 4.1 Bundle Integrity Verification

1. Load the `.seilx` bundle
2. Recompute integrity hashes over the canonicalized bundle components:
   - `decision_context`
   - `evidence.t0_state`
   - `evidence.execution_trace`
   - `evidence.overrides`
3. Compare the computed result against `integrity.chain_hash`
4. If integrity verification fails, bundle status is set to `INVALID`

### 4.2 External Verdict Verification

For each entry in `external_verdicts`:

1. Resolve the referenced payload object
2. Compute SHA-256 over the canonicalized payload
3. Compare the computed hash against `payload_hash`
4. Where signature material is available, validate the originating signature
5. Record verification outcome as `verified`, `failed`, or `pending`

Verification discrepancies must be surfaced explicitly and preserved within the evidence record.

### 4.3 Failure Semantics

Verification failures are never silently ignored or rewritten.

A failed external verdict does not automatically invalidate the entire `.seilx` bundle. Instead, verification state is preserved at the artifact level and exposed to downstream reviewers, auditors, or verification systems.

Bundle-level integrity failure results in overall bundle status `INVALID`.

---

## §5 — Handoff Format

SEILX receives RTK-1 evidence artifacts in batch delivery mode during the pilot engagement. This section defines the expected delivery structure and ingestion behavior.

### 5.1 RTK-1 → SEILX Delivery Payload

SEILX expects the following payload structure at ingestion time:

```json
{
  "submission_id": "uuid-v4",
  "status": "completed | failed | timeout",
  "evidence_ref": "object-reference",
  "signed_report_ref": "object-reference",
  "delivered_at": "ISO-8601"
}
```

The referenced evidence artifact is preserved within `external_verdicts` without modification.

Companion artifacts, including signed reports or PDFs, are preserved as associated evidentiary references and are not interpreted or rewritten by SEILX.

### 5.2 Ingestion Failure Behavior

If payload status is not `completed`, SEILX does not compose the external verdict into the `.seilx` bundle.

The ingestion attempt is recorded and surfaced for operational review. Partial ingestion or silent recovery behavior is not performed automatically.

### 5.3 Post-Pilot Transport Evolution

Real-time or synchronous API transport is outside pilot scope.

The evidence structures defined in §3 are intended to remain transport-agnostic such that future transport evolution does not require changes to evidentiary semantics or verification behavior.

---

## §6 — Verification States and Output Semantics

SEILX records verification state at both bundle level and external artifact level. Bundle status and artifact status are reported separately to preserve forensic clarity.

### 6.1 Bundle-Level States

| State     | Meaning                                                                                                                |
|-----------|------------------------------------------------------------------------------------------------------------------------|
| `VALID`   | Bundle-level integrity verified. No bundle integrity violations detected.                                              |
| `INVALID` | Bundle-level integrity verification failed. The bundle cannot be treated as integrity-confirmed.                       |
| `PARTIAL` | Bundle-level integrity verified, but one or more external evidentiary artifacts remain failed, pending, or unresolved. |

### 6.2 External Artifact States

| State          | Meaning                                                                                               |
|----------------|-------------------------------------------------------------------------------------------------------|
| `verified`     | Payload hash matches and originating signature validation succeeded where signature material is available. |
| `failed`       | Payload hash mismatch, invalid signature, or integrity discrepancy detected.                          |
| `pending`      | Payload hash matches, but required signature material or key resolution is not yet available.         |
| `unverifiable` | Payload reference cannot be resolved or required evidence material is unavailable.                    |

### 6.3 Verification Output Record

Verification output is produced as a structured record associated with the `.seilx` bundle.

```json
{
  "bundle_id": "uuid-v4",
  "verified_at": "ISO-8601",
  "bundle_status": "VALID | INVALID | PARTIAL",
  "external_artifact_states": [
    {
      "source": "RTK-1",
      "verification_status": "verified | failed | pending | unverifiable",
      "payload_hash": "sha256-hex",
      "detail": "string"
    }
  ]
}
```

---

## §7 — Trust Boundary Statement

RTK-1 establishes evidence regarding whether an AI system's boundary held under adversarial conditions at test-time.

SEILX establishes evidence regarding what can be independently verified about the execution-fixed state of a system at the moment a decision was produced.

These are different evidentiary questions. The composed bundle carries both answers as cryptographically distinct artifacts, without either party inspecting or re-deriving the other's output.

SEILX does not grade RTK-1 evidence. RTK-1 does not compose SEILX bundles. Each layer is authoritative over its own evidentiary scope. The boundary between them is structural, not adversarial.

---

*This specification is intentionally narrow: it defines only the integration boundary, not either party's internal architecture.*

*SEILX Group OÜ — Confidential / Pre-pilot draft — For RTK Security Labs partnership reference only*
