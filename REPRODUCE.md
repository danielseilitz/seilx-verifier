# Reproducing §6 Independent Verification

This document records a specific, reproducible verification result: an
independent verifier implemented by SEILX successfully reproduced the
verification outcome of a publicly available RTK Security Labs evidence
object, from a clean environment with no prior local state.

## What this proves

The SEILX verifier (`rtk_verify.py`), cloned fresh from this repository,
can independently confirm the integrity and authenticity of an RTK-1
evidence object using only:

- the evidence object, fetched from RTK's public URL
- RTK's public signing key, fetched from RTK's public URL
- the verifier code in this repository

No RTK source code, no private channel, and no prior local cache were
used. The verifier recomputed the canonical hash (RFC8785-JCS) and
validated the ECDSA P-256 signature independently.

## What this does not prove

This result confirms the technical verification path works end to end
against one real evidence object. It does not, on its own, establish
market demand, commercial adoption, or category ownership. It is a
technical artifact, not a business outcome.

## Reference commit

Repository: `https://github.com/danielseilitz/seilx-verifier`
Commit: `375a784` — "Add RTK-1 evidence verifier (§6 verification)"

## Reference evidence object

- Evidence ID: `ff47765c-2077-5ca9-a30e-7bb902d8f1b7`
- Source: `https://rtksecuritylabs.com/rtk1_evidence_a58a098c.json`
- Signing key: `https://rtksecuritylabs.com/keys/rtk-key-2026-01.pem`
- Producer: RTK Security Labs
- Verdict: C1 (no unauthorized execution observed)
- Freshness window: valid until 2026-08-29T22:35:26Z

## Steps to reproduce

Run these commands in order, in a new, empty directory:

```bash
git clone https://github.com/danielseilitz/seilx-verifier.git seilx-verifier-clean
cd seilx-verifier-clean

pip install rfc8785 cryptography --break-system-packages

curl -o rtk1_evidence_a58a098c.json https://rtksecuritylabs.com/rtk1_evidence_a58a098c.json
curl -o rtk_pubkey.pem https://rtksecuritylabs.com/keys/rtk-key-2026-01.pem

py rtk_verify.py
```

## Expected output

```
=======================================================
  SEILX §6 VERIFICATION — RTK Evidence Object
=======================================================
  Evidence ID:  ff47765c-2077-5c...
  Producer:     RTK Security Labs
  System:       claude-sonnet-4-6 (production), system class: llm_api
  Valid until:  2026-08-29T22:35:26.284093Z

  §6 RECORD:    VALID
  Detail:       Verdict: C1 — No unauthorized execution observed

  COMPOSITION_INTACT — Evidence verified independently.
```

## Verification log

| Date | Environment | Result | Notes |
|---|---|---|---|
| 2026-06-16 | Clean clone, new directory, fresh dependency install | VALID | First independently reproduced result. RTK URLs returned `200 OK`, no auth required, `access-control-allow-origin: *`. |

## Next steps toward stronger independence

This reproduction was run by the same person who wrote the verifier.
The next levels of independence are:

1. **Third-party operator run** — Ramon (RTK) or another party not
   involved in writing the verifier runs these exact steps on their own
   machine and reports the result.
2. **Unrelated third party** — someone with no relationship to either
   SEILX or RTK downloads the verifier, the evidence object, and the key,
   and reproduces the result independently.

Each level removes one more dependency on trust in the people who built
the system, which is the property this verifier is meant to demonstrate.
