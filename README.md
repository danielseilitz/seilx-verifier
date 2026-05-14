# SEILX Verifier

CLI tool for verifying .seilx evidence bundles.

## What it does

- Validates bundle structure (Pydantic)
- Verifies hash chain (SHA-256)
- Detects manipulation
- Produces JSON output (.verified.json)

## Install

    pip install -r requirements.txt

## Usage

    python seilx_verify.py verify examples/sample-bundle.seilx
    python seilx_verify.py verify --verbose examples/sample-bundle.seilx

## Status

- Structure validation: implemented
- Hash chain verification: implemented
- Signature verification: pending
