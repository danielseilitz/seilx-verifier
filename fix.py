#!/usr/bin/env python3
"""
SEILX Verifier CLI
Verifierar .seilx evidence bundles för manipulation och integritet.
"""

import typer
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from pydantic import BaseModel, ValidationError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import base64

app = typer.Typer(help="SEILX Evidence Bundle Verifier")
console = Console()

KEY_DIR = Path(__file__).parent / "test_keys"
PRIVATE_KEY_FILE = KEY_DIR / "seilx_test_private.pem"
PUBLIC_KEY_FILE = KEY_DIR / "seilx_test_public.pem"
KEY_ID = "seilx-test-2026-05"

# ECDSA P-256 key files (crypto-agility)
ECDSA_PRIVATE_KEY_FILE = KEY_DIR / "seilx_test_ecdsa_private.pem"
ECDSA_PUBLIC_KEY_FILE = KEY_DIR / "seilx_test_ecdsa_public.pem"


# --- Key management ---

def ensure_test_keys():
    """Generate test key pair if not present."""
    KEY_DIR.mkdir(exist_ok=True)
    if not PRIVATE_KEY_FILE.exists():
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        PRIVATE_KEY_FILE.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        PUBLIC_KEY_FILE.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def ensure_ecdsa_keys():
    """Generate ECDSA P-256 test key pair if not present."""
    KEY_DIR.mkdir(exist_ok=True)
    if not ECDSA_PRIVATE_KEY_FILE.exists():
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        ECDSA_PRIVATE_KEY_FILE.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        ECDSA_PUBLIC_KEY_FILE.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def load_public_key() -> Ed25519PublicKey:
    ensure_test_keys()
    return serialization.load_pem_public_key(PUBLIC_KEY_FILE.read_bytes())

def load_private_key() -> Ed25519PrivateKey:
    ensure_test_keys()
    return serialization.load_pem_private_key(PRIVATE_KEY_FILE.read_bytes(), password=None)

def load_ecdsa_public_key():
    ensure_ecdsa_keys()
    return serialization.load_pem_public_key(ECDSA_PUBLIC_KEY_FILE.read_bytes())

def load_ecdsa_private_key():
    ensure_ecdsa_keys()
    return serialization.load_pem_private_key(ECDSA_PRIVATE_KEY_FILE.read_bytes(), password=None)

def sign_ecdsa(hash_chain: str) -> str:
    """Sign hash chain with ECDSA P-256."""
    private_key = load_ecdsa_private_key()
    sig = private_key.sign(hash_chain.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode("utf-8")

def verify_ecdsa_signature(bundle) -> dict:
    """Verify ECDSA P-256 signature against bundle hash chain."""
    sig_value = getattr(bundle.integrity, "signature_ecdsa", None)
    if not sig_value:
        return {"verified": False, "status": "MISSING", "reason": "No ECDSA signature in bundle"}
    try:
        public_key = load_ecdsa_public_key()
        sig_bytes = base64.b64decode(sig_value)
        hash_chain = bundle.integrity.hash_chain
        public_key.verify(sig_bytes, hash_chain.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return {"verified": True, "status": "VERIFIED", "reason": "ECDSA P-256 signature valid"}
    except InvalidSignature:
        return {"verified": False, "status": "INVALID", "reason": "ECDSA signature failed"}
    except Exception as e:
        return {"verified": False, "status": "ERROR", "reason": str(e)}


# --- Data models ---

class DecisionOutput(BaseModel):
    verdict: str
    amount: Optional[float] = None
    currency: Optional[str] = None

class Decision(BaseModel):
    type: str
    timestamp: str
    input_hash: str
    output: DecisionOutput

class T0State(BaseModel):
    policy_version: str
    model_version: str
    input_data: Dict[str, Any]

class ExecutionStep(BaseModel):
    step: int
    action: str
    timestamp: str
    metadata: Optional[Dict[str, Any]] = None

class Evidence(BaseModel):
    t0_state: T0State
    execution_trace: list[ExecutionStep]
    overrides: list[Dict[str, Any]] = []

class Integrity(BaseModel):
    hash_chain: str
    signature: str
    signature_ecdsa: str = ""

class SeilxBundle(BaseModel):
    version: str = "0.1.0"
    id: str
    created_at: str
    decision: Decision
    evidence: Evidence
    integrity: Integrity


# --- Core functions ---

def compute_hash_chain(bundle: SeilxBundle) -> str:
    hasher = hashlib.sha256()
    t0_str = json.dumps({
        "policy_version": bundle.evidence.t0_state.policy_version,
        "model_version": bundle.evidence.t0_state.model_version,
        "input_data": bundle.evidence.t0_state.input_data
    }, sort_keys=True)
    hasher.update(t0_str.encode('utf-8'))
    for step in bundle.evidence.execution_trace:
        step_str = json.dumps({
            "step": step.step,
            "action": step.action,
            "timestamp": step.timestamp
        }, sort_keys=True)
        hasher.update(step_str.encode('utf-8'))
    return f"sha256:{hasher.hexdigest()}"


def sign_bundle(hash_chain: str) -> str:
    """Sign the hash chain with the test private key."""
    private_key = load_private_key()
    signature_bytes = private_key.sign(hash_chain.encode('utf-8'))
    return base64.b64encode(signature_bytes).decode('utf-8')


def verify_signature(bundle: SeilxBundle) -> dict:
    """Verify Ed25519 signature against bundle hash chain."""
    sig_value = bundle.integrity.signature

    # Handle legacy placeholder signatures
    if sig_value.startswith("ecdsa:") or sig_value == "pending":
        return {
            "verified": False,
            "status": "FATAL_CHAIN_BREACH",
            "key_id": KEY_ID,
            "reason": "Legacy placeholder signature — re-sign bundle with: py seilx_verify.py sign <file>",
            "recoverable": False, "required_action": "REGENERATE_FROM_ORIGIN_RUNTIME"
        }

    try:
        public_key = load_public_key()
        sig_bytes = base64.b64decode(sig_value)
        hash_chain = bundle.integrity.hash_chain
        public_key.verify(sig_bytes, hash_chain.encode('utf-8'))
        return {
            "verified": True,
            "status": "VERIFIED",
            "key_id": KEY_ID,
            "reason": "Ed25519 signature valid",
            "implementation_note": f"Signature verified against {KEY_ID} public key"
        }
    except InvalidSignature:
        return {
            "verified": False,
            "status": "INVALID",
            "key_id": KEY_ID,
            "reason": "Signature verification failed — bundle may be tampered",
            "implementation_note": "Signature does not match hash chain"
        }
    except Exception as e:
        return {
            "verified": False,
            "status": "ERROR",
            "key_id": KEY_ID,
            "reason": f"Signature verification error: {e}",
            "implementation_note": "Check key files in test_keys/"
        }


# --- CLI commands ---

@app.command()
def verify(
    file: Path = typer.Argument(..., help="Path to .seilx bundle file"),
    pubkey: Optional[Path] = typer.Option(None, "--pubkey", help="Path to external public key PEM file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Detailed output")
):
    """Verify a .seilx evidence bundle."""
    console.print(f"[bold blue]SEILX Verifier v0.1.0[/bold blue]")
    console.print(f"Loading bundle: {file}\n")

    if not file.exists():
        console.print(f"[bold red]ERROR:[/bold red] File not found: {file}")
        raise typer.Exit(code=1)

    try:
        raw_data = json.loads(file.read_text(encoding='utf-8'))
    except json.JSONDecodeError as e:
        console.print(f"[bold red]ERROR:[/bold red] Invalid JSON: {e}")
        raise typer.Exit(code=1)

    try:
        bundle = SeilxBundle(**raw_data)
        console.print("[green]✓[/green] Structure validation: [bold green]PASSED[/bold green]")
        structure_ok = True
    except ValidationError as e:
        console.print(f"[bold red]✗[/bold red] Structure validation: FAILED[/bold red]")
        if verbose:
            for error in e.errors():
                console.print(f"  — {error['loc']}: {error['msg']}")
        raise typer.Exit(code=1)

    computed = compute_hash_chain(bundle)
    stored = bundle.integrity.hash_chain
    if computed == stored:
        console.print("[green]✓[/green] Hash chain verification: [bold green]PASSED[/bold green]")
        hash_ok = True
    else:
        console.print("[red]✗[/red] Hash chain verification: [bold red]FAILED — MANIPULATION DETECTED[/bold red]")
        if verbose:
            console.print(f"  Stored:   {stored}")
            console.print(f"  Computed: {computed}")
        hash_ok = False

    sig_result = verify_signature(bundle)
    ecdsa_result = verify_ecdsa_signature(bundle)

    # Crypto-agility verdict
    ed_ok = sig_result["status"] == "VERIFIED"
    ec_ok = ecdsa_result["status"] == "VERIFIED"
    if ed_ok and ec_ok:
        crypto_verdict = "DUAL VERIFIED"
    elif ed_ok or ec_ok:
        crypto_verdict = "PARTIAL VALIDITY"
    else:
        crypto_verdict = "UNVERIFIED"
    console.print(f"[bold]Crypto-Agility:[/bold] {crypto_verdict} (Ed25519: {sig_result['status']} | ECDSA P-256: {ecdsa_result['status']})")

    if sig_result["status"] == "VERIFIED":
        sig_icon = "[green]✓[/green]"
        sig_color = "green"
    elif sig_result["status"] == "PENDING":
        sig_icon = "[yellow]◎[/yellow]"
        sig_color = "yellow"
    else:
        sig_icon = "[red]✗[/red]"
        sig_color = "red"

    console.print(f"{sig_icon} Signature verification: [bold {sig_color}]{sig_result['status']}[/bold {sig_color}]")
    if verbose:
        console.print(f"  Key ID: {sig_result.get('key_id', 'unknown')}")
        console.print(f"  Reason: {sig_result['reason']}")

    status = "VALID" if (structure_ok and hash_ok) else "INVALID"

    result = {
        "status": status,
        "bundle_id": bundle.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "key_id": sig_result.get("key_id", KEY_ID),
        "checks": {
            "structure": structure_ok,
            "hashes": hash_ok,
            "signatures": sig_result["verified"]
        },
        "signature_status": sig_result,
    }

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Details", style="white")
    table.add_row("Structure", "[green]✓ PASSED[/green]", "All required fields present")
    table.add_row("Hash Chain",
                  "[green]✓ PASSED[/green]" if hash_ok else "[red]✗ FAILED[/red]",
                  "Integrity verified" if hash_ok else "MANIPULATION DETECTED")
    if sig_result["status"] == "VERIFIED":
        sig_display = f"[green]✓ {sig_result['status']}[/green]"
        sig_detail = f"Ed25519 — key: {KEY_ID}"
    elif sig_result["status"] == "PENDING":
        sig_display = f"[yellow]◎ {sig_result['status']}[/yellow]"
        sig_detail = "Re-sign with: py seilx_verify.py sign <file>"
    else:
        sig_display = f"[red]✗ {sig_result['status']}[/red]"
        sig_detail = sig_result["reason"]
    table.add_row("Signature", sig_display, sig_detail)

    console.print("\n[bold]Verification Result:[/bold]")
    console.print(table)
    console.print("\n[bold]JSON Output:[/bold]")
    console.print(json.dumps(result, indent=2))

    output_file = file.with_suffix('.verified.json')
    output_file.write_text(json.dumps(result, indent=2), encoding='utf-8')
    console.print(f"\n[dim]Result saved to: {output_file}[/dim]")


@app.command()
def sign(
    file: Path = typer.Argument(..., help="Path to .seilx bundle file to sign")
):
    """Sign a .seilx bundle with the test key."""
    console.print(f"[bold blue]SEILX Signer v0.1.0[/bold blue]")
    console.print(f"Signing bundle: {file}\n")

    if not file.exists():
        console.print(f"[bold red]ERROR:[/bold red] File not found: {file}")
        raise typer.Exit(code=1)

    try:
        raw_data = json.loads(file.read_text(encoding='utf-8'))
        bundle = SeilxBundle(**raw_data)
    except Exception as e:
        console.print(f"[bold red]ERROR:[/bold red] {e}")
        raise typer.Exit(code=1)

    computed = compute_hash_chain(bundle)
    stored = bundle.integrity.hash_chain
    if computed != stored:
        console.print(f"[bold red]SIGNING REFUSED:[/bold red] Hash chain integrity check failed.")
        console.print(f"  Stored:   {stored}")
        console.print(f"  Computed: {computed}")
        console.print("[bold red]This bundle has been tampered with and cannot be signed.[/bold red]")
        raise typer.Exit(code=1)

    signature = sign_bundle(computed)
    raw_data["integrity"]["signature"] = signature
    ecdsa_sig = sign_ecdsa(computed)
    raw_data["integrity"]["signature_ecdsa"] = ecdsa_sig

    file.write_text(json.dumps(raw_data, indent=2), encoding='utf-8')
    console.print(f"[green]✓[/green] Bundle signed with key: [bold]{KEY_ID}[/bold]")
    console.print(f"[green]✓[/green] Hash chain: {computed[:40]}...")
    console.print(f"[green]✓[/green] Ed25519 + ECDSA P-256 signatures written to: {file}")


@app.command()
def info():
    """Show verifier information."""
    console.print("[bold blue]SEILX Verifier[/bold blue] v0.1.0")
    console.print("Checks: structure, hash chain, signature (Ed25519 + ECDSA P-256)")
    console.print(f"Key ID: {KEY_ID}")
    ensure_test_keys()
    console.print(f"Public key: {PUBLIC_KEY_FILE}")


if __name__ == "__main__":
    app()