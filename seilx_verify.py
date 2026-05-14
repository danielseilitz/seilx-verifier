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

app = typer.Typer(help="SEILX Evidence Bundle Verifier")
console = Console()

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

class SeilxBundle(BaseModel):
    version: str = "0.1.0"
    id: str
    created_at: str
    decision: Decision
    evidence: Evidence
    integrity: Integrity


def compute_hash_chain(bundle: SeilxBundle) -> str:
    """Beräknar hash-kedjan från t0_state + execution_trace."""
    hasher = hashlib.sha256()
    
    # Hasha t0_state
    t0_str = json.dumps({
        "policy_version": bundle.evidence.t0_state.policy_version,
        "model_version": bundle.evidence.t0_state.model_version,
        "input_data": bundle.evidence.t0_state.input_data
    }, sort_keys=True)
    hasher.update(t0_str.encode('utf-8'))
    
    # Hasha varje steg i execution_trace
    for step in bundle.evidence.execution_trace:
        step_str = json.dumps({
            "step": step.step,
            "action": step.action,
            "timestamp": step.timestamp
        }, sort_keys=True)
        hasher.update(step_str.encode('utf-8'))
    
    return f"sha256:{hasher.hexdigest()}"


@app.command()
def verify(
    file: Path = typer.Argument(..., help="Path to .seilx bundle file"),
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

    # Struktur-validering
    try:
        bundle = SeilxBundle(**raw_data)
        console.print("[green]✓[/green] Structure validation: [bold green]PASSED[/bold green]")
        structure_ok = True
    except ValidationError as e:
        console.print(f"[bold red]✗ Structure validation: FAILED[/bold red]")
        if verbose:
            for error in e.errors():
                console.print(f"  - {error['loc']}: {error['msg']}")
        raise typer.Exit(code=1)

    # Hash-kedja
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

    # Signatur (placeholder)
    console.print("[yellow]○[/yellow] Signature verification: [bold yellow]PENDING[/bold yellow]")

    status = "VALID" if (structure_ok and hash_ok) else "INVALID"

    result = {
        "status": status,
        "bundle_id": bundle.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {
            "structure": structure_ok,
            "hashes": hash_ok,
            "signatures": False
        },
        "warnings": ["Signature verification not yet implemented"]
    }

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Details", style="white")
    table.add_row("Structure", "[green]✓ PASSED[/green]", "All required fields present")
    table.add_row("Hash Chain", "[green]✓ PASSED[/green]" if hash_ok else "[red]✗ FAILED[/red]", 
                  "Integrity verified" if hash_ok else "MANIPULATION DETECTED")
    table.add_row("Signature", "[yellow]○ PENDING[/yellow]", "Implementation in progress")

    console.print("\n[bold]Verification Result:[/bold]")
    console.print(table)
    console.print("\n[bold]JSON Output:[/bold]")
    console.print(json.dumps(result, indent=2))

    output_file = file.with_suffix('.verified.json')
    output_file.write_text(json.dumps(result, indent=2), encoding='utf-8')
    console.print(f"\n[dim]Result saved to: {output_file}[/dim]")

@app.command()
def info():
    """Show verifier information."""
    console.print("[bold blue]SEILX Verifier[/bold blue] v0.1.0")

if __name__ == "__main__":
    app()