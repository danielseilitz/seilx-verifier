
import pathlib

f = pathlib.Path('seilx_verify.py')
txt = f.read_text(encoding='utf-8')

old = '''    hash_chain = compute_hash_chain(bundle)
    signature = sign_bundle(hash_chain)

    raw_data["integrity"]["hash_chain"] = hash_chain
    raw_data["integrity"]["signature"] = signature'''

new = '''    computed = compute_hash_chain(bundle)
    stored = bundle.integrity.hash_chain
    if computed != stored:
        console.print(f"[bold red]SIGNING REFUSED:[/bold red] Hash chain integrity check failed.")
        console.print(f"  Stored:   {stored}")
        console.print(f"  Computed: {computed}")
        console.print("[bold red]This bundle has been tampered with and cannot be signed.[/bold red]")
        raise typer.Exit(code=1)

    signature = sign_bundle(computed)
    raw_data["integrity"]["signature"] = signature'''

if old in txt:
    f.write_text(txt.replace(old, new), encoding='utf-8')
    print("DONE - patch applied successfully")
else:
    print("NOT FOUND - could not locate target code")
    print(repr(txt[txt.find('hash_chain = compute'):txt.find('hash_chain = compute')+200]))