"""
SEILX Crypto-Agility Patch
Lägger till ECDSA P-256 som andra signatur i seilx_verify.py
Kör: python patch_crypto_agility.py
"""

import sys
import os

VERIFY_FILE = os.path.join(os.path.dirname(__file__), "seilx_verify.py")

# Läs originalfilen
with open(VERIFY_FILE, "r", encoding="utf-8") as f:
    content = f.read()

# Backup
with open(VERIFY_FILE + ".bak", "w", encoding="utf-8") as f:
    f.write(content)
print("Backup skapad: seilx_verify.py.bak")

# PATCH 1: Lägg till ECDSA-imports efter befintliga crypto-imports
OLD_IMPORTS = "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey"
NEW_IMPORTS = """from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes"""

if OLD_IMPORTS in content:
    content = content.replace(OLD_IMPORTS, NEW_IMPORTS)
    print("PATCH 1 OK: ECDSA imports tillagda")
else:
    print("PATCH 1 SKIP: imports redan tillagda eller annan struktur")

# PATCH 2: Lägg till ECDSA nyckelhantering efter KEY_ID-raden
OLD_KEY_SECTION = 'KEY_ID = "seilx-test-2026-05"'
NEW_KEY_SECTION = '''KEY_ID = "seilx-test-2026-05"

# ECDSA P-256 key files (crypto-agility)
ECDSA_PRIVATE_KEY_FILE = KEY_DIR / "seilx_test_ecdsa_private.pem"
ECDSA_PUBLIC_KEY_FILE = KEY_DIR / "seilx_test_ecdsa_public.pem"

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
        return {"verified": False, "status": "ERROR", "reason": str(e)}'''

if OLD_KEY_SECTION in content:
    content = content.replace(OLD_KEY_SECTION, NEW_KEY_SECTION)
    print("PATCH 2 OK: ECDSA nyckelhantering tillagd")
else:
    print("PATCH 2 SKIP: KEY_ID-rad ej hittad")

# PATCH 3: Lägg till signature_ecdsa i Integrity-modellen
OLD_INTEGRITY = """class Integrity(BaseModel):
    hash_chain: str
    signature: str"""
NEW_INTEGRITY = """class Integrity(BaseModel):
    hash_chain: str
    signature: str
    signature_ecdsa: str = \"\""""

if OLD_INTEGRITY in content:
    content = content.replace(OLD_INTEGRITY, NEW_INTEGRITY)
    print("PATCH 3 OK: signature_ecdsa tillagd i Integrity-modellen")
else:
    print("PATCH 3 SKIP: Integrity-klass ej hittad")

# PATCH 4: Uppdatera verify-kommandot att köra båda signaturer
OLD_SIG_RESULT = "sig_result = verify_signature(bundle)"
NEW_SIG_RESULT = """sig_result = verify_signature(bundle)
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
    console.print(f"[bold]Crypto-Agility:[/bold] {crypto_verdict} (Ed25519: {sig_result['status']} | ECDSA P-256: {ecdsa_result['status']})")"""

if OLD_SIG_RESULT in content:
    content = content.replace(OLD_SIG_RESULT, NEW_SIG_RESULT)
    print("PATCH 4 OK: Dual-signature verdict tillagd i verify-kommandot")
else:
    print("PATCH 4 SKIP: sig_result-rad ej hittad")

# Skriv patched fil
with open(VERIFY_FILE, "w", encoding="utf-8") as f:
    f.write(content)

print("\nKLART. seilx_verify.py uppdaterad med Crypto-Agility.")
print("Backup finns i seilx_verify.py.bak om något gick fel.")