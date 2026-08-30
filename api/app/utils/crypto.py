"""
Crypto helpers — NIST SP 800-63B, SC-12
- argon2id for passwords (OWASP)
- RS256 JWT keys
"""
from __future__ import annotations
import secrets, pathlib, base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEYS_DIR = pathlib.Path(__file__).parent.parent.parent.parent / "infra" / "keys"
KEYS_DIR.mkdir(parents=True, exist_ok=True)
PRIVATE_KEY_PATH = KEYS_DIR / "jwt_rs256.key"
PUBLIC_KEY_PATH = KEYS_DIR / "jwt_rs256.pub"

def ensure_keys():
    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PRIVATE_KEY_PATH.write_bytes(priv_pem)
    PUBLIC_KEY_PATH.write_bytes(pub_pem)
    PRIVATE_KEY_PATH.chmod(0o600)

def load_private_key_pem() -> str:
    ensure_keys()
    return PRIVATE_KEY_PATH.read_text()

def load_public_key_pem() -> str:
    ensure_keys()
    return PUBLIC_KEY_PATH.read_text()

def generate_backup_codes(n=8) -> list[str]:
    return [secrets.token_urlsafe(6)[:8].upper() for _ in range(n)]
