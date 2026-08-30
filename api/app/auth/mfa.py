"""
MFA TOTP RFC6238 — NIST IA-2(1), SP 800-63B AAL2
"""
from __future__ import annotations
import pyotp, qrcode, io, base64
from typing import Dict

def generate_secret() -> str:
    return pyotp.random_base32()

def otpauth_url(secret: str, username: str, issuer: str="MiniSOC") -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)

def verify_totp(secret: str, code: str, valid_window: int=1) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=valid_window)

def qr_base64(otpauth_url: str) -> str:
    img = qrcode.make(otpauth_url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()
