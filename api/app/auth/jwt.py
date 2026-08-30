"""
JWT RS256 — NIST IA-2, SC-12
Access 15m, Refresh 7d with rotation (jti).
"""
from __future__ import annotations
import time, uuid, json
from typing import Optional
from jose import jwt, JWTError
from ..utils.crypto import load_private_key_pem, load_public_key_pem

ALG = "RS256"
ACCESS_EXPIRE = 15*60
REFRESH_EXPIRE = 7*24*3600

# In-memory revoke & refresh store (prod: Redis)
_revoked_jti: set[str] = set()
_refresh_store: dict[str, dict] = {}  # refresh_jti -> {username, exp}

def create_access_token(username: str, role: str) -> str:
    now = int(time.time())
    jti = str(uuid.uuid4())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + ACCESS_EXPIRE,
        "jti": jti,
        "type": "access",
    }
    return jwt.encode(payload, load_private_key_pem(), algorithm=ALG)

def create_refresh_token(username: str) -> str:
    now = int(time.time())
    jti = str(uuid.uuid4())
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + REFRESH_EXPIRE,
        "jti": jti,
        "type": "refresh",
    }
    token = jwt.encode(payload, load_private_key_pem(), algorithm=ALG)
    _refresh_store[jti] = {"username": username, "exp": now+REFRESH_EXPIRE}
    return token

def verify_token(token: str, expected_type: str="access") -> Optional[dict]:
    try:
        payload = jwt.decode(token, load_public_key_pem(), algorithms=[ALG])
        if payload.get("type") != expected_type:
            return None
        if payload.get("jti") in _revoked_jti:
            return None
        if expected_type=="refresh" and payload.get("jti") not in _refresh_store:
            return None
        return payload
    except JWTError:
        return None

def revoke_jti(jti: str):
    _revoked_jti.add(jti)

def rotate_refresh(old_jti: str, username: str) -> Optional[str]:
    if old_jti not in _refresh_store:
        return None
    # revoke old
    _refresh_store.pop(old_jti, None)
    revoke_jti(old_jti)
    return create_refresh_token(username)

def revoke_refresh(jti: str):
    _refresh_store.pop(jti, None)
    revoke_jti(jti)
