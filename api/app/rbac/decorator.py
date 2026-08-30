"""
RBAC decorator — AC-3 Enforcement, AC-6 Least Privilege
"""
from __future__ import annotations
import pathlib, yaml
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from ..auth.jwt import verify_token
from ..auth.user_store import get_user

_ROLES_PATH = pathlib.Path(__file__).parent / "roles.yaml"
_roles_cfg = yaml.safe_load(_ROLES_PATH.read_text())

bearer = HTTPBearer(auto_error=False)

def _permissions_for_role(role: str) -> set[str]:
    cfg = _roles_cfg["roles"].get(role, {})
    return set(cfg.get("permissions", []))

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing token")
    payload = verify_token(credentials.credentials, "access")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = get_user(payload["sub"])
    if not user or not user.get("active"):
        raise HTTPException(status_code=401, detail="User inactive")
    # Check MFA required for role
    role = payload.get("role")
    role_cfg = _roles_cfg["roles"].get(role, {})
    if role_cfg.get("mfa_required") and not user.get("mfa_enabled"):
        raise HTTPException(status_code=403, detail="MFA required for role")
    return {"username": payload["sub"], "role": role, "jti": payload["jti"], "payload": payload}

def require_permission(permission: str):
    def dep(current = Depends(get_current_user)):
        perms = _permissions_for_role(current["role"])
        # admin has all? No, explicit — but check admin perms include all needed via config
        if permission not in perms:
            raise HTTPException(status_code=403, detail=f"Forbidden: need {permission}")
        return current
    return dep

def require_role(*roles: str):
    def dep(current = Depends(get_current_user)):
        if current["role"] not in roles:
            raise HTTPException(status_code=403, detail=f"Forbidden: need role {roles}")
        return current
    return dep
