"""
AuthService — Lógica de negocio (IA-2, IA-5, AC-7)
Desacoplado de FastAPI. Usa repositories inyectados.
Purple-team: testeable sin HTTP.
"""
from __future__ import annotations
import time
from typing import Dict, Optional
from ..repositories.user_repository import FileUserRepository
from ..repositories.audit_repository import FileAuditRepository
from ..auth.passwords import hash_password, verify_password
from ..auth.jwt import create_access_token, create_refresh_token, verify_token, rotate_refresh
from ..auth.mfa import verify_totp

class AuthService:
    def __init__(self, users: FileUserRepository, audit: FileAuditRepository):
        self.users = users
        self.audit = audit
        self._failed: dict[str, list[float]] = {}
        self._locked: dict[str, float] = {}

    def is_locked(self, username: str) -> bool:
        until = self._locked.get(username, 0)
        if time.time() < until:
            return True
        if username in self._locked and time.time() >= until:
            self._locked.pop(username, None)
            self._failed.pop(username, None)
        return False

    def _record_fail(self, username: str):
        now = time.time()
        lst = [t for t in self._failed.get(username, []) if now - t < 900]
        lst.append(now)
        self._failed[username]=lst
        if len(lst) >= 5:
            self._locked[username]= now+900
        # persist in user record too for audit
        u = self.users.get_by_username(username)
        if u:
            try: self.users.update(username, failed_attempts=lst, locked_until=self._locked.get(username,0))
            except: pass

    def _clear_fail(self, username: str):
        self._failed.pop(username, None)
        self._locked.pop(username, None)
        u = self.users.get_by_username(username)
        if u:
            try: self.users.update(username, failed_attempts=[], locked_until=0)
            except: pass

    def authenticate(self, username: str, password: str, src_ip: str, user_agent: str) -> Dict:
        if self.is_locked(username):
            self.audit.emit({"actor": username, "action":"auth_fail", "object":"/auth/login", "result":"fail","reason":"locked","src_ip":src_ip,"user_agent":user_agent,"mitre_technique":"T1110"})
            raise PermissionError("locked")
        user = self.users.get_by_username(username)
        if not user or not user.get("active") or not verify_password(password, user["password_hash"]):
            self._record_fail(username)
            self.audit.emit({"actor": username, "action":"auth_fail", "object":"/auth/login", "result":"fail","src_ip":src_ip,"user_agent":user_agent,"mitre_technique":"T1110"})
            raise ValueError("invalid_credentials")
        # ok
        if user.get("mfa_enabled"):
            self.audit.emit({"actor": username, "action":"auth_mfa_required", "object":"/auth/login", "result":"success","src_ip":src_ip,"user_agent":user_agent})
            return {"mfa_required": True, "user": user}
        self._clear_fail(username)
        self.users.set_last_login(username)
        access = create_access_token(user["username"], user["role"])
        refresh = create_refresh_token(user["username"])
        self.audit.emit({"actor": username, "action":"auth_success", "object":"/auth/login", "result":"success","src_ip":src_ip,"user_agent":user_agent,"role": user["role"]})
        return {"mfa_required": False, "access_token": access, "refresh_token": refresh, "user": user}

    def verify_mfa(self, username: str, code: str, src_ip: str, user_agent: str) -> Dict:
        user = self.users.get_by_username(username)
        if not user or not user.get("mfa_secret"):
            raise ValueError("mfa_not_setup")
        ok = verify_totp(user["mfa_secret"], code)
        # backup codes fallback
        if not ok and code in user.get("backup_codes", []):
            remaining = [c for c in user["backup_codes"] if c != code]
            self.users.update(username, backup_codes=remaining, mfa_enabled=True)
            ok=True
        if not ok:
            self.audit.emit({"actor": username, "action":"auth_mfa_fail", "object":"/auth/mfa/verify", "result":"fail","src_ip":src_ip,"user_agent":user_agent,"mitre_technique":"T1110"})
            raise ValueError("invalid_mfa")
        self.users.update(username, mfa_enabled=True)
        self._clear_fail(username)
        self.users.set_last_login(username)
        access = create_access_token(user["username"], user["role"])
        refresh = create_refresh_token(user["username"])
        self.audit.emit({"actor": username, "action":"auth_mfa_success", "object":"/auth/mfa/verify", "result":"success","src_ip":src_ip,"user_agent":user_agent,"role": user["role"]})
        return {"access_token": access, "refresh_token": refresh, "user": user}

    def refresh(self, refresh_token: str) -> Dict:
        payload = verify_token(refresh_token, "refresh")
        if not payload:
            raise ValueError("invalid_refresh")
        new_refresh = rotate_refresh(payload["jti"], payload["sub"])
        if not new_refresh:
            raise ValueError("revoked")
        user = self.users.get_by_username(payload["sub"])
        if not user:
            raise ValueError("user_gone")
        access = create_access_token(user["username"], user["role"])
        return {"access_token": access, "refresh_token": new_refresh}
