"""
User store — AC-2, AC-3
In-memory for demo + JSON persistence. Replace with DB in prod (SC-28).
"""
from __future__ import annotations
import json, pathlib, time
from typing import Dict, Optional
from .passwords import hash_password
from ..utils.crypto import ensure_keys

STORE_PATH = pathlib.Path(__file__).parent.parent.parent / "infra" / "users.json"
STORE_PATH.parent.mkdir(parents=True, exist_ok=True)

# In-memory cache
_users: Dict[str, dict] = {}
_failed_attempts: Dict[str, list[float]] = {}
_locked_until: Dict[str, float] = {}

def _load():
    global _users
    if STORE_PATH.exists():
        try:
            _users = json.loads(STORE_PATH.read_text())
        except Exception:
            _users = {}
    if not _users:
        # bootstrap default users (change passwords immediately)
        # These are for initial demo only — will be overwritten by scripts/bootstrap_iam.sh if run
        _users = {
            "admin": {
                "username": "admin",
                "password_hash": hash_password("Admin_Str0ng!_2026"),
                "role": "admin",
                "mfa_secret": None,
                "mfa_enabled": False,
                "backup_codes": [],
                "active": True,
                "created_at": time.time(),
                "last_login": None,
            },
            "analyst": {
                "username": "analyst",
                "password_hash": hash_password("Analyst_Str0ng!_2026"),
                "role": "analyst",
                "mfa_secret": None,
                "mfa_enabled": False,
                "backup_codes": [],
                "active": True,
                "created_at": time.time(),
                "last_login": None,
            },
            "viewer": {
                "username": "viewer",
                "password_hash": hash_password("Viewer_Str0ng!_2026"),
                "role": "viewer",
                "mfa_secret": None,
                "mfa_enabled": False,
                "backup_codes": [],
                "active": True,
                "created_at": time.time(),
                "last_login": None,
            },
        }
        _save()

def _save():
    STORE_PATH.write_text(json.dumps(_users, indent=2))
    STORE_PATH.chmod(0o600)

def ensure_loaded():
    if not _users:
        _load()

def get_user(username: str) -> Optional[dict]:
    ensure_loaded()
    return _users.get(username)

def list_users() -> Dict[str, dict]:
    ensure_loaded()
    return dict(_users)

def create_user(username: str, password: str, role: str) -> dict:
    ensure_loaded()
    if username in _users:
        raise ValueError("user exists")
    if role not in {"viewer","analyst","responder","admin"}:
        raise ValueError("invalid role")
    _users[username] = {
        "username": username,
        "password_hash": hash_password(password),
        "role": role,
        "mfa_secret": None,
        "mfa_enabled": False,
        "backup_codes": [],
        "active": True,
        "created_at": time.time(),
        "last_login": None,
    }
    _save()
    return _users[username]

def update_user(username: str, **kwargs):
    ensure_loaded()
    if username not in _users:
        raise KeyError("not found")
    _users[username].update(kwargs)
    _save()

def record_failed(username: str):
    now = time.time()
    lst = _failed_attempts.get(username, [])
    lst = [t for t in lst if now - t < 900]  # 15m window
    lst.append(now)
    _failed_attempts[username] = lst
    if len(lst) >= 5:
        _locked_until[username] = now + 900

def is_locked(username: str) -> bool:
    until = _locked_until.get(username, 0)
    if time.time() < until:
        return True
    # auto unlock
    if username in _locked_until and time.time() >= until:
        _locked_until.pop(username, None)
        _failed_attempts.pop(username, None)
    return False

def clear_failed(username: str):
    _failed_attempts.pop(username, None)
    _locked_until.pop(username, None)

def set_last_login(username: str):
    ensure_loaded()
    if username in _users:
        _users[username]["last_login"] = time.time()
        _save()
