"""
UserRepository — Implementación File + Memory (AC-2)
Patrón Repository con persistencia JSON (WAL simulado). En prod → Postgres.
"""
from __future__ import annotations
import json, pathlib, time, threading
from typing import Optional, List, Dict
from .interfaces import IUserRepository

STORE_PATH = pathlib.Path(__file__).parent.parent.parent / "infra" / "users.json"

class FileUserRepository(IUserRepository):
    def __init__(self, store_path: pathlib.Path = STORE_PATH):
        self.store_path = store_path
        self._lock = threading.RLock()
        self._users: Dict[str, Dict] = {}
        self._load()

    def _load(self):
        if self.store_path.exists():
            try:
                self._users = json.loads(self.store_path.read_text())
            except Exception:
                self._users = {}
        # no bootstrap here — service se encarga

    def _persist(self):
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self.store_path.write_text(json.dumps(self._users, indent=2))
            self.store_path.chmod(0o600)

    def get_by_username(self, username: str) -> Optional[Dict]:
        with self._lock:
            return self._users.get(username)

    def list_all(self) -> List[Dict]:
        with self._lock:
            return list(self._users.values())

    def create(self, username: str, password_hash: str, role: str) -> Dict:
        with self._lock:
            if username in self._users:
                raise ValueError("user_exists")
            rec = {
                "username": username,
                "password_hash": password_hash,
                "role": role,
                "mfa_secret": None,
                "mfa_enabled": False,
                "backup_codes": [],
                "active": True,
                "created_at": time.time(),
                "last_login": None,
                "failed_attempts": [],
                "locked_until": 0,
            }
            self._users[username] = rec
            self._persist()
            return rec

    def update(self, username: str, **fields) -> Dict:
        with self._lock:
            if username not in self._users:
                raise KeyError("user_not_found")
            self._users[username].update(fields)
            self._persist()
            return self._users[username]

    def exists(self, username: str) -> bool:
        with self._lock:
            return username in self._users

    def set_last_login(self, username: str) -> None:
        with self._lock:
            if username in self._users:
                self._users[username]["last_login"] = time.time()
                self._persist()

    # helpers para bootstrap testing
    def seed_if_empty(self, seed_fn):
        with self._lock:
            if not self._users:
                seed_fn(self)

# Singleton default
_default_repo: Optional[FileUserRepository] = None

def get_user_repository() -> FileUserRepository:
    global _default_repo
    if _default_repo is None:
        _default_repo = FileUserRepository()
    return _default_repo
