"""
Repository Pattern — Interfaces (Ports)
NIST SP 800-53 CM-14, Clean Architecture
Define contratos de persistencia. Implementaciones inyectables.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Protocol

class IUserRepository(ABC):
    """AC-2, IA-2 — Gestión de identidades"""
    @abstractmethod
    def get_by_username(self, username: str) -> Optional[Dict]: ...

    @abstractmethod
    def list_all(self) -> List[Dict]: ...

    @abstractmethod
    def create(self, username: str, password_hash: str, role: str) -> Dict: ...

    @abstractmethod
    def update(self, username: str, **fields) -> Dict: ...

    @abstractmethod
    def exists(self, username: str) -> bool: ...

    @abstractmethod
    def set_last_login(self, username: str) -> None: ...

class IRecordRepository(ABC):
    """AC-3, AU-3 — Recurso protegido con ownership"""
    @abstractmethod
    def create(self, title: str, value: int, note: Optional[str], owner: str) -> Dict: ...

    @abstractmethod
    def get(self, record_id: int) -> Optional[Dict]: ...

    @abstractmethod
    def list(self, owner_filter: Optional[str]=None) -> List[Dict]: ...

    @abstractmethod
    def update(self, record_id: int, **fields) -> Dict: ...

    @abstractmethod
    def delete(self, record_id: int) -> None: ...

class IAuditRepository(ABC):
    """AU-2, AU-3, AU-9 — Hash-chain + WORM"""
    @abstractmethod
    def emit(self, event: Dict) -> str:  # returns hash
        ...

    @abstractmethod
    def search(self, query: str, limit: int=50) -> List[Dict]: ...
