"""
RecordRepository — AC-3, SI-10
In-memory con lock + futura extensión a DB. Patrón Repository.
"""
from __future__ import annotations
import time, threading
from typing import Optional, List, Dict
from .interfaces import IRecordRepository

class InMemoryRecordRepository(IRecordRepository):
    def __init__(self):
        self._records: Dict[int, Dict] = {}
        self._next_id = 1
        self._lock = threading.RLock()

    def create(self, title: str, value: int, note: Optional[str], owner: str) -> Dict:
        with self._lock:
            rid = self._next_id
            self._next_id += 1
            rec = {"id": rid, "title": title, "value": value, "note": note, "owner": owner, "created_at": time.time()}
            self._records[rid] = rec
            return rec

    def get(self, record_id: int) -> Optional[Dict]:
        with self._lock:
            return self._records.get(record_id)

    def list(self, owner_filter: Optional[str]=None) -> List[Dict]:
        with self._lock:
            if owner_filter:
                return [r for r in self._records.values() if r["owner"]==owner_filter]
            return list(self._records.values())

    def update(self, record_id: int, **fields) -> Dict:
        with self._lock:
            if record_id not in self._records:
                raise KeyError("not_found")
            self._records[record_id].update(fields)
            return self._records[record_id]

    def delete(self, record_id: int) -> None:
        with self._lock:
            if record_id not in self._records:
                raise KeyError("not_found")
            del self._records[record_id]

_default: Optional[InMemoryRecordRepository] = None

def get_record_repository() -> InMemoryRecordRepository:
    global _default
    if _default is None:
        _default = InMemoryRecordRepository()
    return _default
