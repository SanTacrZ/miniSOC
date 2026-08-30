"""
In-memory records store — AC-3 ownership check demo
Replace with DB in prod (SC-28)
"""
from __future__ import annotations
import time, threading
from typing import Dict, Optional

# record: {id, title, value, note, owner, created_at}
_records: Dict[int, dict] = {}
_next_id = 1
_lock = threading.Lock()

def create_record(title: str, value: int, note: Optional[str], owner: str) -> dict:
    global _next_id
    with _lock:
        rid = _next_id
        _next_id += 1
        rec = {"id": rid, "title": title, "value": value, "note": note, "owner": owner, "created_at": time.time()}
        _records[rid] = rec
        return rec

def get_record(rid: int) -> Optional[dict]:
    return _records.get(rid)

def list_records(owner_filter: Optional[str]=None) -> list[dict]:
    if owner_filter:
        return [r for r in _records.values() if r["owner"]==owner_filter]
    return list(_records.values())

def update_record(rid: int, **kwargs):
    if rid not in _records:
        raise KeyError("not found")
    _records[rid].update(kwargs)
    return _records[rid]

def delete_record(rid: int):
    if rid not in _records:
        raise KeyError("not found")
    del _records[rid]
