"""
AuditRepository — AU-2, AU-9
Escritura JSONL con hash-chain. Separado de middleware para inyección.
"""
from __future__ import annotations
import json, pathlib, time, uuid, os
from typing import List, Dict
from .interfaces import IAuditRepository
from ..utils.hash_chain import next_hash, canonical

class FileAuditRepository(IAuditRepository):
    def __init__(self, log_paths: list[pathlib.Path] | None = None):
        base = pathlib.Path(__file__).parent.parent.parent.parent
        self.primary = base / "logs" / "siem.jsonl"
        self.alternates = [pathlib.Path("/tmp/soc_siem.jsonl"), pathlib.Path.cwd() / "logs" / "siem.jsonl"]
        if log_paths:
            self.primary = log_paths[0]
            self.alternates = log_paths[1:]

    def emit(self, event: Dict) -> str:
        event.setdefault("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        event.setdefault("event_id", str(uuid.uuid4()))
        event.setdefault("svc", "api")
        canon = canonical(event)
        h = next_hash(canon)
        event["hash"] = h
        line = json.dumps(event, ensure_ascii=False)
        for p in [self.primary] + self.alternates:
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                with open(p, "a", encoding="utf-8") as f:
                    f.write(line+"\n")
                    f.flush()
                    try: os.fsync(f.fileno())
                    except: pass
            except: pass
        return h

    def search(self, query: str, limit: int=50) -> List[Dict]:
        q = query.lower()
        results=[]
        for p in [self.primary] + self.alternates:
            if not p.exists(): continue
            for line in p.read_text().splitlines()[-1000:]:
                try:
                    e=json.loads(line)
                    if not q or q in json.dumps(e).lower():
                        results.append(e)
                except: continue
        return results[-limit:]

_default: FileAuditRepository | None = None
def get_audit_repository() -> FileAuditRepository:
    global _default
    if _default is None:
        _default = FileAuditRepository()
    return _default
