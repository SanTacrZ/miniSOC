"""
RecordService — AC-3, SI-10
Reglas de negocio para records.
"""
from __future__ import annotations
from typing import Optional, List, Dict
from ..repositories.record_repository import InMemoryRecordRepository
from ..repositories.audit_repository import FileAuditRepository

class RecordService:
    def __init__(self, records: InMemoryRecordRepository, audit: FileAuditRepository):
        self.records = records
        self.audit = audit

    def create(self, title: str, value: int, note: Optional[str], owner: str, src_ip: str) -> Dict:
        suspicious = note and any(s in note for s in [";", "$(", "`", "flag", "|"])
        if suspicious:
            self.audit.emit({"actor": owner, "action":"suspicious_note","object":"/records","result":"success","src_ip":src_ip,"note_len": len(note or ""),"mitre_technique":"T1059"})
        return self.records.create(title, value, note, owner)

    def get(self, record_id: int, requester: str, role: str) -> Dict:
        r = self.records.get(record_id)
        if not r:
            raise KeyError("not_found")
        if role=="viewer" and r["owner"]!=requester:
            # AC-3 deny
            self.audit.emit({"actor": requester, "action":"authz_fail","object":f"/records/{record_id}","result":"fail","src_ip":"-","mitre_technique":"T1548"})
            raise PermissionError("forbidden_not_your_record")
        return r

    def list(self, requester: str, role: str, owner_filter: Optional[str]=None) -> List[Dict]:
        if role=="viewer":
            owner_filter = requester
        return self.records.list(owner_filter)
