"""
Normalize logs to ECS-like schema for correlation
"""
from __future__ import annotations
import json

def normalize(raw: dict) -> dict:
    # Already structured, but ensure fields
    return {
        "timestamp": raw.get("timestamp"),
        "event_id": raw.get("event_id"),
        "svc": raw.get("svc","unknown"),
        "src_ip": raw.get("src_ip"),
        "actor": raw.get("actor"),
        "role": raw.get("role"),
        "action": raw.get("action"),
        "object": raw.get("object"),
        "result": raw.get("result"),
        "status_code": raw.get("status_code"),
        "mitre_technique": raw.get("mitre_technique"),
        "user_agent": raw.get("user_agent"),
        "raw": raw,
    }
