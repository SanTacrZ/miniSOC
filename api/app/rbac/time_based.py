"""
Time-based RBAC — AC-2(3), AC-3 Just-In-Time
Roles temporales (ej: responder solo 4h tras incidente). Ver playbooks.yml.
"""
from __future__ import annotations
import time, json, pathlib

STATE = pathlib.Path("logs/rbac_time.json")
STATE.parent.mkdir(parents=True, exist_ok=True)

def grant_temporary(username: str, role: str, ttl_seconds: int = 14400):
    data={}
    if STATE.exists():
        try: data=json.loads(STATE.read_text())
        except: data={}
    data[username] = {"role": role, "expires": time.time()+ttl_seconds, "granted_at": time.time()}
    STATE.write_text(json.dumps(data, indent=2))
    return data[username]

def is_elevated(username: str) -> str | None:
    if not STATE.exists(): return None
    try: data=json.loads(STATE.read_text())
    except: return None
    rec=data.get(username)
    if not rec: return None
    if time.time() > rec["expires"]:
        # auto revoke
        data.pop(username, None)
        STATE.write_text(json.dumps(data, indent=2))
        return None
    return rec["role"]

def revoke(username: str):
    if not STATE.exists(): return
    data=json.loads(STATE.read_text())
    data.pop(username, None)
    STATE.write_text(json.dumps(data, indent=2))
