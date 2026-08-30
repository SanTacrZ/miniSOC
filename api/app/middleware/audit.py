"""
AU-2, AU-3, AU-12 Audit Generation
Structured JSON logging with hash-chain (AU-9)
"""
from __future__ import annotations
import time, json, uuid, pathlib, os
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from ..utils.hash_chain import next_hash, canonical

LOG_DIR = pathlib.Path(__file__).parent.parent.parent.parent / "logs"
# In docker, logs may be at ./logs or /logs
if not LOG_DIR.exists():
    # try cwd
    alt = pathlib.Path.cwd() / "logs"
    if alt.exists() or True:
        LOG_DIR = alt
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "siem.jsonl"

# also alias for siem engine polling
ALT_LOG = pathlib.Path("/tmp/soc_siem.jsonl")

def _write_event(event: dict):
    # canonical + hash
    canon = canonical(event)
    h = next_hash(canon)
    event["hash"] = h
    # if hash_chain already set, ensure previous hash reference
    # Write as JSONL
    line = json.dumps(event, ensure_ascii=False)
    for path in {LOG_FILE, ALT_LOG, pathlib.Path.cwd() / "logs" / "siem.jsonl"}:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(line+"\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            pass

class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        # Call next
        response: Response = await call_next(request)
        # Build event AFTER (AU-12: generate before response but we have result now)
        duration_ms = int((time.time()-start)*1000)
        # Try to get actor from request.state if set by auth? fallback to token parsing without verification
        actor = getattr(request.state, "actor", "anonymous")
        role = getattr(request.state, "role", "none")
        src_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("User-Agent", "-")
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_id": str(uuid.uuid4()),
            "trace_id": request_id,
            "svc": "api",
            "src_ip": src_ip,
            "user_agent": user_agent,
            "actor": actor,
            "role": role,
            "action": f"{request.method} {request.url.path}",
            "object": request.url.path,
            "result": "success" if response.status_code < 400 else "fail",
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "bytes_out": int(response.headers.get("content-length", 0)) if response.headers.get("content-length") else 0,
            "mitre_technique": None,
        }
        # Add hash_chain previous reference already via next_hash
        _write_event(event)
        response.headers["X-Request-ID"] = request_id
        return response

def emit_custom(event: dict):
    """Manual emit for auth events that need mitre tagging"""
    # Ensure required fields
    event.setdefault("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    event.setdefault("event_id", str(uuid.uuid4()))
    event.setdefault("svc", "api")
    _write_event(event)
