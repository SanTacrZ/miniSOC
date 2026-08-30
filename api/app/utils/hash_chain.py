"""
AU-9 Protection of Audit Information
Implements hash-chain for log integrity: H_n = SHA256(H_{n-1} || canonical_json)
"""
from __future__ import annotations
import hashlib, json, pathlib

STATE_PATH = pathlib.Path(__file__).parent.parent.parent.parent / "logs" / ".hash_chain"
# fallback for api container
STATE_PATH_ALIAS = pathlib.Path("/tmp/soc_hash_chain")

def _state_file() -> pathlib.Path:
    # try primary, else alias
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        return STATE_PATH
    except Exception:
        return STATE_PATH_ALIAS

def previous_hash() -> str:
    p = _state_file()
    # also check alias if primary missing
    if not p.exists() and STATE_PATH_ALIAS.exists():
        p = STATE_PATH_ALIAS
    if p.exists():
        return p.read_text().strip()
    return "0"*64

def next_hash(canonical_json: str) -> str:
    prev = previous_hash()
    h = hashlib.sha256((prev + canonical_json).encode()).hexdigest()
    # write to both
    for p in {STATE_PATH, STATE_PATH_ALIAS}:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(h)
        except Exception:
            pass
    return h

def canonical(event: dict) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
