"""
OpenSearch / Wazuh Forwarder — Integration real
- Lee logs/siem.jsonl + logs/alerts.jsonl + logs/rustyapa.jsonl
- Envía bulk a OpenSearch (_bulk) o Wazuh vía API
- Fallback: si OpenSearch no disponible, escribe a logs/opensearch_buffer.jsonl
NIST SI-4, AU-9
"""
from __future__ import annotations
import json, pathlib, time, http.client, urllib.parse, os, sys

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX", "minisoc-siem")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS", "Minisoc123!")
WAZUH_HOST = os.getenv("WAZUH_HOST", "")
WAZUH_TOKEN = os.getenv("WAZUH_TOKEN", "")

LOG_PATHS = [
    pathlib.Path("logs/siem.jsonl"),
    pathlib.Path("logs/rustyapa.jsonl"),
    pathlib.Path("logs/alerts.jsonl"),
    pathlib.Path("logs/findings.json"),
]

def bulk_payload(events: list[dict], index: str) -> str:
    lines=[]
    for e in events:
        # ECS-like mapping
        doc = {
            "@timestamp": e.get("timestamp"),
            "event": {"id": e.get("event_id"), "action": e.get("action"), "outcome": e.get("result")},
            "source": {"ip": e.get("src_ip")},
            "user": {"name": e.get("actor"), "roles": [e.get("role")] if e.get("role") else []},
            "rule": {"id": e.get("rule_id"), "name": e.get("title")} if e.get("rule_id") else {},
            "tags": e.get("mitre") or ([e.get("mitre_technique")] if e.get("mitre_technique") else []),
            "minisoc": e,
        }
        header = json.dumps({"index": {"_index": index}})
        lines.append(header)
        lines.append(json.dumps(doc, ensure_ascii=False))
    return "\n".join(lines) + "\n" if lines else ""

def send_to_opensearch(payload: str) -> bool:
    if not payload:
        return True
    try:
        conn = http.client.HTTPConnection(OPENSEARCH_HOST, OPENSEARCH_PORT, timeout=5)
        # OpenSearch default is HTTPS with self-signed; try HTTP first, fallback no verify
        # For dev, allow http if https fails
        headers = {"Content-Type": "application/x-ndjson"}
        # Basic auth if set
        if OPENSEARCH_USER and OPENSEARCH_PASS:
            import base64
            creds = base64.b64encode(f"{OPENSEARCH_USER}:{OPENSEARCH_PASS}".encode()).decode()
            headers["Authorization"] = f"Basic {creds}"
        conn.request("POST", "/_bulk", body=payload.encode(), headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode()
        if resp.status in (200, 201):
            # Check for errors in bulk
            j = json.loads(body)
            if j.get("errors"):
                print(f"[!] OpenSearch bulk partial errors: {body[:500]}")
                return False
            return True
        else:
            print(f"[!] OpenSearch {resp.status} {body[:500]}")
            return False
    except Exception as e:
        print(f"[!] OpenSearch unreachable {e}")
        return False

def send_to_wazuh(events: list[dict]) -> bool:
    if not WAZUH_HOST or not WAZUH_TOKEN:
        return False
    try:
        import urllib.request
        data = json.dumps({"events": events}).encode()
        req = urllib.request.Request(f"https://{WAZUH_HOST}/siem/events", data=data, headers={"Authorization": f"Bearer {WAZUH_TOKEN}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status in (200, 201, 202)
    except Exception as e:
        print(f"[!] Wazuh push failed {e}")
        return False

def tail_and_forward(batch=100, poll=2):
    seen=set()
    print(f"[*] Forwarder to OpenSearch {OPENSEARCH_HOST}:{OPENSEARCH_PORT}/{OPENSEARCH_INDEX}")
    print(f"[*] Wazuh {'enabled' if WAZUH_HOST else 'disabled (set WAZUH_HOST/WAZUH_TOKEN to enable)'}")
    while True:
        events=[]
        for p in LOG_PATHS:
            candidates=[]
            if p.is_dir(): continue
            if not p.exists(): continue
            # handle .json (findings) vs .jsonl
            if p.suffix==".json" and p.name=="findings.json":
                try:
                    arr=json.loads(p.read_text())
                    for e in arr:
                        # normalize findings to event
                        evt={"timestamp": e.get("timestamp"), "event_id": e.get("id"), "action": e.get("id"), "result": e.get("status"), "severity": e.get("severity"), "title": e.get("title")}
                        events.append(evt)
                except: pass
                continue
            for line in p.read_text().splitlines():
                if not line.strip(): continue
                h = hash(line)
                if h in seen: continue
                seen.add(h)
                try:
                    e=json.loads(line); events.append(e)
                except: continue
                if len(events)>=batch: break
        if events:
            payload = bulk_payload(events, OPENSEARCH_INDEX)
            ok = send_to_opensearch(payload)
            if ok:
                print(f"[+] Forwarded {len(events)} events to OpenSearch")
                # also try wazuh if configured
                if WAZUH_HOST:
                    send_to_wazuh(events)
            else:
                # buffer
                buf = pathlib.Path("logs/opensearch_buffer.jsonl")
                buf.parent.mkdir(parents=True, exist_ok=True)
                with open(buf,"a") as f:
                    for e in events:
                        f.write(json.dumps(e)+"\n")
                print(f"[!] Buffered {len(events)} to {buf}")
        time.sleep(poll)

if __name__=="__main__":
    # one-shot mode for CI
    if "--once" in sys.argv:
        events=[]
        for p in LOG_PATHS:
            if not p.exists(): continue
            if p.suffix==".jsonl":
                for line in p.read_text().splitlines():
                    try: events.append(json.loads(line))
                    except: pass
        if events:
            print(bulk_payload(events[:5], OPENSEARCH_INDEX)[:2000])
        else:
            print("[*] no events")
    else:
        tail_and_forward()
