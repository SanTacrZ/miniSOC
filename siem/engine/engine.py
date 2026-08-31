"""
SIEM Engine — SP 800-92 Analysis + Sigma-like correlation
Polls logs/*.jsonl every 2s, applies YAML rules and stateful correlations
Writes alerts to logs/alerts.jsonl and alerts/alert-*.json
"""
from __future__ import annotations
import time, json, pathlib, yaml, hashlib, glob, collections, re
from .normalize import normalize

LOG_PATHS = [
    pathlib.Path(__file__).parent.parent.parent / "logs" / "siem.jsonl",
    pathlib.Path("/tmp/soc_siem.jsonl"),
    pathlib.Path.cwd() / "logs" / "siem.jsonl",
]
RUSTY_LOG = pathlib.Path(__file__).parent.parent.parent / "logs" / "rustyapa.jsonl"
ALERTS_JSONL = pathlib.Path(__file__).parent.parent.parent / "logs" / "alerts.jsonl"
ALERTS_DIR = pathlib.Path(__file__).parent.parent.parent / "alerts"
ALERTS_DIR.mkdir(parents=True, exist_ok=True)
RULES_DIR = pathlib.Path(__file__).parent.parent / "rules" / "sigma_like"

# state for correlations
state = {
    "auth_fail_by_ip": collections.defaultdict(list),  # ip -> [timestamps]
    "auth_success_after_fail": {},
    "rusty_payload": [],
}

SEEN = set()

def load_rules():
    rules = []
    for yf in RULES_DIR.glob("*.yml"):
        try:
            rules.append(yaml.safe_load(yf.read_text()))
        except Exception as e:
            print(f"[!] rule {yf} bad: {e}")
    return rules

def emit_alert(rule: dict, events: list[dict], severity=None, title=None):
    aid = hashlib.sha256(f"{time.time()}{rule.get('id')}{events[0].get('event_id') if events else ''}".encode()).hexdigest()[:12]
    alert = {
        "alert_id": aid,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rule_id": rule.get("id"),
        "title": title or rule.get("title"),
        "severity": severity or rule.get("level","medium"),
        "mitre": rule.get("tags", []),
        "description": rule.get("description"),
        "events": events[:5],
        "evidence_refs": [e.get("event_id") for e in events],
        "status": "open",
    }
    # write jsonl
    ALERTS_JSONL.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERTS_JSONL, "a") as f:
        f.write(json.dumps(alert)+"\n")
    # also individual file
    (ALERTS_DIR / f"alert-{aid}.json").write_text(json.dumps(alert, indent=2))
    # timeline
    tl = pathlib.Path(__file__).parent.parent.parent / "logs" / "timeline.jsonl"
    with open(tl, "a") as f:
        f.write(json.dumps({"alert_id": aid, "rule": alert["title"], "events": events[:3], "ts": alert["timestamp"]})+"\n")
    print(f"[ALERT] {alert['severity'].upper()} {alert['title']} ({aid})")
    return alert

def check_sigma_rules(events: list[dict], rules: list[dict]):
    alerts=[]
    for rule in rules:
        det = rule.get("detection", {})
        # simple Sigma: selection + condition + threshold
        sel = det.get("selection", {})
        cond = det.get("condition", "selection")
        threshold = rule.get("threshold")
        # brute force: count auth_fail per src_ip window
        if rule.get("id")=="SOC-001-brute-force":
            window = 60
            # group by ip
            by_ip = collections.defaultdict(list)
            for e in events:
                if e["action"]=="auth_fail" and e["result"]=="fail":
                    by_ip[e["src_ip"]].append(e)
            for ip, evs in by_ip.items():
                if len(evs) >= 5:
                    # check window: last 5 within 60s
                    times = [e["timestamp"] for e in evs[-5:]]
                    alerts.append(emit_alert(rule, evs[-5:], title=f"Brute force from {ip} ({len(evs)} fails)"))
        elif rule.get("id")=="SOC-002-rustyapa-exploit":
            for e in events:
                raw = e["raw"]
                if raw.get("svc")=="rustyapa":
                    plen = raw.get("payload_len",0)
                    note = raw.get("note","")
                    if plen>4096 or any(s in str(note) for s in [";","$(","`","flag"]):
                        alerts.append(emit_alert(rule, [e]))
        elif rule.get("id")=="SOC-003-priv-esc":
            for e in events:
                if e["action"].startswith("GET /admin") or e["action"].startswith("POST /admin"):
                    if e["result"]=="fail" and e["status_code"]==403:
                        # count burst 3 fails same actor in last minute
                        actor = e["actor"]
                        fails = [x for x in events if x["actor"]==actor and x["status_code"]==403]
                        if len(fails)>=3:
                            alerts.append(emit_alert(rule, fails[-3:]))
                            break
        elif rule.get("id")=="SOC-004-large-payload":
            # suspicious_note with large bytes
            for e in events:
                if e["raw"].get("action")=="suspicious_note" or e["raw"].get("bytes_out",0)>50000:
                    alerts.append(emit_alert(rule, [e]))
                    break
        elif rule.get("id")=="SOC-005-journal-clear":
            for e in events:
                if "journal_clear" in str(e["action"]) or "journal" in str(e["raw"].get("note","")):
                    alerts.append(emit_alert(rule, [e]))
    return alerts

def try_auto_respond(alerts):
    try:
        from .responder import check_alerts_for_auto
        # also direct run for current batch
        for a in alerts:
            try:
                from .responder import run_playbook
                run_playbook(a)
            except Exception as e:
                print(f"[!] auto-respond error {e}")
        # plus sweep file-based
        check_alerts_for_auto()
    except Exception as e:
        print(f"[!] soar hook error {e}")

def poll_once():
    events=[]
    for p in LOG_PATHS + [RUSTY_LOG]:
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            h = hashlib.sha256(line.encode()).hexdigest()
            if h in SEEN:
                continue
            SEEN.add(h)
            try:
                raw=json.loads(line)
                events.append(normalize(raw))
            except: continue
    # keep only recent 500 for rule evaluation
    events = events[-500:]
    if not events:
        return []
    rules = load_rules()
    alerts = check_sigma_rules(events, rules)
    # SOAR auto for batch (also called in main_loop, idempotent via marker)
    try:
        try_auto_respond(alerts)
    except: pass
    return alerts

def main_loop(poll_interval=2):
    print(f"[*] SIEM engine polling {LOG_PATHS} + {RUSTY_LOG} + SOAR auto")
    while True:
        try:
            alerts = poll_once()
            if alerts:
                try_auto_respond(alerts)
        except Exception as e:
            print(f"[!] engine error {e}")
        time.sleep(poll_interval)

if __name__=="__main__":
    main_loop()
