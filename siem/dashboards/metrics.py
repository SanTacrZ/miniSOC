#!/usr/bin/env python3
"""
SOC Metrics — MTTD / MTTR / Alert Fatigue
Lee logs/alerts.jsonl + logs/siem.jsonl + logs/blocklist.json y reporta:
- MTTD: tiempo medio desde primer evento malicioso hasta alerta
- MTTR: tiempo desde alerta hasta contain (block_ip / snapshot)
- Alert fatigue: alertas por hora, top reglas, FP estimación
- SLA: % alertas high/critical con MTTD <15m (P1) / 60m (P2)

Uso:
  python siem/dashboards/metrics.py --json
  python siem/dashboards/metrics.py --html > labs/evidence/metrics.html
"""
from __future__ import annotations
import json, pathlib, time, collections, statistics
from datetime import datetime, timezone

ALERTS = pathlib.Path("logs/alerts.jsonl")
SIEM = pathlib.Path("logs/siem.jsonl")
BLOCKLIST = pathlib.Path("logs/blocklist.json")

def parse_ts(s: str) -> float:
    try:
        dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except: return 0

def load_alerts():
    if not ALERTS.exists(): return []
    return [json.loads(l) for l in ALERTS.read_text().splitlines() if l.strip()]

def compute():
    alerts = load_alerts()
    if not alerts:
        return {"alerts":0, "mttd_seconds":None, "mttr_seconds":None, "by_rule":{}, "by_severity":{}}
    # MTTD: alerta.timestamp - primer evento.timestamp por alert
    mttds=[]
    for a in alerts:
        at = parse_ts(a["timestamp"])
        evs = a.get("events") or []
        if evs:
            evt_ts = min(parse_ts(e.get("timestamp","")) for e in evs if e.get("timestamp"))
            if evt_ts and at: mttds.append(max(0, at - evt_ts))
    # MTTR: alerta.timestamp -> blocklist timestamp correlacionado por src_ip
    mttrs=[]
    bl={}
    if BLOCKLIST.exists():
        try: bl=json.loads(BLOCKLIST.read_text())
        except: bl={}
    # also check soar logs: logs/siem.jsonl contain contain_block_ip
    soar_times={}
    if SIEM.exists():
        for line in SIEM.read_text().splitlines():
            try:
                e=json.loads(line)
                if e.get("svc")=="soar" and e.get("action")=="contain_block_ip":
                    soar_times[e.get("src_ip","")] = parse_ts(e["timestamp"])
            except: pass
    for a in alerts:
        at = parse_ts(a["timestamp"])
        src_ip = (a.get("events") or [{}])[0].get("src_ip")
        # try soar contain time, else blocklist value (unix ts)
        ct = soar_times.get(src_ip) or bl.get(src_ip)
        if isinstance(ct, float):  # from blocklist unix ts
            pass
        elif isinstance(ct, str):
            ct=parse_ts(ct)
        if ct and at:
            # ct is contain time, may be future vs at? use max
            if ct >= at: mttrs.append(ct - at)
    by_rule = collections.Counter(a.get("rule_id","unknown") for a in alerts)
    by_sev = collections.Counter(a.get("severity","unknown") for a in alerts)
    return {
        "alerts": len(alerts),
        "mttd_seconds": statistics.mean(mttds) if mttds else None,
        "mttd_p95": sorted(mttds)[int(len(mttds)*0.95)] if mttds else None,
        "mttr_seconds": statistics.mean(mttrs) if mttrs else None,
        "by_rule": dict(by_rule),
        "by_severity": dict(by_sev),
        "alerts_per_hour": len(alerts)/max(1, (time.time()-min(parse_ts(a["timestamp"]) for a in alerts if parse_ts(a["timestamp"])))/3600) if alerts else 0,
        "sla_p1_met": sum(1 for v in mttds if v<900)/max(1,len(mttds)) if mttds else None,  # 15m
    }

if __name__ == "__main__":
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--html", action="store_true")
    args=ap.parse_args()
    m=compute()
    if args.html:
        html = f"""<html><head><title>SOC Metrics</title></head><body>
<h1>MiniSOC — Metrics</h1>
<p>Alerts: {m['alerts']}</p>
<p>MTTD: {m['mttd_seconds']:.1f}s P95 {m['mttd_p95']:.1f}s</p>
<p>MTTR: {m['mttr_seconds']:.1f}s</p>
<p>SLA P1 (<15m): {m['sla_p1_met']*100:.1f}%</p>
<pre>{json.dumps(m, indent=2)}</pre>
</body></html>"""
        print(html)
    else:
        print(json.dumps(m, indent=2))
