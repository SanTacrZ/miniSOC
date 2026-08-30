#!/usr/bin/env python3
"""Generate forensic timeline from logs + alert"""
import json, pathlib, argparse

def build_timeline(log_paths, alert_id=None):
    events=[]
    for p in log_paths:
        if not p.exists(): continue
        for line in p.read_text().splitlines():
            try:
                e=json.loads(line); events.append(e)
            except: pass
    events.sort(key=lambda x: x.get("timestamp",""))
    return events

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--alert", help="alert json file")
    ap.add_argument("--out", default="labs/evidence/timeline.jsonl")
    args=ap.parse_args()
    logs = [pathlib.Path("logs/siem.jsonl"), pathlib.Path("logs/rustyapa.jsonl"), pathlib.Path("/tmp/soc_siem.jsonl")]
    tl = build_timeline(logs, args.alert)
    out = pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    with open(out,"w") as f:
        for e in tl[-200:]:
            f.write(json.dumps(e)+"\n")
    print(f"[+] timeline {len(tl)} events -> {out}")
