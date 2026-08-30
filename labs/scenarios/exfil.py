#!/usr/bin/env python3
"""Scenario: exfil via large payloads / scraping"""
import time, pathlib, json, uuid
for i in range(5):
    evt={"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event_id": str(uuid.uuid4()), "svc":"api","src_ip":"10.33.7.99","actor":"viewer","action":"suspicious_note","object":"/records","result":"success","bytes_out": 60000, "note_len": 5000, "mitre_technique":"T1041"}
    for p in [pathlib.Path("logs/siem.jsonl"), pathlib.Path("/tmp/soc_siem.jsonl")]:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p,"a") as f: f.write(json.dumps(evt)+"\n")
    print(f"exfil emit {i}")
    time.sleep(0.1)
print("[+] exfil done")
