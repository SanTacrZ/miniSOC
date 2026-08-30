#!/usr/bin/env python3
"""Scenario: brute force API -> should trigger SOC-001"""
import httpx, time, sys
API="http://localhost:8000"
def main():
    print("[*] brute force 7 fails from 10.33.7.42")
    for i in range(7):
        try:
            r=httpx.post(f"{API}/auth/login", json={"username":"admin","password":"wrong123"}, headers={"X-Forwarded-For":"10.33.7.42"})
            print(i, r.status_code)
        except Exception as e:
            # offline -> emit synthetic log directly
            import pathlib, json, uuid
            p=pathlib.Path("logs/siem.jsonl")
            p.parent.mkdir(parents=True, exist_ok=True)
            evt={"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event_id": str(uuid.uuid4()), "svc":"api","src_ip":"10.33.7.42","actor":"admin","action":"auth_fail","object":"/auth/login","result":"fail","mitre_technique":"T1110"}
            with open(p,"a") as f: f.write(json.dumps(evt)+"\n")
            with open("/tmp/soc_siem.jsonl","a") as f2: f2.write(json.dumps(evt)+"\n")
            print(f"offline emit {i}")
        time.sleep(0.2)
    print("[+] done - check siem: python siem/engine/engine.py")

if __name__=="__main__":
    main()
