"""Runner — agregador + salida findings.json para SIEM"""
from __future__ import annotations
import json, pathlib
from ..iam.checks import run_all as iam
from ..network.checks import run_all as net
from ..storage.checks import run_all as sto

def run_all():
    findings = []
    findings.extend(iam())
    findings.extend(net())
    findings.extend(sto())
    # enrich
    for f in findings:
        f["timestamp"] = __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime())
        f["compliance"] = "NIST SP 800-53"
    return findings

def main():
    findings = run_all()
    out = pathlib.Path(__file__).parent.parent.parent / "logs" / "findings.json"
    out2 = pathlib.Path(__file__).parent.parent.parent / "cloud_audit" / "findings.json"
    for p in [out, out2, pathlib.Path("logs/findings.json")]:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(findings, indent=2))
    # also emit to siem.jsonl as distinct svc
    siem = pathlib.Path(__file__).parent.parent.parent / "logs" / "siem.jsonl"
    alt = pathlib.Path("/tmp/soc_siem.jsonl")
    for f in findings:
        if f["status"]=="FAIL":
            event = {"svc":"cloud_audit","action":f["id"],"object":f["title"],"result":"fail","severity":f["severity"],"resources":f["resources"], "mitre_technique": None}
            for p in [siem, alt]:
                if p.parent.exists() or True:
                    try:
                        p.parent.mkdir(parents=True, exist_ok=True)
                        import json as js, uuid, time as tm
                        event["timestamp"]= tm.strftime("%Y-%m-%dT%H:%M:%SZ", tm.gmtime())
                        event["event_id"]= str(uuid.uuid4())
                        p.write_text
                        with open(p,"a") as fh: fh.write(js.dumps(event)+"\n")
                    except: pass
    print(json.dumps(findings, indent=2))
    fails = sum(1 for f in findings if f["status"]=="FAIL")
    print(f"\n[SUMMARY] {fails}/{len(findings)} FAIL")
    return fails

if __name__=="__main__":
    main()
