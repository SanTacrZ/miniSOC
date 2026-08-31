#!/usr/bin/env python3
"""
Purple Team ATT&CK Chain Emulator — NIST DE.CM / RS.MA
Simula kill-chain completa ATT&CK para entrenar SOC sin tocar producción.

Chain por defecto (configurable via YAML):
  T1078 Valid Accounts → T1110 Brute Force → T1190 Exploit Rustyapa
  → T1059 Execution (note ; cat) → T1548 PrivEsc → T1041 Exfil

Cada técnica emite evento JSONL a logs/siem.jsonl con MITRE + timestamp
espaciado para que SIEM correlacione y genere playbooks.

Uso:
  python scripts/attack_emulator.py --chain full --speed 1.0
  python scripts/attack_emulator.py --chain rustyapa-only
  python scripts/attack_emulator.py --list-chains
"""
from __future__ import annotations
import json, pathlib, time, uuid, argparse, random, yaml

LOG = pathlib.Path("logs/siem.jsonl")
ALT = pathlib.Path("/tmp/soc_siem.jsonl")
RUSTY_LOG = pathlib.Path("logs/rustyapa.jsonl")

CHAINS = {
    "full": ["T1078_valid_accounts", "T1110_brute_force", "T1190_rustyapa", "T1059_execution", "T1548_privesc", "T1041_exfil"],
    "rustyapa-only": ["T1190_rustyapa", "T1059_execution"],
    "cloud-misconfig": ["T1078_valid_accounts", "T1098_persist", "T1041_exfil"],
    "initial-access": ["T1110_brute_force", "T1190_rustyapa"],
}

def emit(event: dict):
    event.setdefault("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    event.setdefault("event_id", str(uuid.uuid4()))
    line = json.dumps(event, ensure_ascii=False)
    for p in [LOG, ALT]:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f: f.write(line + "\n")
    # also rustyapa log if svc rustyapa
    if event.get("svc") == "rustyapa":
        RUSTY_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(RUSTY_LOG, "a") as f: f.write(line + "\n")
    print(f" → {event['action']:25} {event.get('mitre_technique','') :12} {event.get('src_ip','')}")

def step_T1078(src_ip="10.33.7.100"):
    emit({"svc":"api","src_ip":src_ip,"actor":"admin","action":"auth_success","object":"/auth/login","result":"success","mitre_technique":"T1078","user_agent":"Mozilla/5.0 (attack)"})

def step_T1110(src_ip="10.33.7.100", n=6):
    for i in range(n):
        emit({"svc":"api","src_ip":src_ip,"actor":"admin","action":"auth_fail","object":"/auth/login","result":"fail","mitre_technique":"T1110"})
        time.sleep(0.15)
    # eventual success (credential stuffing win)
    emit({"svc":"api","src_ip":src_ip,"actor":"admin","action":"auth_success","object":"/auth/login","result":"success","mitre_technique":"T1078"})

def step_T1190(src_ip="10.33.7.100"):
    # Use batch UAF TTP (real), not large payload spray
    emit({"svc":"rustyapa","src_ip":src_ip,"action":"batch","object":"batch transfer","result":"success","payload_len":17,"note":"batch-out","mitre_technique":"T1190"})

def step_T1059(src_ip="10.33.7.100"):
    emit({"svc":"api","src_ip":src_ip,"actor":"analyst","action":"suspicious_note","object":"/records","result":"success","note":"; cat /app/flag.txt","mitre_technique":"T1059","bytes_out":1200})

def step_T1548(src_ip="10.33.7.100"):
    for i in range(4):
        emit({"svc":"api","src_ip":src_ip,"actor":"viewer","action":"GET /admin/users","object":"/admin/users","result":"fail","status_code":403,"mitre_technique":"T1548"})

def step_T1041(src_ip="10.33.7.100"):
    emit({"svc":"api","src_ip":src_ip,"actor":"viewer","action":"suspicious_note","object":"/records","result":"success","mitre_technique":"T1041","bytes_out":75000,"note_len":4096})

def step_T1098(src_ip="10.33.7.100"):
    emit({"svc":"cloud_audit","src_ip":src_ip,"action":"IAM-001","object":"No wildcard","result":"fail","severity":"critical","mitre_technique":"T1098"})

STEPS = {
    "T1078_valid_accounts": step_T1078,
    "T1110_brute_force": step_T1110,
    "T1190_rustyapa": step_T1190,
    "T1059_execution": step_T1059,
    "T1548_privesc": step_T1548,
    "T1041_exfil": step_T1041,
    "T1098_persist": step_T1098,
}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", default="full", choices=list(CHAINS.keys())+["custom"])
    ap.add_argument("--steps", nargs="*", help="custom steps if chain=custom")
    ap.add_argument("--speed", type=float, default=1.0, help="multiplier delay")
    ap.add_argument("--src-ip", default="10.33.7.200")
    ap.add_argument("--list-chains", action="store_true")
    args = ap.parse_args()
    if args.list_chains:
        for k,v in CHAINS.items(): print(f"{k:20} → {' → '.join(v)}")
        exit(0)
    chain = CHAINS[args.chain] if args.chain!="custom" else args.steps or CHAINS["full"]
    print(f"[*] Emulating chain {args.chain}: {' → '.join(chain)} from {args.src_ip} speed {args.speed}x")
    for step in chain:
        fn = STEPS[step]
        # pass src_ip if supports
        try: fn(src_ip=args.src_ip)
        except TypeError: fn()
        time.sleep(0.6/args.speed)
    print(f"[✓] Chain done — check: cat logs/siem.jsonl | tail -n {len(chain)*2} | jq; python -m siem.engine.engine --once || python -c \"from siem.engine.engine import poll_once; print(poll_once())\"")
