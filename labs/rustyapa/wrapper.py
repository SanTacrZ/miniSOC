#!/usr/bin/env python3
"""
Rustyapa wrapper — instrumenta el binario vulnerable para SOC
TEE logs → logs/rustyapa.jsonl (formato SIEM) + stdout passthrough
Uso: python labs/rustyapa/wrapper.py --binary /tmp/rustyapa_inspect/static/RUSTyapa --port 11331
"""
import subprocess, pathlib, json, time, uuid, sys, threading, os, argparse

LOG = pathlib.Path(__file__).parent.parent.parent / "logs" / "rustyapa.jsonl"
ALT = pathlib.Path("/tmp/soc_siem.jsonl")

def emit(event: dict):
    event.setdefault("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    event.setdefault("event_id", str(uuid.uuid4()))
    event.setdefault("svc", "rustyapa")
    line = json.dumps(event, ensure_ascii=False)
    for p in [LOG, ALT]:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a") as f:
                f.write(line+"\n")
        except: pass

def run_binary(binary: str):
    print(f"[*] launching {binary} with SOC wrapper")
    emit({"action":"rustyapa_start","object":binary,"result":"success"})
    proc = subprocess.Popen([binary], stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    emit({"action":"rustyapa_exit","object":binary,"result":"terminate","returncode": proc.returncode})

def simulate_deposit(src_ip="127.0.0.1", row=0, amount=100, note="test"):
    # For testing without binary: emit synthetic event
    emit({"action":"commit","object":f"table=0 row={row}","result":"success","src_ip":src_ip,"payload_len": len(note.encode()), "note": note[:200], "delta": amount, "tags_len": len(note)})

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--binary", default="/tmp/rustyapa_inspect/static/RUSTyapa")
    ap.add_argument("--simulate", action="store_true", help="emit synthetic logs for demo")
    args=ap.parse_args()
    if args.simulate:
        for i in range(3):
            simulate_deposit(note="A"*5000 if i==2 else "normal")
            time.sleep(0.5)
        print("[*] synthetic logs emitted to", LOG)
    else:
        if pathlib.Path(args.binary).exists():
            run_binary(args.binary)
        else:
            print(f"[!] binary not found {args.binary}, using simulate")
            simulate_deposit(note="fallback")
