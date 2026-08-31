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

# Cadenas de abort de glibc que DELATAN el UAF de run_batch.
# Aparecen en stderr y nunca en operación normal -> IOC de alta fidelidad.
ABORT_SIGNATURES = [
    "double free detected in tcache 2",
    "unaligned fastbin chunk detected 3",
    "unaligned tcache chunk detected",
    "malloc(): corrupted top size",
    "free(): invalid pointer",
]

def classify_abort(stderr_text: str, returncode: int):
    """Devuelve la firma de abort encontrada o None."""
    for sig in ABORT_SIGNATURES:
        if sig in stderr_text:
            return sig
    if returncode is not None and returncode < 0:
        return f"signal {-returncode}"
    return None

def run_binary(binary: str):
    """Lanza el binario con stdout en passthrough y stderr capturado.

    stderr se captura porque ahí va el mensaje de abort de glibc, que es el IOC
    más fiable del exploit real (PB-02): el ataque no usa payloads grandes, así
    que una regla basada sólo en payload_len lo pierde.
    """
    print(f"[*] launching {binary} with SOC wrapper")
    emit({"action":"rustyapa_start","object":binary,"result":"success"})
    proc = subprocess.Popen([binary], stdin=sys.stdin, stdout=sys.stdout,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    stderr_lines = []
    def pump():
        for line in proc.stderr:
            stderr_lines.append(line.rstrip("\n"))
            sys.stderr.write(line)
            sys.stderr.flush()
    t = threading.Thread(target=pump, daemon=True)
    t.start()
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    t.join(timeout=2)
    tail = "\n".join(stderr_lines[-5:])
    sig = classify_abort(tail, proc.returncode)
    if sig:
        emit({"action":"rustyapa_abort","object":binary,"result":"abort","src_ip":"127.0.0.1",
              "returncode": proc.returncode, "abort_signature": sig,
              "stderr_tail": tail[:500], "payload_len": 0})
    emit({"action":"rustyapa_exit","object":binary,"result":"terminate",
          "returncode": proc.returncode, "stderr_tail": tail[:500]})

def simulate_deposit(src_ip="127.0.0.1", row=0, amount=100, note="test"):
    # For testing without binary: emit synthetic event
    emit({"action":"commit","object":f"table=0 row={row}","result":"success","src_ip":src_ip,"payload_len": len(note.encode()), "note": note[:200], "delta": amount, "tags_len": len(note)})

def simulate_batch(src_ip="10.33.7.42", src=0, dst=1, amount=100):
    """Emite el TTP REAL de PB-02: Batch transfer (run_batch).

    Ojo: el exploit real NO manda payloads grandes ni metacharacteres. Usa
    `Transactions -> 3. Batch transfer`, y el payload son 17 bytes fijos
    ("batch-out" + "batch-in") escritos por el propio binario. Por eso
    `payload_len > 4096` NO detecta este ataque (falso negativo) y la regla
    SOC-006 se apoya en `action == batch` + el abort de glibc.
    """
    emit({"action":"batch","object":f"src={src} dst={dst}","result":"success","src_ip":src_ip,
          "payload_len":17,"note":"batch-out|batch-in","delta":amount,
          "tags_len":17,"journal_ops":6,"journal_delta":0,
          "mitre_technique":"T1190"})

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--binary", default="/tmp/rustyapa_inspect/static/RUSTyapa")
    ap.add_argument("--simulate", action="store_true", help="emit synthetic logs for demo")
    ap.add_argument("--simulate-batch", dest="simulate_batch", action="store_true",
                    help="emit the REAL PB-02 TTP: Batch transfer + glibc abort")
    args=ap.parse_args()
    if args.simulate:
        for i in range(3):
            simulate_deposit(note="A"*5000 if i==2 else "normal")
            time.sleep(0.5)
        print("[*] synthetic logs emitted to", LOG)
    elif args.simulate_batch:
        # TTP real de PB-02: batch + abort (lo que hace el exploit de verdad)
        simulate_batch()
        time.sleep(0.3)
        emit({"action":"rustyapa_abort","object":"simulated","result":"abort","src_ip":"10.33.7.42",
              "returncode":-6,"abort_signature":"double free detected in tcache 2",
              "stderr_tail":"free(): double free detected in tcache 2","payload_len":0})
        print("[*] simulated batch+abort emitted to", LOG)
    else:
        if pathlib.Path(args.binary).exists():
            run_binary(args.binary)
        else:
            print(f"[!] binary not found {args.binary}, using simulate")
            simulate_deposit(note="fallback")
