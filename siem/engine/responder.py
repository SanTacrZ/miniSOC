"""SOAR responder — block IP, revoke JWT, snapshot, auto-isolate playbooks"""
import argparse, json, pathlib, time, subprocess, yaml, shutil

BLOCKLIST = pathlib.Path("logs/blocklist.json")
BLOCKLIST.parent.mkdir(parents=True, exist_ok=True)
PLAYBOOKS = pathlib.Path(__file__).parent / "playbooks.yml"

def block_ip(ip, ttl=900):
    data={}
    if BLOCKLIST.exists():
        try: data=json.loads(BLOCKLIST.read_text())
        except: data={}
    data[ip]= time.time()+ttl
    BLOCKLIST.write_text(json.dumps(data, indent=2))
    print(f"[+] blocked {ip} for {ttl}s")
    # also emit audit for SIEM to show containment
    audit = pathlib.Path("logs/siem.jsonl")
    evt={"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event_id": f"soar-{int(time.time())}", "svc":"soar","action":"contain_block_ip","object":ip,"result":"success","src_ip":ip,"mitre_technique":"T1110"}
    for p in [audit, pathlib.Path("/tmp/soc_siem.jsonl")]:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p,"a") as f: f.write(json.dumps(evt)+"\n")

def revoke_jti(jti):
    p=pathlib.Path("logs/revoked.jsonl")
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p,"a") as f: f.write(json.dumps({"jti":jti,"ts": time.time()})+"\n")
    print(f"[+] revoked {jti}")
    # also log
    audit = pathlib.Path("logs/siem.jsonl")
    evt={"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event_id": f"soar-revoke-{jti[:8]}", "svc":"soar","action":"contain_revoke_jti","object":jti,"result":"success"}
    for pp in [audit, pathlib.Path("/tmp/soc_siem.jsonl")]:
        with open(pp,"a") as f: f.write(json.dumps(evt)+"\n")

def snapshot_evidence(dest="labs/evidence/auto", include="logs/siem.jsonl"):
    dest = pathlib.Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    for src in ["logs/siem.jsonl", "logs/rustyapa.jsonl", "logs/alerts.jsonl", "alerts", "infra/terraform/main.tf"]:
        sp = pathlib.Path(src)
        if sp.exists():
            if sp.is_dir():
                shutil.copytree(sp, dest/sp.name, dirs_exist_ok=True)
            else:
                shutil.copy2(sp, dest/sp.name)
    # timeline
    try:
        from .timeline import build_timeline
        tl = build_timeline([pathlib.Path("logs/siem.jsonl"), pathlib.Path("logs/rustyapa.jsonl")])
        (dest/"timeline.jsonl").write_text("\n".join(json.dumps(e) for e in tl[-200:]))
    except: pass
    print(f"[+] snapshot -> {dest}")

def kill_rustyapa():
    print("[*] kill_rustyapa — restarting container (simulated)")
    try:
        subprocess.run(["docker","restart","minisoc-rustyapa"], timeout=5)
    except: print("[=] docker not available — simulated restart")
    # emit
    audit = pathlib.Path("logs/siem.jsonl")
    evt={"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event_id": f"soar-kill-{int(time.time())}", "svc":"soar","action":"contain_kill_rustyapa","object":"rustyapa","result":"success","mitre_technique":"T1190"}
    for p in [audit, pathlib.Path("/tmp/soc_siem.jsonl")]:
        with open(p,"a") as f: f.write(json.dumps(evt)+"\n")

def load_playbooks():
    if not PLAYBOOKS.exists(): return []
    return yaml.safe_load(PLAYBOOKS.read_text()).get("playbooks", [])

def run_playbook(alert: dict):
    """Ejecuta playbook(s) que matchean alert.rule_id. Retorna acciones ejecutadas."""
    executed=[]
    for pb in load_playbooks():
        trig = pb.get("trigger", {})
        # trigger.rule_id acepta un id o una lista de ids (SOC-002 y SOC-006
        # describen el mismo TTP de Rustyapa con señales distintas).
        trig_ids = trig.get("rule_id")
        if isinstance(trig_ids, str):
            trig_ids = [trig_ids]
        if not trig_ids or alert.get("rule_id") not in trig_ids:
            continue
        # severity gate (acepta una severidad o lista)
        sev = trig.get("severity")
        if sev:
            sevs = [sev] if isinstance(sev, str) else list(sev)
            if alert.get("severity") not in sevs:
                continue
        if not pb.get("auto", False):
            print(f"[-] playbook {pb['id']} requires manual approval — skipping auto")
            continue
        print(f"[*] SOAR auto playbook {pb['id']}: {pb['name']}")
        for act in pb.get("actions", []):
            t = act.get("type")
            # templating simple
            src_ip = (alert.get("events") or [{}])[0].get("src_ip") or "unknown"
            jti = (alert.get("events") or [{}])[0].get("raw", {}).get("jti") or alert.get("events",[{}])[0].get("event_id","")
            if t=="block_ip":
                ttl = act.get("params", {}).get("ttl", 900)
                # support templating
                ip = act.get("params", {}).get("src_ip", src_ip).replace("{{event.src_ip}}", src_ip)
                block_ip(ip, ttl)
                executed.append(f"block_ip {ip}")
            elif t=="revoke_jti":
                revoke_jti(jti)
                executed.append(f"revoke {jti[:8]}")
            elif t=="snapshot_evidence":
                dest = act.get("params", {}).get("dest", "labs/evidence/auto").replace("{{alert.alert_id}}", alert.get("alert_id","unknown"))
                snapshot_evidence(dest)
                executed.append(f"snapshot {dest}")
            elif t=="kill_rustyapa":
                kill_rustyapa()
                executed.append("kill_rustyapa")
            elif t=="notify":
                msg = act.get("params", {}).get("message","").replace("{{event.src_ip}}", src_ip).replace("{{alert.alert_id}}", alert.get("alert_id",""))
                print(msg)
                executed.append(f"notify: {msg}")
    return executed

def check_alerts_for_auto():
    """Poll logs/alerts.jsonl y dispara playbooks nuevos (llamado por engine)"""
    alerts_path = pathlib.Path("logs/alerts.jsonl")
    if not alerts_path.exists(): return
    done = set()
    marker = pathlib.Path("logs/.soar_done")
    if marker.exists():
        try: done=set(marker.read_text().splitlines())
        except: pass
    for line in alerts_path.read_text().splitlines():
        if not line.strip(): continue
        try:
            alert=json.loads(line)
            aid=alert.get("alert_id")
            if aid in done: continue
            ex = run_playbook(alert)
            if ex:
                done.add(aid)
        except Exception as e:
            print(f"[!] playbook error {e}")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("\n".join(done))

if __name__=="__main__":
    ap=argparse.ArgumentParser(description="SOAR responder")
    ap.add_argument("--block-ip")
    ap.add_argument("--ttl", type=int, default=900)
    ap.add_argument("--revoke")
    ap.add_argument("--snapshot", nargs="?", const="labs/evidence/manual", help="snapshot evidencia")
    ap.add_argument("--kill-rustyapa", action="store_true")
    ap.add_argument("--run-playbooks", action="store_true", help="eval alerts y ejecuta playbooks auto")
    ap.add_argument("--alert-json", help="alert json file for single run")
    args=ap.parse_args()
    if args.block_ip: block_ip(args.block_ip, args.ttl)
    if args.revoke: revoke_jti(args.revoke)
    if args.snapshot: snapshot_evidence(args.snapshot)
    if args.kill_rustyapa: kill_rustyapa()
    if args.run_playbooks: check_alerts_for_auto()
    if args.alert_json:
        alert=json.loads(pathlib.Path(args.alert_json).read_text())
        print(run_playbook(alert))
