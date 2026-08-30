"""SOAR-lite responder — block IP, revoke JWT"""
import argparse, json, pathlib, time

BLOCKLIST = pathlib.Path("logs/blocklist.json")
BLOCKLIST.parent.mkdir(parents=True, exist_ok=True)

def block_ip(ip, ttl=900):
    data={}
    if BLOCKLIST.exists():
        try: data=json.loads(BLOCKLIST.read_text())
        except: data={}
    data[ip]= time.time()+ttl
    BLOCKLIST.write_text(json.dumps(data, indent=2))
    print(f"[+] blocked {ip} for {ttl}s")

def revoke_jti(jti):
    # in-memory via api jwt store — here we append to file that api could poll
    p=pathlib.Path("logs/revoked.jsonl")
    with open(p,"a") as f: f.write(json.dumps({"jti":jti,"ts": time.time()})+"\n")
    print(f"[+] revoked {jti}")

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--block-ip")
    ap.add_argument("--revoke")
    args=ap.parse_args()
    if args.block_ip: block_ip(args.block_ip)
    if args.revoke: revoke_jti(args.revoke)
