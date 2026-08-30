#!/bin/bash
set -e
SCENARIO=${1:-brute-force}
echo "[*] Simulate: $SCENARIO"
case $SCENARIO in
  brute-force) python labs/scenarios/brute_force.py ;;
  exfil) python labs/scenarios/exfil.py ;;
  rustyapa-pwn) python labs/rustyapa/exploit.py --level 2 --spray 5 --size 5000 ;;
  rustyapa-spray) python labs/rustyapa/exploit.py --spray 20 --size 3000 ;;
  cloud) python -m cloud_audit.checks.runner ;;
  all)
    bash "$0" brute-force
    bash "$0" exfil
    bash "$0" rustyapa-pwn
    bash "$0" cloud
    ;;
  *) echo "unknown $SCENARIO — options: brute-force|exfil|rustyapa-pwn|cloud|all" ;;
esac
echo "[*] Now run SIEM: source .venv/bin/activate && python siem/engine/engine.py"
echo "[*] Or check alerts: cat logs/alerts.jsonl | jq"
