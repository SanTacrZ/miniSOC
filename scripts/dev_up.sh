#!/bin/bash
# Mini-SOC en local SIN docker — arranca los 4 servicios del lab.
#
#   ./scripts/dev_up.sh start | stop | status
#
# Servicios:
#   8000  API vulnerable (FastAPI, NIST controls)
#   8001  SIEM API (alertas)
#   --    SIEM engine (correlacion Sigma-like + SOAR)
#   11331 Rustyapa DBMS vulnerable (socat -> wrapper.py -> binario)
#
# Todo va a una sesion tmux `soc` para verlo en vivo:  tmux attach -t soc
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SESSION=soc
LOGDIR="$ROOT/logs"
mkdir -p "$LOGDIR" labs/evidence

start() {
  tmux has-session -t "$SESSION" 2>/dev/null && { echo "[=] ya esta corriendo: tmux attach -t $SESSION"; exit 0; }
  # shellcheck disable=SC1091
  source .venv/bin/activate

  tmux new-session  -d -s "$SESSION" -n rustyapa  "cd $ROOT && source .venv/bin/activate && socat -v TCP-LISTEN:11331,reuseaddr,fork EXEC:'python labs/rustyapa/wrapper.py --binary labs/rustyapa/bin/RUSTyapa' 2>&1 | tee -a $LOGDIR/rustyapa-socat.log"
  tmux new-window   -t "$SESSION" -n engine      "cd $ROOT && source .venv/bin/activate && python -u -m siem.engine.engine 2>&1 | tee -a $LOGDIR/engine.log"
  tmux new-window   -t "$SESSION" -n siem-api    "cd $ROOT && source .venv/bin/activate && python -m uvicorn siem.engine.api:app --host 127.0.0.1 --port 8001 2>&1 | tee -a $LOGDIR/siem-api.log"
  tmux new-window   -t "$SESSION" -n api         "cd $ROOT && source .venv/bin/activate && python -m uvicorn api.app.main:app --host 127.0.0.1 --port 8000 2>&1 | tee -a $LOGDIR/api.log"

  sleep 4
  echo "[*] servicios arrancados"
  status
  echo
  echo "  tmux attach -t $SESSION     # ver todo en vivo (Ctrl-b n/p para cambiar de ventana)"
  echo
  echo "  # Diviertete: dispara el exploit real contra Rustyapa"
  echo "  printf '3\n3\n0\n1\n100\n0\n0\n' | timeout 10 nc 127.0.0.1 11331"
  echo "  # ...y mira como el SOC lo caza:"
  echo "  tail -f $LOGDIR/engine.log"
}

stop() {
  tmux has-session -t "$SESSION" 2>/dev/null && tmux kill-session -t "$SESSION"
  pkill -f "socat -v TCP-LISTEN:11331" 2>/dev/null
  pkill -f "siem.engine.engine" 2>/dev/null
  pkill -f "uvicorn" 2>/dev/null
  echo "[*] servicios parados"
}

status() {
  printf "  %-10s %s\n" "11331" "$(curl -s -m 2 --max-time 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:11331 2>/dev/null || true) rustyapa (raw tcp)"
  printf "  %-10s %s\n" "8001"   "$(curl -s -m 3 http://127.0.0.1:8001/alerts -o /dev/null -w '%{http_code}' 2>/dev/null || echo down) siem-api /alerts"
  printf "  %-10s %s\n" "8000"   "$(curl -s -m 3 http://127.0.0.1:8000/health -o /dev/null -w '%{http_code}' 2>/dev/null || echo down) api /health"
  printf "  %-10s %s\n" "engine" "$(pgrep -f 'siem.engine.engine' >/dev/null && echo up || echo down)"
}

case "${1:-start}" in
  start) start ;;
  stop)  stop ;;
  status) status ;;
  *) echo "uso: $0 start|stop|status" ; exit 1 ;;
esac
