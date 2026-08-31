#!/bin/bash
set -e
echo "[*] Rotating mTLS certs"
bash infra/certs/generate_certs.sh
echo "[*] Restart services with MTLS_ENABLED=true"
docker compose -f infra/docker-compose.yml restart api siem 2>&1 | head -n 20
echo "[✓] Rotated — test: curl --cacert infra/certs/ca.crt --cert infra/certs/client.crt --key infra/certs/client.key https://localhost:8000/health"
