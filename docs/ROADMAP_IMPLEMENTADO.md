# Roadmap Implementado — 2026-08-31

> Checklist del README `## 8. Próximos pasos` ahora ✅

## ✅ 1. Wazuh / OpenSearch real

**Artefactos:**
- `siem/forwarder/opensearch_forwarder.py:1` — bulk ECS → OpenSearch `_bulk`, buffer `logs/opensearch_buffer.jsonl`
- `siem/wazuh/README.md`, `infra/opensearch/README.md`, `siem/dashboards/minisoc_ndjson.ndjson`
- `infra/docker-compose.yml:22` servicios `opensearch` (2.15.0), `opensearch-dashboards` (5601), `forwarder`, `wazuh` (profile)

**Verificación:**
```bash
docker compose -f infra/docker-compose.yml up -d opensearch opensearch-dashboards
OPENSEARCH_HOST=localhost python siem/forwarder/opensearch_forwarder.py --once | head
curl http://localhost:9200/minisoc-siem/_count
```

- Fallback sin Wazuh: forwarder sigue funcionando (buffer). Con `WAZUH_HOST` env se activa push a Wazuh API.

## ✅ 2. mTLS entre servicios

**Artefactos:**
- `infra/certs/generate_certs.sh:1` → CA 4096 + api/siem/client 2048 (SAN api,localhost,127.0.0.1), `infra/certs/README.md`
- `api/app/core/mtls.py:1` (ctx server/client), `api/app/middleware/mtls.py:1`
- `api/app/main.py:28` integra `MTLSMiddleware`
- `scripts/rotate_mtls.sh`

**Uso:**
```bash
bash infra/certs/generate_certs.sh
MTLS_ENABLED=true python -c "from api.app.core.mtls import server_ssl_context; print(server_ssl_context().verify_mode)" # 2 = CERT_REQUIRED
# En prod: docker-compose command con --ssl-certfile /certs/api.crt --ssl-ca-certs /certs/ca.crt --ssl-cert-reqs 2
curl --cacert infra/certs/ca.crt --cert infra/certs/client.crt --key infra/certs/client.key https://localhost:8000/health
```

- Default `MTLS_ENABLED=false` para no romper Tests; activar en `infra/docker-compose.yml` env.

## ✅ 3. SOAR playbook auto-isolate

**Artefactos:**
- `siem/engine/playbooks.yml:1` — 3 playbooks YAML (PB-BF-AUTO, PB-RUSTYAPA-AUTO auto:true, PB-PRIVESC-AUTO)
- `siem/engine/responder.py:1` reescrito: `block_ip`, `revoke_jti`, `snapshot_evidence`, `kill_rustyapa`, `run_playbook`, `check_alerts_for_auto`
- `siem/engine/engine.py:117` hook `try_auto_respond` en `poll_once` + `main_loop`

**Verificación:**
```bash
bash scripts/simulate_incident.sh brute-force && bash scripts/simulate_incident.sh rustyapa-pwn
python -c "from siem.engine.engine import poll_once; print(poll_once())"
cat logs/blocklist.json  # {"10.33.7.42": 178813...}
ls labs/evidence/rustyapa-*/  # snapshot + timeline
# Auto para SOC-002 (high) se dispara solo; PB-BF-AUTO requiere approval (auto:false) → manual: python siem/engine/responder.py --run-playbooks
```

- Acciones emiten `svc:soar` a `siem.jsonl` (AU-6) y son auditables.

## ✅ 4. Exportar Sigma → Elastic

**Artefactos:**
- `siem/tools/sigma_to_elastic.py:1` — Sigma YAML → DSL JSON + EQL, `--check`
- `siem/elastic/README.md`, `siem/elastic/dsl/*.json` (5), `siem/elastic/eql/*.eql` (5)

**Verificación:**
```bash
python siem/tools/sigma_to_elastic.py --check
# [+ ] 5 Sigma → Elastic exported
cat siem/elastic/dsl/SOC-002-rustyapa-exploit.json | jq .query
cat siem/elastic/eql/SOC-001-brute-force.eql
# Importa DSL en Kibana Dev Tools: POST minisoc-siem/_search
```

- Mapeo Sigma→ECS en `tools/sigma_to_elastic.py:25` con `meta` preservando `rule_id/mitre`.

## Tests & Evidencia

- `pytest api/tests` 9 passed
- `simulate_incident.sh all` + `poll_once` → 10 alertas + `blocklist.json` + snapshots `labs/evidence/rustyapa-*`
- `cloud_audit` 4/7 FAIL (incluye nuevo FAIL si terraform no cifra)
- `opensearch_forwarder --once` genera bulk NDJSON válido
- `mTLS` ctx `CERT_REQUIRED` con `MTLS_ENABLED=true`

## Cómo activar todo

```bash
docker compose -f infra/docker-compose.yml up --build
# Wazuh opcional:
docker compose -f infra/docker-compose.yml --profile wazuh up -d
# mTLS:
MTLS_ENABLED=true docker compose up api siem --force-recreate
```

---
*Documentado para auditoría — ver CHANGELOG.md [0.4.0]*
