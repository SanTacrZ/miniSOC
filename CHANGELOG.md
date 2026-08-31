# Changelog — Mini-SOC

Todas las notas en formato Keep a Changelog + SemVer. Repo: https://github.com/SanTacrZ/miniSOC

## [0.4.0] - 2026-08-31 — Roadmap Completo (Wazuh/OpenSearch, mTLS, SOAR, Sigma→Elastic)

### Added
- **Wazuh/OpenSearch:** `siem/forwarder/opensearch_forwarder.py` bulk ECS + buffer, `siem/wazuh/README.md`, `infra/opensearch/README.md`, `siem/dashboards/minisoc_ndjson.ndjson`, docker services `opensearch` `opensearch-dashboards` `forwarder` `wazuh` (profile) en `infra/docker-compose.yml`
- **mTLS:** `infra/certs/generate_certs.sh` (CA 4096 + api/siem/client 2048 SAN), `api/app/core/mtls.py`, `api/app/middleware/mtls.py`, `api/app/main.py` integrado, `scripts/rotate_mtls.sh`, `infra/certs/README.md`
- **SOAR auto-isolate:** `siem/engine/playbooks.yml` (3 playbooks), `siem/engine/responder.py` reescrito (block_ip, revoke_jti, snapshot, kill_rustyapa, run_playbook), `siem/engine/engine.py` hook auto en `poll_once`/`main_loop`
- **Sigma→Elastic:** `siem/tools/sigma_to_elastic.py` exports 5 reglas → `siem/elastic/dsl/*.json` + `siem/elastic/eql/*.eql`, `siem/elastic/README.md`

### Verified
- `opensearch_forwarder --once` NDJSON válido, `MTLS_ENABLED=true` ctx CERT_REQUIRED, `simulate_incident` → 10 alertas + `blocklist.json` + snapshots `labs/evidence/rustyapa-*`, `sigma_to_elastic --check` 5/5, `pytest` 9 passed

## [0.3.0] - 2026-08-30 — Cloud Audit + Labs + Infra + Purple Verification

### Added
- `cloud_audit/` — 7 checks NIST (IAM-001/002/003, NET-001/002, STO-001/002) sobre `infra/terraform/main.tf` con misconfigs intencionales; `runner.py` emite `findings.json` → SIEM
- `labs/rustyapa/` — wrapper instrumentado (`wrapper.py:9`), exploits graduados (`exploit.py:1`), README hunting; integrado con `siem/rules/sigma_like/rustyapa_exploit.yml`
- `labs/scenarios/` — `brute_force.py`, `exfil.py` generadores sintéticos para SIEM
- `infra/docker-compose.yml` — api:8000 + siem:8001 + rustyapa:11331 en `soc_net 10.20.0.0/24`
- `infra/terraform/main.tf` — baseline con 4 FAIL críticos (0.0.0.0/0, public bucket, wildcard IAM) para auditar
- `scripts/bootstrap_iam.sh`, `simulate_incident.sh`, `ship_logs.py`
- `siem/Dockerfile`

### Fixed
- Paths `STORE_PATH` y `KEYS_DIR` corregidos a `SOC/infra/*` (4 niveles) — `user_repository.py:10`, `crypto.py:11`
- Tests purple-team ahora 9/9 pass (`test_auth.py:1`, `test_repo_pattern.py:1`)

### Verified (Purple Team)
- `simulate_incident.sh all` → 10 alertas (SOC-001 medium, SOC-002 high x8, SOC-004 medium) + `cloud_audit` 3/7 FAIL
- `pytest api/tests` 9 passed, SIEM engine poll OK, `simulate_incident brute-force/exfil/rustyapa-pwn` OK

## [0.2.0] - 2026-08-30 — Repository Pattern

### Added
- Patrón Repositorio (`api/app/repositories/interfaces.py:8`, `user_repository.py:12`, `record_repository.py:10`, `audit_repository.py:10`)
- Servicios desacoplados `AuthService` (`api/app/services/auth_service.py:12`), `RecordService`
- `docs/repository_pattern.md` — diagrama + migración desde legacy
- `api/app/main.py` refactorizado a v2 (DI via FastAPI Depends), `main_legacy.py` preservado
- `.gitignore` saneado, `infra/keys/README.md`, `CHANGELOG.md`

### Fixed
- Librerías corruptas: `cryptography 44.0.2 → 46.0.5`, `pydantic 2.11.7 → 2.13.5 + core 2.46.5` (wheel cp314). `scripts/check_libs.sh:1` verifica `pip check` OK

### Standards
- NIST CM-14, AC-2, Clean Architecture. Purple-team testeable sin HTTP.

## [0.1.0] - 2026-08-30 — Bootstrap Mini-SOC

### Added
- Estructura inicial SOC: `api/`, `siem/`, `cloud_audit/`, `labs/`, `infra/`, `docs/`
- `api/` FastAPI segura: JWT RS256, MFA TOTP, RBAC least privilege, validación strict, rate-limit, audit hash-chain
- `siem/engine` + 5 reglas Sigma (`brute_force.yml`, `rustyapa_exploit.yml`, `priv_esc_api.yml`, `large_payload.yml`, `audit_tamper.yml`)
- Docs NIST: `nist_mapping.md`, `architecture.md`, `threat_models.md`, `incident_playbooks.md`, `hunting_hypotheses.md`
- Toolchain verificado con `.venv` (Python 3.14)

## [0.5.0] - 2026-08-31 — Purple Team Emulator + Metrics + Compliance + CI

### Added
- **Attack Emulator:** `scripts/attack_emulator.py` 4 chains ATT&CK (full/rustyapa-only/cloud-misconfig/initial-access) 7 TTps T1078/T1110/T1190/T1059/T1548/T1041/T1098 con `src_ip` y `speed`, emite `mitre_technique` a `logs/siem.jsonl` para SIEM
- **Metrics Dashboard:** `siem/dashboards/metrics.py` MTTD/MTTR/P95/SLA P1 (<15m) `by_rule`/`by_severity` + `--html` para `labs/evidence/metrics.html`
- **Compliance Score:** `scripts/compliance_score.py` + `docs/COMPLIANCE_SCORE.md` scoring CSF 6 funciones (global 81/100) desde `cloud_audit`, `pytest`, `mTLS`, `detect`; usado en CI gate
- **CI:** `.github/workflows/ci.yml` purple-team (pip check, pytest, cloud_audit, sigma→elastic, emulator smoke, metrics+compliance gate 75, mTLS verify)
- **IAM JIT:** `api/app/rbac/time_based.py` grant_temporary 4h + auto-revoke AC-2(3) para `responder`

### Verified
- `attack_emulator --chain initial-access` → 7 alerts SOC-002/SOC-001, `metrics --json` MTTD 201s SLA 100%, `compliance --json` global 81, `pytest` 9 passed

