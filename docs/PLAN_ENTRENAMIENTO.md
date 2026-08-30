# Plan de Entrenamiento SOC — 4 Semanas (Purple Team)

## Semana 1 — Fundamentos + API
- Día 1: `docs/nist_mapping.md` + `architecture.md` + correr `check_libs.sh` + `pytest`
- Día 2: Romper API (docs/break_it.md) — JWT none, IDOR viewer, rate-limit
- Día 3: Hunt H-02 (brute_then_success) con `hunting_hypotheses.md`
- Entregable: `labs/evidence/week1/` con timeline + postmortem

## Semana 2 — SIEM & Detección
- Crear tu propia regla Sigma (ej: `user_agent curl` → alerta)
- Ajustar thresholds (payload_len 4096 → 2048 y medir FP)
- Simular `exfil` + validar `SOC-004`

## Semana 3 — Cloud Audit
- Introducir nueva misconfig en `infra/terraform` y ver FAIL
- Remediar (cerrar 0.0.0.0/0) y re-auditar hasta PASS

## Semana 4 — Rustyapa Pwn + IR
- Explota Rustyapa nivel 1-3, genera alerta SOC-002, haz timeline con `siem/engine/timeline.py`
- Escribe postmortem en `labs/evidence/rustyapa-YYYYMMDD/` siguiendo `incident_playbooks.md#PB-02`
- Propón fix en `wrapper.py` (cap 4096) y verifica que ya no alerta con payload legítimo

### Evaluación purple-team
Cada semana: `bash scripts/simulate_incident.sh all` + `pytest` + `python -m cloud_audit.checks.runner` debe seguir verde.
