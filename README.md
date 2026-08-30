# Mini-SOC — Laboratorio Profesional NIST-Compliant

> **Proyecto personal de nivel internacional** para formación SOC Analyst / Detection Engineer / Cloud Security
> **Stack:** Python 3.14, FastAPI, SIEM Engine propio, RBAC+TOTP MFA, Audit Framework, Rustyapa Pwn Lab
> **Estándares:** NIST CSF 2.0, NIST SP 800-53 rev5, SP 800-92 (Log Management), SP 800-61r2 (Incident Handling), SP 800-63B (Auth), OWASP ASVS 4.0, MITRE ATT&CK

---

## 1. Objetivo

Construir un **Mini-SOC operable** donde:
- **API segura** demuestra `Authentication → Authorization → Validation` con trazabilidad.
- **SIEM** ingesta logs estructurados, correlaciona y genera alertas con severidad/TTPs.
- **Cloud Audit** detecta misconfigs reales (IAM, Network, Storage) inspirado en Prowler/ScoutSuite.
- **Rustyapa** (`labs/rustyapa`) es el sistema vulnerable monitorizado para practicar `Threat Hunting + IR`.
- Todo es **auditable, testeable y rompible** por ti para entrenar ofensiva/defensiva.

---

## 2. Mapa NIST (resumen)

| NIST CSF 2.0 | SP 800-53 | Implementación en este repo |
|--------------|-----------|-----------------------------|
| **GV (Govern)** | PM, RA | `docs/nist_mapping.md`, `threat_models.md` |
| **ID (Identify)** | RA-3, CM-8 | Inventario `infra/`, `cloud_audit/` |
| **PR (Protect)** | AC-2/3/5/6, IA-2/5/8, SC-7/8 | `api/app/auth`, `rbac/`, TLS, validación, MFA |
| **DE (Detect)** | AU-2/6/12, SI-4 | `siem/engine`, `rules/`, `parsers/` |
| **RS (Respond)** | IR-4, IR-6 | `docs/incident_playbooks.md`, `siem/engine/responder.py` |
| **RC (Recover)** | CP-10, IR-4 | Post-incident `labs/evidence` + timeline |

Ver `docs/nist_mapping.md` para matriz completa 1:1 con controles y evidencias.

---

## 3. Arquitectura

```
[ Client ] --> [ FastAPI Secure API ] --structured JSON--> [ SIEM Engine ] --> [ Alerts ]
                     |                                          |
                     +-- auth (JWT+TOTP)                        +-- rules/sigma_like (YAML)
                     +-- rbac (least privilege)                 +-- correlations
                     +-- validation (pydantic strict)           +-- dashboards
                     +-- middleware (audit, rate-limit)

[ Cloud Audit ] --> checks IAM/RBAC/Network/Storage --> [ Findings JSON ] --> [ SIEM ]

[ Labs/Rustyapa ] --wrapper.sh--> tee logs --> [ SIEM parsers ] --> alert "RUSTyapa pwn"
```

- **Logs:** `NIST SP 800-92` JSONL con `timestamp, event_id, actor, action, src_ip, result, mitre_technique, hash_chain`
- **Infra:** `docker-compose.yml` levanta `api:8000`, `siem:8001`, `rustyapa:11331` monitorizado
- **Storage de logs:** `logs/` (no repo) + hash encadenado para integridad (AU-9)

---

## 4. Quick Start

```bash
# 1. Crear venvs e instalar (usa opencrow toolchain si existe)
python3 -m venv .venv && source .venv/bin/activate
pip install -r api/requirements.txt -r siem/requirements.txt -r cloud_audit/requirements.txt

# 2. Levantar todo
docker compose -f infra/docker-compose.yml up --build

# 3. API health
curl -k https://localhost:8000/health  # o http si sin TLS local
curl http://localhost:8000/docs  # OpenAPI

# 4. Crear usuario + MFA enroll (ver api/README)
./scripts/bootstrap_iam.sh

# 5. Ver SIEM en vivo
curl http://localhost:8001/alerts
tail -f logs/siem.jsonl | jq

# 6. Atacar laboratorios
python labs/rustyapa/exploit.py        # ver labs/rustyapa/README.md
./scripts/simulate_incident.sh brute-force
```

---

## 5. Estructura

```
SOC/
├── api/                # Secure API - FastAPI + NIST SP 800-63B
├── siem/               # SIEM engine + Sigma-like rules
├── cloud_audit/        # Audit IAM/Network/Storage misconfigs
├── labs/
│   ├── rustyapa/       # Pwn lab instrumentado (vuln heap/logic)
│   ├── scenarios/      # Escenarios reproducibles (brute, sqli, priv-esc)
│   └── evidence/       # Timelines forenses tras cada run
├── infra/              # docker-compose + terraform con misconfigs intencionales
├── docs/               # NIST mapping, playbooks, hunting hypotheses
└── scripts/
```

---

## 6. Flujo de Entrenamiento SOC (tu loop)

1. **Hunt → Hypothesis:** `docs/hunting_hypotheses.md` te da `Si el atacante explota Rustyapa → buscaré X en logs`.
2. **Simula incidente:** `scripts/simulate_incident.sh rustyapa-pwn` genera tráfico malicioso.
3. **Alerta → Evidence → Timeline:** SIEM crea `alerts/*.json` + `evidence/timeline.jsonl`; tú investigas.
4. **Valida:** ¿True positive? ¿Qué ATT&CK (T1190, T1078, T1211)? ¿Qué control NIST falló?
5. **Rompe la API:** Intenta `auth bypass, IDOR, JWT none, MFA replay` — checklist en `docs/break_it.md`.

Todo queda **loggeado y versionado** — ideal para portfolio / entrevista SOC.

---

## 7. Hardening Checklist (antes de intentar romperlo)

- [x] Passwords `argon2id` (SP 800-63B), JWT RS256 corta vida + refresh rotation
- [x] MFA TOTP (RFC6238) obligatorio para `admin` y `analyst` (IA-2(1))
- [x] RBAC estricto: `viewer < analyst < responder < admin` con least privilege (AC-6)
- [x] Validación estricta `pydantic` + `extra=forbid`, `SQLi/XSS` regex, rate-limit (SC-5)
- [x] Logs firmados hash-chain + WORM `logs/siem.jsonl` (AU-9)
- [x] Headers seguridad: HSTS, CSP, X-Frame (SC-8, SI-4)
- [x] Audit cloud falla si `0.0.0.0/0`, `s3:public`, `iam:*` (CM-6, AC-3)

---

## 8. Próximos pasos (roadmap)

- [ ] Integrar Wazuh / OpenSearch real (ahora engine Python ligero)
- [ ] mTLS entre servicios
- [ ] SOAR playbook auto-isolate (`siem/engine/responder.py`)
- [ ] Exportar Sigma → Elastic

---

## 9. Referencias

- NIST CSF 2.0, SP 800-53 r5, SP 800-92, SP 800-61r2
- OWASP ASVS 4.0, OWASP Top10 2021
- MITRE ATT&CK v14, SigmaHQ
- RFC6238 TOTP, RFC7519 JWT

---

*Autor: Sebastian Botero — Proyecto formativo SOC. Hecho para romperlo.*
