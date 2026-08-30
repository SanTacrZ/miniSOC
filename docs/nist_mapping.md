# NIST Mapping — Mini-SOC

> Mapeo 1:1 entre controles **NIST SP 800-53 rev5** / **CSF 2.0** y artefactos del repo. Útil para auditoría y entrevista.

## 1. CSF 2.0 → Repo

| Función | Categoría | Artefacto | Evidencia |
|---------|-----------|-----------|-----------|
| **GV.OC** Organización | GV.OC-01 | `docs/architecture.md` | Diagrama + inventario |
| **GV.RM** Riesgo | GV.RM-01/02 | `docs/threat_models.md` | STRIDE + ATT&CK |
| **ID.AM** Asset Mgmt | ID.AM-01 | `infra/docker-compose.yml` | Inventario servicios |
| **PR.AC** Control Acceso | PR.AC-01/04 | `api/app/auth/*`, `rbac/*` | RBAC least privilege |
| **PR.DS** Seguridad Datos | PR.DS-01/02 | TLS, `utils/crypto.py` | Cifrado tránsito/reposo |
| **DE.CM** Monitor Continuo | DE.CM-01/03 | `siem/engine/*`, `parsers/*` | SIEM ingestion |
| **DE.AE** Análisis | DE.AE-02 | `siem/rules/*` | Correlación Sigma |
| **RS.MA** Análisis Incidente | RS.MA-01 | `docs/incident_playbooks.md` | Playbooks SP 800-61 |
| **RC.RP** Plan Recuperación | RC.RP-01 | `labs/evidence/postmortem.md` | Lecciones |

## 2. SP 800-53 rev5 (subset crítico implementado)

### AC — Access Control
- **AC-2 Account Management** → `cloud_audit/iam/checks.py: check_iam_users()` + `api/app/auth/user_store.py` (provision/deprovision, disable inactive >45d)
- **AC-3 Access Enforcement** → `rbac/decorator.py` `@require_role("analyst")`, deny-by-default, tests `api/tests/test_rbac.py`
- **AC-5 Separation of Duties** → roles no solapados: `viewer` no puede `write`, `analyst` no puede `admin:iam` (ver `rbac/roles.yaml`)
- **AC-6 Least Privilege** → cada endpoint declara permisos mínimos; `cloud_audit` marca `iam:*:*` como CRITICAL
- **AC-7 Unsuccessful Logon** → `middleware/rate_limit.py` 5 intentos → 15m lock + log `AU-6`

### AU — Audit and Accountability
- **AU-2 Audit Events** → cada request genera `event_id` en `siem/parsers/api_parser.py` (AU-2 a,b,c)
- **AU-3 Content of Records** → JSON incluye `timestamp, actor, src_ip, user_agent, action, object, result, trace_id`
- **AU-6 Audit Review** → `siem/engine/engine.py` revisa cada 5s, alerta en `auth_fail >=5`
- **AU-9 Protection of Audit Info** → hash-chain `utils/hash_chain.py` (SHA256(prev_hash+event)), WORM `logs/`
- **AU-12 Audit Generation** → `middleware/audit.py` genera antes de la respuesta, no despachable

### IA — Identification & Authentication
- **IA-2 Identification** → JWT `sub` obligatorio, `jti` único (SP 800-63B AAL2)
- **IA-2(1) MFA** → TOTP RFC6238, enrol en `/auth/mfa/setup`, verify en `/auth/mfa/verify` (`auth/mfa.py`)
- **IA-5 Authenticator Management** → argon2id, 12 chars min, no reuse 5, lockout (ver `auth/passwords.py`)
- **IA-8 Identification (non-org)** → API keys opcional con scope limitado (`auth/apikey.py`)

### SC — System & Comms Protection
- **SC-7 Boundary Protection** → `infra/terraform` simula SG `0.0.0.0/0:22` → detectado como fail
- **SC-8 Transmission Confidentiality** → TLS 1.2+ en `infra/docker-compose.yml` (cert self-signed dev), HSTS
- **SC-12 Cryptographic Key Est.** → RS256 keys rotadas cada 90d vía `scripts/rotate_keys.sh`

### SI — System & Information Integrity
- **SI-3 Malicious Code** → SIEM rule `sigma_like/exec_from_tags.yml` detecta payload sospechoso en Rustyapa tags
- **SI-4 System Monitoring** → SIEM engine + `parsers/` cubre API, OS, Rustyapa
- **SI-10 Info Input Validation** → `models/` con `pydantic` strict, `extra=forbid`, regex OWASP (SI-10)

### CM — Configuration Management
- **CM-2 Baseline** → `infra/terraform/*.tf` + `checks/` define baseline y drift
- **CM-6 Settings** → `cloud_audit` compara contra baseline, reporta `storage:public`

### IR — Incident Response (SP 800-61r2)
- **IR-4 Incident Handling** → `docs/incident_playbooks.md` con fases `Preparation → Detection → Containment → Eradication → Recovery → Lessons`
- **IR-6 Reporting** → `siem/engine/responder.py` genera `evidence/timeline.jsonl` + `alerts/`

## 3. SP 800-92 Log Management

Fases implementadas:
1. **Generation** → `api/app/middleware/audit.py` + `labs/rustyapa/wrapper.py` (structured JSON)
2. **Transmission** → filebeat-like `scripts/ship_logs.py` (simulado) → `logs/siem.jsonl`
3. **Storage** → rotación diaria, hash encadenado, retención 30d (AU-11)
4. **Analysis** → `siem/engine/engine.py` normaliza → correlaciona
5. **Disposal** → `scripts/retention.py` borra >30d tras archivado

## 4. SP 800-63B (Digital Identity)

- **MEMORIZED SECRETS**: 8-64 chars, check vs HIBP top 10k (simulado), argon2id
- **MFA**: OTP 6 dígitos, ventana 30s, backup codes 8
- **SESSION**: JWT access 15m, refresh 7d rotation, revoke list en memoria (IR: logout)

## 5. OWASP ASVS 4.0

Mapeo en `api/tests/test_asvs.py`:
- 2.1 Password Security, 2.2 MFA, 2.3 Session, 3.2 Session Binding, 5.1 Input Validation

## 6. ATT&CK Coverage

Ver `docs/threat_models.md` y `siem/rules/`:

| Táctica | Técnica | Regla |
|---------|---------|-------|
| Initial Access | T1190 Exploit Public-Fac. | `rustyapa_exploit.yml` |
| Execution | T1059 CLI | `exec_in_tags.yml` |
| Persistence | T1078 Valid Accounts | `brute_force.yml` |
| Priv Esc | T1068 | `priv_esc_api.yml` |
| Exfil | T1041 | `large_payload.yml` |

---
*Cada control tiene test automatizado — `pytest -m nist`.*
