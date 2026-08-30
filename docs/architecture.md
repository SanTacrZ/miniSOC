# Arquitectura — Mini-SOC

## 1. Diagrama (C4 — Context)

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Mini-SOC (DockerNet 10.20.0.0/24)            │
│                                                                      │
│  ┌──────────┐   JSONL    ┌──────────┐  alerts  ┌──────────┐          │
│  │ Secure   │───────────►│  SIEM    ├──────────►│ Evidence │          │
│  │ API :8000│            │ Engine   │           │ & Alerts │          │
│  └────┬─────┘            │ :8001    │           └────┬─────┘          │
│       │                  └────▲─────┘                │                │
│       │                       │                      │                │
│  ┌────▼─────┐            ┌────┴─────┐           ┌───▼──────┐         │
│  │ Cloud    │───────────►│ Parsers  │◄──────────│ Dash     │         │
│  │ Audit    │  findings  └──────────┘   logs    └───┬──────┘         │
│  └──────────┘                                        │                │
│  ┌──────────┐   raw+wrapper   ┌──────────┐           │                │
│  │ Rustyapa │────────────────►│ Wrapper  │───────────┘                │
│  │ :11331   │   tee logs      │ Monitor  │                            │
│  └──────────┘                 └──────────┘                            │
└──────────────────────────────────────────────────────────────────────┘
                              ▲
                         atacante (tú)
```

## 2. Componentes

### 2.1 Secure API (`api/`)

- **Framework:** FastAPI 0.115, Uvicorn, Pydantic v2 strict
- **Endpoints:**
  - `POST /auth/login` → JWT + refresh (IA-2)
  - `POST /auth/mfa/setup` → QR TOTP, `POST /auth/mfa/verify` (IA-2(1))
  - `GET /users/me`, `GET /admin/users` (RBAC)
  - `POST /records`, `GET /records/{id}` (validación + RBAC)
  - `POST /audit/search` (solo `analyst+`)
  - `GET /health` (no auth)
- **Middleware:**
  - `audit.py` → genera evento AU-3 antes de responder
  - `rate_limit.py` → token bucket 60/min por IP (SC-5, AC-7)
  - `security_headers.py` → HSTS/CSP/X-Frame (SC-8)
  - `trace.py` → `X-Request-ID` + hash-chain

### 2.2 SIEM Engine (`siem/`)

- **Ingest:** `parsers/api_parser.py`, `parsers/rustyapa_parser.py`, `parsers/cloud_audit_parser.py` leen `logs/*.jsonl` cada 1s (inotify-sim).
- **Normalize:** ECS-like schema `siem/engine/normalize.py` → `event.action`, `user.name`, `source.ip`, `mitre.*`
- **Correlate:** `engine.py` aplica:
  - Sigma-like YAML en `rules/sigma_like/*.yml` (e.g., `brute_force.yml` → 5 fails/IP/60s)
  - `rules/correlations/*.py` (stateful, ej: `priv_esc_chain` → login fail → success → admin action)
- **Alert:** severity `low|medium|high|critical`, `confidence`, `mitre_attack`, `evidence_refs`, escribe `alerts/alert-<ts>.json`, también `timeline.jsonl`
- **Responder:** `engine/responder.py` (opcional auto-containment: bloquea IP en memoria)

### 2.3 Cloud Audit (`cloud_audit/`)

- **Checks JSON:** `checks/baseline.json` define desired-state. Cada check retorna `{id, title, severity, status: PASS|FAIL, resource, remediation}`.
- **IAM:** `iam/checks.py` → `IAM-001 wildcard`, `IAM-002 inactive >45d`, `IAM-003 no MFA`, `IAM-004 overprivileged`
- **Network:** `network/checks.py` → `NET-001 0.0.0.0/0:22`, `NET-002 unrestricted egress`, `NET-003 no flow logs`
- **Storage:** `storage/checks.py` → `STO-001 public bucket`, `STO-002 unencrypted`, `STO-003 versioning off`
- **Runner:** `checks/runner.py` ejecuta todos, salida `findings.json` → ingerido por SIEM

### 2.4 Labs / Rustyapa (`labs/`)

- **Original:** `static/RUSTyapa` (Rust DBMS). Vulnerabilidad: lógica en `Transaction::commit` + manejo tags (`Vec<u8>` extend) + `active` y `target` controlables desde `deposit/note`. Wrapper lo hace observable.
- **Wrapper:** `labs/rustyapa/wrapper.py` lanza binario con `pty`, hace `tee` a `logs/rustyapa.jsonl` en formato SIEM (timestamp, src_ip, payload_len, action).
- **Exploits:** `labs/rustyapa/exploit.py` contiene PoCs graduados: `info_leak → heap spray → control flow` (documentado en `labs/rustyapa/README.md`).
- **Scenarios:** `labs/scenarios/*.py` generan ruido background + ataque para que SIEM discrimine.

## 3. Flujo de Datos (Log Lifecycle SP 800-92)

1. **Generation:** API `audit` middleware + rustyapa wrapper → JSONL por línea, inmediatamente `fsync`
2. **Transmission:** `scripts/ship_logs.py` tail → SIEM (en dev es file read; en prod sería Filebeat → OpenSearch)
3. **Storage:** `/logs` rotación `siem-YYYY-MM-DD.jsonl`, hash-chain `prev_hash = sha256(prev_hash+raw_line)`
4. **Analysis:** SIEM normaliza → correlaciona → alerta
5. **Disposal:** `scripts/retention.py` archiva gzip >30d

## 4. Seguridad por Capas

| Capa | Control | Implementación |
|------|---------|---------------|
| Red | Segmentation | Docker net `soc_net` aislada, solo `api:8000` y `siem:8001` expuestos |
| Host | Hardening | Dockerfile `USER nonroot`, `readOnlyRootFilesystem`, `seccomp` |
| App | Auth/AuthZ | JWT RS256, TOTP, RBAC deny-by-default |
| Data | Input Validation | Pydantic strict, regex `^[a-zA-Z0-9_\- ]{1,64}$`, length caps |
| Audit | Integrity | hash-chain + firma HMAC opcional |

## 5. Decisiones Técnicas

- **Por qué FastAPI y no Flask?** Async, validación nativa, OpenAPI, performance → estándar industria.
- **Por qué SIEM propio y no ELK?** Para aprender reglas Sigma/correlación desde cero; luego migrar a Wazuh/OpenSearch sin cambiar formato (logs ya ECS-like).
- **Por qué Rustyapa instrumentado y no solo k8s?** Permite `ATT&CK T1190` real con trazas observables, perfecto para hunting.

## 6. Puertos

- `8000` API, `8001` SIEM dashboard (simple HTML), `11331` Rustyapa (jail)

## 7. Escalabilidad

- SIEM engine es stateless excepto `engine/state.json` para correlaciones → puede horizontalizar.
- API logs → `stdout` + file → compatible con Loki/ELK.

---
*Diagrama editable: `docs/architecture.drawio` (próximo).*
