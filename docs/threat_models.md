# Threat Model — Mini-SOC (STRIDE + ATT&CK)

## 1. Alcance

Activos: `API` (datos + IAM), `SIEM` (logs/alertas), `Rustyapa` (vulnerable DBMS), `Cloud Audit` (misconfigs), `Storage logs`.

Atacante: tú (post-construcción) — asume red interna pero sin credenciales iniciales.

## 2. STRIDE por Componente

| Componente | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation |
|------------|----------|-----------|-------------|----------------|-----|-----------|
| **API /auth** | JWT none, alg confusion → mitigado RS256 fijo | — | logs con hash-chain evitan repudio | enumeración usuarios → rate-limit + generic msg | brute-force → lockout | MFA bypass → TOTP window 1 |
| **API /records** | IDOR → mitigado check `owner==actor || role>=analyst` | SQLi/XSS → pydantic strict + escape | — | leak via error verbose → handler genérico | large payload 5k → limit 4k | RBAC bypass → decorator test |
| **SIEM** | fake logs → HMAC opcional | log injection `\n` → JSON escape | — | alerts leak → auth analyst+ | flood logs → rate-limit + dedup | — |
| **Rustyapa** | — | heap spray tags | — | info leak via error msg | OOM via 5MB note → cap 4096 | RCE via crafted transaction → monitor |

## 3. ATT&CK Mapping (lo que podrás practicar)

| ID | Táctica | Técnica | Cómo se ve en este SOC | Detección SIEM |
|----|---------|---------|------------------------|----------------|
| T1190 | Initial Access | Exploit Public-Facing App | `labs/rustyapa/exploit.py --stage 1` envía note gigante | `rustyapa_exploit.yml` → payload_len >4096 OR csum anomalía |
| T1110 | Credential Access | Brute Force | `simulate_incident.sh brute-force` 20 logins fail | `brute_force.yml` 5 fails/IP/60s → medium |
| T1078 | Persistence | Valid Accounts | login success tras brute | correlación `brute_force` → `auth_success` mismo IP → high |
| T1548 | PrivEsc | Abuse Elevation | `analyst` intenta `DELETE /admin/users` | `priv_esc_api.yml` → 403 burst |
| T1059 | Execution | CLI | `; cat /app/flag.txt` en note/tags (si RCE) | `exec_in_tags.yml` regex `\$\(|;|flag` |
| T1041 | Exfiltration | Exfil Over C2 | `GET /records?limit=1000` masivo | `large_payload.yml` → bytes_out >100k/10s |
| T1070 | Defense Evasion | Indicator Removal | `DELETE /audit` o clear journal | `audit_tamper.yml` → journal clear |

## 4. Hipótesis Hunting (para `docs/hunting_hypotheses.md`)

Ver archivo dedicado; resumen:

- **H1:** Si Rustyapa es explotado, el `tags` length crece anormalmente antes de `commit` → buscar `tags_len` p95 + `value` jump.
- **H2:** Si API es scrapeada, habrá `user_agent` raro + `rate_limit` hits.
- **H3:** Si IAM wild card existe, `cloud_audit` lo marcará CRITICAL → pivot a `siem` para ver si fue usado.

## 5. Controles Detectivos

Cada fila ATT&CK tiene regla Sigma + test en `api/tests` y `siem/tests`.

## 6. Supuestos y Out-of-scope

- No cubrimos DDoS L7 volumétrico real (solo rate-limit local).
- No mTLS entre servicios en v1 (roadmap).
- Logs en memoria para SIEM demo — prod usaría WORM S3.

---
*Actualiza este archivo tras cada hallazgo de pentest.*
