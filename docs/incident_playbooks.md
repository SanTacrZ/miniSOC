# Incident Playbooks — SP 800-61r2

> Cada playbook sigue: **Preparation → Detection & Analysis → Containment → Eradication → Recovery → Lessons Learned**
> Severidades: `P4 low` → `P1 critical`. SLA: P1 <15m, P2 <1h.

---

## PB-01 — Brute Force API (`T1110`)

**Detección:** SIEM `brute_force.yml` → 5× `auth_fail` mismo `src_ip` en 60s → alerta `medium`.

**Análisis:**
1. Abrir `alerts/alert-*.json` → extraer `src_ip`, `user_agent`, `attempted_users`.
2. `jq 'select(.event.action=="auth_fail")' logs/siem.jsonl | grep <ip>`
3. Ver `timeline.jsonl` para ver si hubo `auth_success` después (→ `high`).

**Contención:**
- Automática: `rate_limit` bloquea IP 15m.
- Manual: `curl -X POST http://localhost:8001/contain -d '{"ip":"1.2.3.4"}'` (añade a blocklist).

**Erradicación/Recuperación:** Forzar reset password usuarios objetivo, revisar `cloud_audit` por credenciales débiles.

**Lecciones:** ¿Por qué no había MFA? → Enforce `IA-2(1)` en `rbac/roles.yaml`.

---

## PB-02 — Rustyapa Exploit (`T1190`)

**Detección:** `rustyapa_exploit.yml` → `payload_len >4096` OR `tags` con `; | $()` OR `row.value` delta anormal.

**Análisis (SOC Analyst loop):**
1. **Alerta** → `evidence/rustyapa_<ts>/alert.json`
2. **Evidencia** → `logs/rustyapa.jsonl` líneas con `event_id` correlacionado.
3. **Timeline:** `python siem/engine/timeline.py --alert alert-xyz.json` genera `timeline.jsonl` ordenado.
4. **Hunt:** ¿Hay `commit` con `delta` negativo grande seguido de `value` jump? → verifica `journal` de Rustyapa.
5. **Valida:** Reproducir en `labs/rustyapa/` con mismo payload (`exploit.py --replay <hex>`).

**Contención:** Wrapper mata proceso Rustyapa y reinicia con `jail` fresh (`labs/rustyapa/wrapper.py --restart`).

**Erradicación:** Parchear validación `note` length en `wrapper.py` (defensa delante del binario vulnerable) o firewall payload.

**Lecciones:** Documentar en `labs/evidence/postmortem.md` con MITRE `T1190`.

---

## PB-03 — Privilege Escalation API (`T1548`)

**Detección:** `priv_esc_api.yml` → `analyst` recibe múltiples `403` en `/admin/*` → `medium`, si luego `200` → `critical`.

**Análisis:** `jq 'select(.event.action=="authz_fail" and .user.role=="analyst")' logs/siem.jsonl`

**Contención:** Revocar JWT (`siem/engine/responder.py --revoke <jti>`).

---

## PB-04 — Cloud Misconfig Explotada

**Detección:** `cloud_audit` genera `FAIL` CRITICAL + SIEM correlaciona con `auth_success` desde IP externa.

**Análisis:** `cat cloud_audit/findings.json | jq '.[] | select(.status=="FAIL")'`

**Contención:** `scripts/remediate_cloud.sh` aplica baseline (cierra `0.0.0.0/0`).

---

## Plantilla Timeline (forense)

Cada incidente genera `labs/evidence/<id>/timeline.jsonl`:

```json
{"ts":"2026-08-30T12:00:01Z","actor":"1.2.3.4","action":"auth_fail","object":"user:admin","result":"fail","alert_id":"abc","mitre":"T1110"}
{"ts":"2026-08-30T12:00:45Z","actor":"1.2.3.4","action":"auth_success","object":"user:admin","result":"success"}
```

Usa `siem/engine/timeline.py` para ordenar y `evidence/reconstruct.py` para play-by-play.

---

## Contacto y Roles (simulado)

- **L1 Analyst:** triage alertas `low/medium`
- **L2 Responder:** contención `high`
- **IR Lead:** `critical` + postmortem

*En este lab tú eres los tres — practica escalado.*
