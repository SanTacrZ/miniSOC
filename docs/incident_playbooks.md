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

## PB-02 — Rustyapa Exploit (`T1190`) — UAF en `run_batch`

> **Severidad `P1 critical`** cuando hay abort de glibc; `P2 high` si sólo aparece `Batch transfer`.
> Actualizado con el análisis real del binario (`rustc 1.96.1`, glibc 2.42).

### Root cause (lo que de verdad pasa)

El binario compilado de `run_batch` inicializa el slot de pila de `Transaction`
**una vez** pero llama **dos veces** a `Transaction::commit(self)`, y `commit`
toma `self` por valor y libera `ops: Vec<u32>` y `payload: Vec<u8>`:

```
objdump: Transaction::new() en 0x15cf7 / 0x173c7 / 0x176e4   (3)
         commit()           en 0x15e14 / 0x17524 / 0x17812 / 0x17924  (4)
```

La 2ª transacción reutiliza buffers ya liberados → **UAF + doble free** sobre dos
chunks de `0x20`. Disparador: `Transactions → 3. Batch transfer`.

### Kill chain observada

| Fase | Acción del atacante | Señal |
|---|---|---|
| 1 | `3 → 3 → src=0 dst=1 amount=100` | `action: batch` — **17 bytes**, sin metachars |
| 2 | Navega 1-2 menús | `malloc(): unaligned fastbin chunk detected 3` (glibc 2.42) |
| 3 | Sale con `0` | `free(): double free detected in tcache 2` |
| 4 | Reconecta ~6× repitiendo 1 | ráfaga de conexiones cortas desde el mismo `src_ip` |
| 5 | Con el heap base filtrado, envenena el tcache | RCE → `cat /app/flag.txt` |

Fase 4 es la huella de red: el leak del heap sólo es legible cuando los 8 bytes
del puntero `fd` sobreviven a `String::from_utf8_lossy`, así que el atacante
**reconecta hasta acertar** (~6 intentos, medidos).

### Detección

- **Regla nueva:** `siem/rules/sigma_like/rustyapa_batch_uaf.yml` → `SOC-006-rustyapa-batch-uaf`
  - `action == "batch"` → `high`
  - `action == "rustyapa_abort"` → `critical`
- **⚠️ Gap cerrado:** `SOC-002` (`payload_len > 4096`) **NO detecta este ataque**.
  El payload real son 17 bytes fijos que escribe el propio binario; el atacante
  nunca envía un payload grande. `SOC-002` sólo salta con el spray sintético del
  lab → falso negativo en el TTP real.
- IOC de alta fidelidad (stderr del jail / `rustyapa_abort.stderr_tail`):
  - `free(): double free detected in tcache 2`
  - `malloc(): unaligned fastbin chunk detected 3` (glibc 2.42)
  - `malloc(): unaligned tcache chunk detected` (glibc 2.43)
  - `returncode == -6` (SIGABRT)

### Análisis

1. Alerta → `alerts/alert-<id>.json`; evidencia en `logs/rustyapa.jsonl`.
2. Confirmar el TTP real (no el simulado):
   ```bash
   jq 'select(.svc=="rustyapa" and (.action=="batch" or .action=="rustyapa_abort"))' logs/rustyapa.jsonl
   jq 'select(.action=="rustyapa_abort") | {ts, src_ip, abort_signature, returncode}' logs/rustyapa.jsonl
   ```
3. Fase de leak (conexiones cortas en ráfaga):
   ```bash
   jq -r 'select(.svc=="rustyapa") | .src_ip' logs/rustyapa.jsonl | sort | uniq -c | sort -rn | head
   ```
   > 5 conexiones cortas del mismo IP en <2 min = leak loop en curso.
4. Timeline: `python siem/engine/timeline.py --alert alerts/alert-<id>.json`.
5. Anomalía de journal (observable en `Journal → 1`): el `commit` de la 2ª
   transacción sale con **`ops=6 delta=0`** en vez de `ops=3 delta=<amount>`,
   porque reutiliza el struct viejo (`3+3` ops, `-amount + amount`).

### Contención

- Automática: `PB-RUSTYAPA-AUTO` (`playbooks.yml`) → `block_ip` 3600s +
  `kill_rustyapa` + `snapshot_evidence`. Dispara con `SOC-002` **o** `SOC-006`.
- Manual: `python -c "from siem.engine.responder import run_playbook; run_playbook({'rule_id':'SOC-006-rustyapa-batch-uaf','severity':'critical','alert_id':'manual'})"`

### Erradicación

El problema **no** es la longitud del `note` — parchear eso no corta el ataque.
Opciones, de mejor a peor:

1. **Código:** en `run_batch`, construir un `Transaction` nuevo por cada
   `transaction(...)` (o pasar `&mut self` a `commit` y no liberar dos veces).
   Verificar compilando el fuente con `rustc 1.96.1` y comprobando que el
   codegen emite **2** inicializaciones.
2. **Binario:** recompilar con un toolchain que no reutilice el slot
   (reproducido: con 1.97.x no se reproduce el fallo).
3. **Compensatorio:** el wrapper debe denegar `Batch transfer` (menú `3 → 3`) o
   reiniciar el jail tras N=1 usos — es la única superficie del UAF.

### Recuperación / Lecciones

- Rotar el flag y cualquier credencial del jail; el exploit termina en lectura
  de `/app/flag.txt`.
- Postmortem en `labs/evidence/postmortem.md` con MITRE `T1190` + `T1068`.
- Lección de detección: **una regla basada en tamaño de payload asume el TTP
  equivocado**. Validar siempre contra el exploit real, no contra el simulador.

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
