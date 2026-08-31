# Threat Hunting — Hipótesis + Búsqueda + Validación

> Metodología: **Hypothesis → Data → Hunt → Validate → Automate (Sigma)**

Cada hipótesis tiene: *idea, datos necesarios, query SIEM, validación, regla resultante*.

---

## H-01 — Rustyapa: UAF vía Batch transfer (sin payload grande)

- **Hipótesis (corregida):** El exploit real **no** hace heap spray con payloads
  grandes. `run_batch` inicializa el slot de `Transaction` una vez y llama dos
  veces a `commit(self)` (que libera `ops`+`payload`) → UAF y doble free sobre
  dos chunks de `0x20`. Basta **una** llamada a `Transactions → 3. Batch
  transfer` con `payload_len=17`. Veremos `action == "batch"` y/o un abort de
  glibc en stderr, **no** `payload_len` elevado.

- **Por qué la hipótesis anterior fallaba:** asumía spray vía `Deposit`
  (`payload_len > 4096`). Eso sólo ocurre en el simulador del lab. Contra el TTP
  real, `SOC-002` es un **falso negativo**.

- **Datos:** `logs/rustyapa.jsonl` → `action`, `abort_signature`, `stderr_tail`,
  `returncode`, `src_ip`, `journal_ops`, `journal_delta`.

- **Hunt (jq):**
  ```bash
  # 1) Uso de la superficie vulnerable (raro en operación legítima)
  jq 'select(.svc=="rustyapa" and .action=="batch") | {ts, src_ip, payload_len, delta}' logs/rustyapa.jsonl

  # 2) Abort de glibc = corrupción de heap confirmada
  jq 'select(.action=="rustyapa_abort") | {ts, src_ip, abort_signature, returncode}' logs/rustyapa.jsonl

  # 3) Fase de leak: ráfaga de conexiones cortas del mismo origen
  jq -r 'select(.svc=="rustyapa") | "\(.src_ip) \(.action)"' logs/rustyapa.jsonl \
    | sort | uniq -c | sort -rn | head

  # 4) Anomalía de journal: la 2ª transacción sale ops=6 delta=0
  jq 'select(.journal_ops==6 and .journal_delta==0)' logs/rustyapa.jsonl
  ```

- **Validación (true positive real):**
  ```bash
  # genera el TTP real: batch (17 bytes) + abort
  python labs/rustyapa/wrapper.py --simulate-batch
  # contra el binario de verdad (el abort lo captura el wrapper):
  printf '3\n3\n0\n1\n100\n0\n0\n' | python labs/rustyapa/wrapper.py --binary ./labs/rustyapa/RUSTyapa
  ```
  Esperado: `SOC-006` `high` por el `batch` y `critical` por el abort.
  Falso positivo a vigilar: restart del jail con `returncode -6` por OOM →
  descartar comprobando que `abort_signature` sea una cadena de glibc.

- **Automatizar:** `siem/rules/sigma_like/rustyapa_batch_uaf.yml` →
  `SOC-006-rustyapa-batch-uaf`, con rama propia en
  `siem/engine/engine.py:check_sigma_rules` (el motor despacha por `rule_id`,
  no evalúa Sigma de forma genérica) y disparo de `PB-RUSTYAPA-AUTO`.

---

## H-02 — Brute Force que escala a Valid Account

- **Hipótesis:** Tras 5 fallos, el atacante prueba credential stuffing y logra login válido → secuencia `fail×5` → `success` mismo IP en <5m.

- **Datos:** `logs/siem.jsonl` `auth_fail` + `auth_success`.

- **Hunt:**
  ```bash
  python siem/engine/hunt.py --hypothesis brute_then_success --window 300
  # o manual jq:
  jq -s 'group_by(.src_ip) | map(select( map(select(.action=="auth_fail")) | length >=5 and any(.action=="auth_success")))' logs/siem.jsonl
  ```

- **Validación:** `scripts/simulate_incident.sh brute-then-success` debe generar alerta `high`. Si no, bajar threshold a 3.

---

## H-03 — IAM Wildcard No Detectado

- **Hipótesis:** Existe `iam:PolicyStatement Effect:Allow Action:* Resource:*` en `infra/terraform` que `cloud_audit` no marcó.

- **Datos:** `cloud_audit/findings.json` + `infra/terraform/*.tf`.

- **Hunt:**
  ```bash
  python cloud_audit/checks/runner.py --verbose | jq '.[] | select(.id=="IAM-001")'
  grep -R "Action.*\*" infra/terraform/
  ```

- **Validación:** Introducir `Action: "*"` a propósito → debe salir `CRITICAL FAIL`.

---

## H-04 — Exfiltration via API Scraping

- **Hipótesis:** Un `viewer` comprometido hará `GET /records?limit=1000` repetido → `bytes_out` alto y `user_agent` anómalo.

- **Hunt:**
  ```bash
  jq 'select(.action=="read_records" and .bytes_out>50000) | {ts, actor, bytes_out, ua}' logs/siem.jsonl
  ```

- **Validación:** `scripts/simulate_incident.sh exfil` genera 10 requests → debe trigger `large_payload.yml`.

---

## H-05 — Defense Evasion — Journal Clear

- **Hipótesis:** Atacante con acceso a Rustyapa limpia `journal` para borrar rastro → evento `journal_clear` seguido de `commit` anómalo.

- **Hunt:**
  ```bash
  jq 'select(.action=="journal_clear")' logs/rustyapa.jsonl
  ```

---

## Cómo usar

1. Elige hipótesis, ejecuta hunt query.
2. Si encuentras señal, crea `labs/evidence/hunt-<id>/` con query + resultado + timeline.
3. Si validas TP, convierte a regla Sigma en `siem/rules/`.

---
*Documenta tus hallazgos como lo harías en un SOC real — esto es tu portfolio.*
