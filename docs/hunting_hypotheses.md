# Threat Hunting — Hipótesis + Búsqueda + Validación

> Metodología: **Hypothesis → Data → Hunt → Validate → Automate (Sigma)**

Cada hipótesis tiene: *idea, datos necesarios, query SIEM, validación, regla resultante*.

---

## H-01 — Rustyapa Heap Spray via Tags

- **Hipótesis:** Un atacante que explota `Transaction::commit` hará crecer `tags` con payloads grandes y repetirá `deposit` muchas veces antes de `commit` para spray heap. Veremos `payload_len` p95 + `tags_len` escalada.

- **Datos:** `logs/rustyapa.jsonl` → campos `payload_len`, `tags_len_before`, `tags_len_after`, `delta`, `ops_len`.

- **Hunt (jq):**
  ```bash
  jq -s 'map(select(.svc=="rustyapa")) | map(.payload_len) | sort' logs/rustyapa.jsonl | tail
  jq 'select(.svc=="rustyapa" and .payload_len>2000) | {ts, src_ip, payload_len, delta}' logs/rustyapa.jsonl
  ```

- **Validación:** Reproducir con `labs/rustyapa/exploit.py --spray 100 --size 3000` y ver si trigger `rustyapa_exploit.yml` (esperado true positive). Falso positivo: legítimo `note` grande → ajustar threshold a 4096.

- **Automatizar:** `siem/rules/sigma_like/rustyapa_exploit.yml` → `payload_len >4096`.

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
