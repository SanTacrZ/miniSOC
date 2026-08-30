# Rustyapa Lab — Vulnerable DBMS instrumentado

> Binario original en `/tmp/rustyapa_inspect/static/RUSTyapa` (copiado a `labs/rustyapa/bin/` en docker). Fuente `src/main.rs:1`.

## Vulnerabilidad (resumen para hunt)

- **Componente:** `Transaction::commit` (`src/main.rs:103`) hace `row.tags.extend(payload)` y `row.value += delta` con `target, delta, payload` controlados por atacante vía `Transactions → Deposit` (`src/main.rs:337`).
- **Superficie:** `prompt_raw("note: ")` lee línea cruda sin límite, `payload` puede ser 5k+ → `tags` Vec<u8> crece sin cap.
- **Lectura hunting:** `payload_len` grande + `delta` anómalo + `tags_len_after` escalado → alerta `SOC-002`.
- **Wrapper:** `wrapper.py:1` hace tee JSONL `logs/rustyapa.jsonl` + `/tmp/soc_siem.jsonl` para SIEM.

## Uso

```bash
# 1. Lanzar binario instrumentado
python labs/rustyapa/wrapper.py --binary ./labs/rustyapa/RUSTyapa

# 2. Simular logs sin binario (CI)
python labs/rustyapa/wrapper.py --simulate

# 3. Explotar graduado
python labs/rustyapa/exploit.py --level 2 --spray 5 --size 5000
# level 1 = enum, 2 = spray heap, 3 = shell chars

# 4. Ver detección
cat logs/rustyapa.jsonl | jq
python siem/engine/engine.py  # o curl http://localhost:8001/alerts
```

## Integración SOC

- **Regla:** `siem/rules/sigma_like/rustyapa_exploit.yml:1` → `payload_len>4096` OR `note contains '; $('`
- **Playbook:** `docs/incident_playbooks.md#PB-02`
- **Hipótesis:** `docs/hunting_hypotheses.md#H-01`

## Artefactos

- `bin/RUSTyapa` — binario (no commiteado, se monta)
- `exploit.py` — PoCs graduados
- `wrapper.py` — instrumentación SIEM

## Flags

- `flag.txt` en `/app/flag.txt` dentro del jail (simulado `kaspersky{test}`).
- Para CTF real: `docker-compose up rustyapa` expone `11331`.

## Seguridad del lab

- Wrapper no parchea binario, solo observa (defense-in-depth: en prod añadir `wrapper.py` validación `note` len 4096).
- Jail (`pwn.red/jail`) limita PIDs, mem, tiempo.

---
*Para purple-team: primero explota, luego mira `siem/engine/timeline.py` y escribe postmortem en `labs/evidence/`.*
