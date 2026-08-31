# Rustyapa Lab — Vulnerable DBMS instrumentado

> Binario original en `/tmp/rustyapa_inspect/static/RUSTyapa` (copiado a `labs/rustyapa/bin/` en docker). Fuente `src/main.rs:1`.

## Vulnerabilidad (resumen para hunt)

- **Componente:** `run_batch` (`src/main.rs:362`). El binario compilado emite **una** inicialización del slot de pila de `Transaction` pero **dos** llamadas a `Transaction::commit`, y `commit` toma `self` por valor y libera `ops: Vec<u32>` + `payload: Vec<u8>` → la 2ª transacción trabaja sobre buffers liberados (**UAF + doble free**, dos chunks de `0x20`).
- **Disparador:** `Transactions → 3. Batch transfer`. **No** hace falta `Deposit`.
- **Superficie real:** 17 bytes fijos (`"batch-out"` + `"batch-in"`) escritos por el propio binario → **sin payload grande ni metacharacteres**. Por eso `SOC-002` (`payload_len > 4096`) NO lo detecta.
- **Lectura hunting:** `action == "batch"` y/o `abort_signature` de glibc en `stderr_tail` → alerta `SOC-006`. Secundario: `journal_ops == 6 and journal_delta == 0`.
- **Wrapper:** `wrapper.py:1` hace tee JSONL `logs/rustyapa.jsonl` + `/tmp/soc_siem.jsonl`, y desde esta revisión **captura stderr** para registrar el abort de glibc.

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
python -m siem.engine.engine  # o curl http://localhost:8001/alerts
```

## Integración SOC

- **Regla (TTP real):** `siem/rules/sigma_like/rustyapa_batch_uaf.yml:1` → `SOC-006` (`action == batch` → high, `rustyapa_abort` → critical)
- **Regla (lab/simulador):** `siem/rules/sigma_like/rustyapa_exploit.yml:1` → `SOC-002` (`payload_len>4096`) — **falso negativo** contra el exploit real
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
