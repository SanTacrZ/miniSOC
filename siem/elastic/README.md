# Elastic Export — Sigma → DSL/EQL

> Generado por `siem/tools/sigma_to_elastic.py:1`

## Generar

```bash
python siem/tools/sigma_to_elastic.py --check
ls siem/elastic/dsl/   # DSL JSON
ls siem/elastic/eql/   # EQL para timeline
```

## Ejemplo DSL (SOC-002)

` s iem/elastic/dsl/SOC-002-rustyapa-exploit.json`:
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"minisoc.svc": "rustyapa"}},
        {"bool": {"should": [
          {"range": {"minisoc.payload_len": {"gt": 4096}}},
          {"wildcard": {"minisoc.note": "*;*"}}
        ]}}
      ]
    }
  }
}
```

## Importar en Elastic / Kibana

- **DSL:** Dev Tools → `POST minisoc-siem/_search` con el JSON.
- **EQL:** Security → Rules → Create EQL rule → pega `siem/elastic/eql/SOC-001-brute-force.eql`.

## Mapeo campos

| Sigma | ECS / minisoc |
|-------|---------------|
| `svc` | `minisoc.svc` |
| `action` | `event.action` |
| `src_ip` | `source.ip` |
| `actor` | `user.name` |
| `payload_len` | `minisoc.payload_len` |
| `result` | `event.outcome` |

Los DSL conservan `meta.rule_id` y `meta.mitre` para trazabilidad NIST.

## CI

`--check` valida JSON y estructura `query` — usado en `pytest`.

---
*Reglas fuente: `siem/rules/sigma_like/*.yml` (5 reglas T1110/T1190/T1548/T1041/T1070).*
