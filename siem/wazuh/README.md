# Wazuh + OpenSearch Integration

> Implementado `2026-08-31` — `siem/forwarder/opensearch_forwarder.py:1`

## Arquitectura

```
[api] --siem.jsonl--> [forwarder] --_bulk--> [OpenSearch 9200]  <-- Dashboards / Detections
                         |
                         +---> [Wazuh Manager 55000] (opcional, si env WAZUH_HOST)
                         |
                         +--> buffer logs/opensearch_buffer.jsonl (si offline)
```

## Uso

### Local con Docker (recomendado)

```bash
# Añade OpenSearch al compose (ya incluido en infra/docker-compose.yml)
docker compose -f infra/docker-compose.yml up opensearch opensearch-dashboards

# Forward continuo
OPENSEARCH_HOST=localhost OPENSEARCH_PORT=9200 python siem/forwarder/opensearch_forwarder.py

# One-shot test (CI)
python siem/forwarder/opensearch_forwarder.py --once | head -c 2000
```

### Variables

- `OPENSEARCH_HOST` (default `localhost`)
- `OPENSEARCH_PORT` `9200`
- `OPENSEARCH_INDEX` `minisoc-siem`
- `OPENSEARCH_USER/PASS` (default `admin/Minisoc123!` para Wazuh distro)
- `WAZUH_HOST`, `WAZUH_TOKEN` (si usas Wazuh manager externo)

### Wazuh Agent (en host)

```bash
# Instala wazuh-agent y apunta a tu manager, luego:
# El forwarder también puede enviar vía Wazuh API si configuras WAZUH_HOST
```

### Verificación

```bash
curl -u admin:Minisoc123! -k https://localhost:9200/minisoc-siem/_search?pretty | jq
# o http si usas la imagen opensearchproject/opensearch:2.15 sin TLS
curl http://localhost:9200/minisoc-siem/_count
```

### Fallback

Si OpenSearch no responde, los eventos se bufferizan en `logs/opensearch_buffer.jsonl` y se reintentan en siguiente poll (cada 2s).

### SIEM Engine sigue siendo fuente de verdad

El engine Python (`siem/engine/engine.py`) genera alertas Sigma; el forwarder solo replica a OpenSearch/Wazuh para dashboards y correlación centralizada. No rompe el lab si OpenSearch está caído (buffer).

## Dashboards

Importa `siem/dashboards/minisoc_ndjson.ndjson` en OpenSearch Dashboards → Management → Saved Objects.

## Seguridad

- Credenciales por env, no hardcodeadas.
- `infra/docker-compose.yml` crea volumen `opensearch-data`.
- En prod usa TLS + roles (leer `infra/opensearch/README.md`).

---
*Bulk formato ECS + `minisoc` nested para hunting.*
