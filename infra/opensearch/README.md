# OpenSearch infra

Ver `infra/docker-compose.yml` → servicios `opensearch` y `opensearch-dashboards`.

Levantar:

```bash
docker compose -f infra/docker-compose.yml up -d opensearch opensearch-dashboards
```

Esperar health:

```bash
curl http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=30s
```

Credenciales por defecto (cambiar en prod): `admin/Minisoc123!` si usas imagen Wazuh, o sin auth para `opensearchproject/opensearch:2.15` en dev.

Índice: `minisoc-siem` creado por `siem/forwarder/opensearch_forwarder.py`.
