# mTLS — CA + Certs para Mini-SOC

> Generado por `infra/certs/generate_certs.sh`. No commitear `*.key` reales (solo `.pub`/`.crt` de ejemplo).

## Estructura

```
infra/certs/
├── ca.key / ca.crt          # CA raíz (self-signed)
├── ca.srl
├── api.key / api.crt        # server api:8000 (CN=api)
├── siem.key / siem.crt      # server siem:8001 (CN=siem)
├── client.key / client.crt  # cliente (forwarder, tests)
└── generate_certs.sh
```

## Uso

```bash
bash infra/certs/generate_certs.sh  # regenera todo (RSA 2048, 365d)
# Verifica
openssl verify -CAfile infra/certs/ca.crt infra/certs/api.crt
```

## FastAPI mTLS

- **Server:** `api/app/core/mtls.py` carga `ca.crt` como truststore, exige `client.crt` si `MTLS_ENABLED=true`.
- **Cliente (forwarder, tests):** usa `ssl_context.load_cert_chain(client.crt, client.key)` + `ca.crt`.

## Docker

Volúmenes en `docker-compose.yml` montan `infra/certs` read-only en `/certs`.

## Rotación

`scripts/rotate_mtls.sh` → re-genera + reinicia servicios. En prod usar Vault/Step-CA.

## Verificación

```bash
curl --cacert infra/certs/ca.crt --cert infra/certs/client.crt --key infra/certs/client.key https://localhost:8000/health
# Sin cert debe dar 400 TLS handshake failure si MTLS_ENABLED=true
```

---
*CN/SAN: `api`, `siem`, `localhost`, `127.0.0.1` — ver `generate_certs.sh:30`.*
