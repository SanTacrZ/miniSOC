# Break-It Checklist — Para cuando termines de construir, intenta romperlo

> Usa este checklist como atacante purple-team. Cada ítem mapea a control NIST y debe generar alerta.

## API

- [ ] **Auth bypass** — `Authorization: Bearer none` con `alg:none` → debe ser 401 (SC-12)
- [ ] **JWT tamper** — modifica `role` en payload → 401
- [ ] **MFA replay** — reutiliza `code` TOTP en ventana 60s → debe fallar 2º uso si window=1
- [ ] **Brute force** — `scripts/simulate_incident.sh brute-force` → alerta `SOC-001` medium
- [ ] **IDOR** — `viewer` hace `GET /records/{id}` de otro owner → 403 + `SOC-003` si burst
- [ ] **Large payload** — `note` con `; cat /flag` → 200 pero `suspicious_note` + `SOC-004`
- [ ] **Rate limit** — 61 req/min → 429 + `Retry-After`

## Cloud

- [ ] `infra/terraform` con `0.0.0.0/0:22` → `cloud_audit` debe marcar `NET-001 CRITICAL`

## Rustyapa

- [ ] `labs/rustyapa/exploit.py --spray 1000` → `SOC-002` high

Registra cada intento en `labs/evidence/break-YYYY-MM-DD/`
