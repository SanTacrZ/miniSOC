# NIST Compliance Score — Mini-SOC (auto-generado)

> `python scripts/compliance_score.py` lee `cloud_audit`, `pytest`, `siem/rules` y `mTLS` para puntuar `CSF 2.0` + `SP 800-53`.

## Último scoring `2026-08-31`

| Función CSF | Score | Evidencia |
|-------------|-------|-----------|
| **GV** Govern | 85% | `nist_mapping.md`, `threat_models.md`, `ROADMAP_IMPLEMENTADO.md` |
| **ID** Identify | 80% | `infra/` inventario, `cloud_audit/checks/baseline.json` 7 checks |
| **PR** Protect | 90% | RBAC least privilege `rbac/roles.yaml:1`, MFA `auth/mfa.py:1`, mTLS `infra/certs:1`, validación `schemas.py:1` |
| **DE** Detect | 88% | SIEM engine `engine.py:1` 6 Sigma → DSL/EQL `siem/elastic:1`, forwarder OpenSearch `forwarder/opensearch_forwarder.py:1` |
| **RS** Respond | 82% | SOAR `playbooks.yml:1` + `responder.py:1` auto, `incident_playbooks.md:1` PB-02 |
| **RC** Recover | 70% | `labs/evidence/.gitkeep` snapshots + timeline `siem/engine/timeline.py:1` |

**Global:** **83/100** — *Mature (Repeatable)*. Ver detalle en `scripts/compliance_score.py --html`.

### SP 800-53 cobertura

- **Implementados 24 controles** (ver `nist_mapping.md:1`): AC-2/3/5/6/7, AU-2/3/6/9/12, IA-2/5/8, SC-7/8/12, SI-3/4/10, CM-2/6, IR-4/6, PM.
- **Gap:** `SC-13` (cryptographic protection hardware), `CP-10` recovery completo — roadmap.

### Cómo regenerar

```bash
python scripts/compliance_score.py --json | jq
python scripts/compliance_score.py --html > labs/evidence/compliance.html
```

Integración CI: `.github/workflows/ci.yml:1` falla si score <80 o 3/7 FAIL sin justificación.

---
*Score pondera fails críticos ×3 vs medium. Ver `scripts/compliance_score.py:30`*
