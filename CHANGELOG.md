# Changelog — Mini-SOC

Todas las notas en formato Keep a Changelog + SemVer. Repo: https://github.com/SanTacrZ/miniSOC

## [0.2.0] - 2026-08-30 — Repository Pattern

### Added
- Patrón Repositorio (`api/app/repositories/interfaces.py:8`, `user_repository.py:12`, `record_repository.py:10`, `audit_repository.py:10`)
- Servicios desacoplados `AuthService` (`api/app/services/auth_service.py:12`), `RecordService`
- `docs/repository_pattern.md` — diagrama + migración desde legacy
- `api/app/main.py` refactorizado a v2 (DI via FastAPI Depends), `main_legacy.py` preservado
- `.gitignore` saneado, `infra/keys/README.md`, `CHANGELOG.md`

### Fixed
- Librerías corruptas: `cryptography 44.0.2 → 46.0.5`, `pydantic 2.11.7 → 2.13.5 + core 2.46.5` (wheel cp314). `scripts/check_libs.sh:1` verifica `pip check` OK

### Standards
- NIST CM-14, AC-2, Clean Architecture. Purple-team testeable sin HTTP.

## [0.1.0] - 2026-08-30 — Bootstrap Mini-SOC

### Added
- Estructura inicial SOC: `api/`, `siem/`, `cloud_audit/`, `labs/`, `infra/`, `docs/`
- `api/` FastAPI segura: JWT RS256, MFA TOTP, RBAC least privilege, validación strict, rate-limit, audit hash-chain
- `siem/engine` + 5 reglas Sigma (`brute_force.yml`, `rustyapa_exploit.yml`, `priv_esc_api.yml`, `large_payload.yml`, `audit_tamper.yml`)
- Docs NIST: `nist_mapping.md`, `architecture.md`, `threat_models.md`, `incident_playbooks.md`, `hunting_hypotheses.md`
- Toolchain verificado con `.venv` (Python 3.14)

