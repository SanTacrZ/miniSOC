# Patrón Repositorio — Mini-SOC API

> Implementado `2026-08-30` siguiendo Clean Architecture + DDD. Ver `api/app/main.py` (v2).

## 1. Por qué Repositorio

**ANTES (`main_legacy.py`)** — lógica acoplada:
```
main.py → user_store (global dict) → auth/jwt → middleware
         ↘ store.py (global dict)
```
- Difícil testear (necesita HTTP)
- Persisitencia acoplada a controllers
- No cumple SRP / DI

**AHORA (`main.py` v2 + `repositories/` + `services/`)**:
```
HTTP Controller (main.py)
   → Service (auth_service, record_service) — reglas de negocio puras
       → Repository Interface (interfaces.py) — contrato
           → Impl: FileUserRepository, InMemoryRecordRepository, FileAuditRepository
```
Beneficios NIST CM-14 + mantenibilidad:
- **Testabilidad purple-team:** `AuthService` testeable sin FastAPI (`tests/test_auth_service.py`).
- **Inversión de dependencias:** servicios dependen de `IUserRepository`, no de `FileUserRepository` → fácil mock para IR drills.
- **Least privilege en datos:** cada repo encapsula validación (AC-2).

## 2. Diagrama

```
[ FastAPI Routes ] --depends--> [ Service ]
                                      |
                        +-------------+-------------+
                        |             |             |
                   IUserRepository IRecordRepository IAuditRepository
                        |             |             |
                   FileUserRepo  InMemRecordRepo FileAuditRepo
                        |             |             |
                   infra/users.json  memory    logs/siem.jsonl (hash-chain AU-9)
```

## 3. Interfaces

Ver `api/app/repositories/interfaces.py:8`:

- `IUserRepository` — `get_by_username`, `create`, `update`, `set_last_login`
- `IRecordRepository` — `create`, `get`, `list`, `update`, `delete`
- `IAuditRepository` — `emit(event) -> hash`, `search`

## 4. Implementaciones

### `user_repository.py:12` — `FileUserRepository`
- Thread-safe `RLock`
- JSON persist `infra/users.json` (chmod 600)
- Seed via `seed_if_empty` (bootstrap IAM)
- Método `update(**fields)` genérico para MFA, lockout

### `record_repository.py:10` — `InMemoryRecordRepository`
- Dict + incremental ID + lock
- Futura migración a Postgres: solo crear `PostgresRecordRepository implements IRecordRepository`

### `audit_repository.py:10` — `FileAuditRepository`
- `emit` genera `canonical -> hash_chain -> JSONL fsync` (AU-9)
- `search` filtra últimas 1000 líneas

## 5. Servicios

### `auth_service.py:12` — `AuthService`
- Inyecta `users` + `audit`
- Métodos:
  - `authenticate(username,password,src_ip,ua)` → maneja `is_locked`, `record_fail`, MFA check, emite `auth_fail/success` (T1110)
  - `verify_mfa` — backup codes, `auth_mfa_success`
  - `refresh` — rotation `jti`
- Estado `_failed/_locked` en memoria pero también replica a user record para audit forense.

### `record_service.py:8` — `RecordService`
- `create` detecta `suspicious_note` → emite `T1059`
- `get` enforce `viewer` ownership → `authz_fail` (T1548) si IDOR
- `list` aplica least-privilege automático

## 6. Inyección en FastAPI

`api/app/main.py:25`:
```python
def get_auth_service():
    return AuthService(get_user_repository(), get_audit_repository())

@app.post("/auth/login")
def login(req, svc=Depends(get_auth_service)): ...
```

Ventaja: en tests puedes hacer `app.dependency_overrides[get_auth_service] = lambda: mock_service`.

## 7. Migración Legacy

- `main_legacy.py` conservado para referencia / auditoría.
- `main.py` es ahora v2 (repository). No breaking change en endpoints — mismo OpenAPI.
- Validado con `api/tests/test_auth.py` y `tests/test_auth_service.py` (nuevo).

## 8. Próximos pasos

- [ ] Añadir `PostgresUserRepository` + `alembic`
- [ ] Cache read-through en `RecordRepository`
- [ ] AuditRepository con OpenSearch backend (prod)

---
*Commit: `feat(api): repository pattern — 2026-08-30`*
