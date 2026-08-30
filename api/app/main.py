"""
Mini-SOC Secure API — Repository Pattern (Clean Architecture)
NIST CSF 2.0 + SP 800-53 rev5 + OWASP ASVS 4.0
Refactorizado a patrón Repositorio: Controllers → Services → Repositories
"""
from __future__ import annotations
import time, uuid
from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .models.schemas import LoginRequest, MFAVerifyRequest, MFASetupResponse, TokenResponse, RefreshRequest, UserCreate, RecordCreate, RecordOut
from .repositories.user_repository import get_user_repository
from .repositories.record_repository import get_record_repository
from .repositories.audit_repository import get_audit_repository
from .services.auth_service import AuthService
from .services.record_service import RecordService
from .auth.mfa import generate_secret, otpauth_url
from .utils.crypto import ensure_keys, generate_backup_codes
from .rbac.decorator import get_current_user, require_permission
from .middleware.audit import AuditMiddleware
from .middleware.rate_limit import RateLimitMiddleware
from .middleware.security_headers import SecurityHeadersMiddleware
from .auth.jwt import revoke_jti

ensure_keys()

app = FastAPI(title="Mini-SOC Secure API (Repository Pattern)", version="2.0.0",
              description="NIST CSF 2.0 + Repository Pattern + Purple Team Verified")

app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuditMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Dependency injection factories
def get_auth_service():
    return AuthService(get_user_repository(), get_audit_repository())

def get_record_service():
    return RecordService(get_record_repository(), get_audit_repository())

@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail, "trace_id": request.headers.get("X-Request-ID", str(uuid.uuid4()))})

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "pattern": "repository"}

# --- AUTH via Service ---
@app.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, svc: AuthService = Depends(get_auth_service)):
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent","-")
    try:
        res = svc.authenticate(req.username, req.password, ip, ua)
    except PermissionError:
        raise HTTPException(status_code=423, detail="Account locked — try later")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if res.get("mfa_required"):
        return TokenResponse(access_token="", refresh_token="", token_type="bearer", mfa_required=True)
    return TokenResponse(access_token=res["access_token"], refresh_token=res["refresh_token"])

@app.post("/auth/mfa/setup", response_model=MFASetupResponse)
def mfa_setup(current=Depends(get_current_user)):
    repo = get_user_repository()
    secret = generate_secret()
    url = otpauth_url(secret, current["username"])
    codes = generate_backup_codes()
    repo.update(current["username"], mfa_secret=secret, backup_codes=codes, mfa_enabled=False)
    return MFASetupResponse(otpauth_url=url, secret=secret, backup_codes=codes)

@app.post("/auth/mfa/verify", response_model=TokenResponse)
def mfa_verify(req: MFAVerifyRequest, request: Request, svc: AuthService = Depends(get_auth_service)):
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent","-")
    try:
        res = svc.verify_mfa(req.username, req.code, ip, ua)
    except ValueError as e:
        msg = str(e)
        if "mfa_not_setup" in msg: raise HTTPException(status_code=400, detail="MFA not setup")
        if "invalid_mfa" in msg: raise HTTPException(status_code=401, detail="Invalid MFA code")
        raise HTTPException(status_code=400, detail=msg)
    return TokenResponse(access_token=res["access_token"], refresh_token=res["refresh_token"])

@app.post("/auth/refresh", response_model=TokenResponse)
def refresh(req: RefreshRequest, svc: AuthService = Depends(get_auth_service)):
    try:
        res = svc.refresh(req.refresh_token)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    return TokenResponse(access_token=res["access_token"], refresh_token=res["refresh_token"])

@app.post("/auth/logout")
def logout(request: Request, current=Depends(get_current_user)):
    revoke_jti(current["jti"])
    get_audit_repository().emit({"actor": current["username"], "action":"auth_logout","object":"/auth/logout","result":"success","src_ip": request.client.host if request.client else "unknown"})
    return {"detail":"logged out"}

# --- USERS via Repository directly (admin) ---
@app.get("/users/me")
def me(current=Depends(get_current_user)):
    repo = get_user_repository()
    user = repo.get_by_username(current["username"])
    return {"username": user["username"], "role": user["role"], "mfa_enabled": user["mfa_enabled"], "created_at": user["created_at"]}

@app.get("/admin/users")
def admin_list(current=Depends(require_permission("read:users"))):
    repo = get_user_repository()
    users = repo.list_all()
    return [{"username": u["username"], "role": u["role"], "active": u["active"], "mfa_enabled": u["mfa_enabled"], "last_login": u["last_login"]} for u in users]

@app.post("/admin/users")
def admin_create(payload: UserCreate, current=Depends(require_permission("write:users"))):
    from .auth.passwords import hash_password
    repo = get_user_repository()
    try:
        repo.create(payload.username, hash_password(payload.password), payload.role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"detail": f"user {payload.username} created", "role": payload.role}

# --- RECORDS via Service ---
@app.post("/records", response_model=RecordOut)
def create(rec: RecordCreate, current=Depends(require_permission("write:records")), request: Request=None, svc: RecordService = Depends(get_record_service)):
    ip = request.client.host if request and request.client else "unknown"
    r = svc.create(rec.title, rec.value, rec.note, current["username"], ip)
    return RecordOut(id=r["id"], title=r["title"], value=r["value"], note=r["note"], owner=r["owner"])

@app.get("/records", response_model=list[RecordOut])
def list_rec(current=Depends(require_permission("read:records")), owner: str | None = Query(None), svc: RecordService = Depends(get_record_service)):
    recs = svc.list(current["username"], current["role"], owner)
    return [RecordOut(id=r["id"], title=r["title"], value=r["value"], note=r["note"], owner=r["owner"]) for r in recs]

@app.get("/records/{rid}", response_model=RecordOut)
def get_one(rid: int, current=Depends(require_permission("read:records")), svc: RecordService = Depends(get_record_service)):
    try:
        r = svc.get(rid, current["username"], current["role"])
    except KeyError:
        raise HTTPException(status_code=404, detail="Not found")
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    return RecordOut(id=r["id"], title=r["title"], value=r["value"], note=r["note"], owner=r["owner"])

@app.get("/audit/search")
def audit_search(q: str = Query("", max_length=64), current=Depends(require_permission("read:audit"))):
    repo = get_audit_repository()
    results = repo.search(q, limit=50)
    return {"query": q, "count": len(results), "results": results}

@app.get("/alerts")
def get_alerts(current=Depends(require_permission("read:alerts"))):
    import pathlib, json, glob
    alerts=[]
    for pat in ["alerts/*.json", "logs/alerts.jsonl"]:
        for f in glob.glob(str(pathlib.Path(__file__).parent.parent.parent / pat)):
            try:
                if f.endswith(".jsonl"):
                    for line in pathlib.Path(f).read_text().splitlines():
                        alerts.append(json.loads(line))
                else:
                    alerts.append(json.loads(pathlib.Path(f).read_text()))
            except: pass
    return {"count": len(alerts), "alerts": alerts[-50:]}
