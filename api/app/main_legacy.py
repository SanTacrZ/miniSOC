"""
Mini-SOC Secure API — NIST SP 800-53 / OWASP ASVS
"""
from __future__ import annotations
import time, uuid
from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from .models.schemas import LoginRequest, MFAVerifyRequest, MFASetupResponse, TokenResponse, RefreshRequest, UserCreate, RecordCreate, RecordOut
from .models.store import create_record, get_record, list_records
from .auth.passwords import verify_password
from .auth.user_store import get_user, create_user, list_users, update_user, record_failed, is_locked, clear_failed, set_last_login
from .auth.jwt import create_access_token, create_refresh_token, verify_token, rotate_refresh, revoke_jti, revoke_refresh
from .auth.mfa import generate_secret, otpauth_url, verify_totp
from .utils.crypto import ensure_keys, generate_backup_codes
from .rbac.decorator import get_current_user, require_permission, require_role
from .middleware.audit import AuditMiddleware, emit_custom
from .middleware.rate_limit import RateLimitMiddleware
from .middleware.security_headers import SecurityHeadersMiddleware

ensure_keys()

app = FastAPI(title="Mini-SOC Secure API", version="1.0.0",
              description="NIST CSF 2.0 + SP 800-53 + OWASP ASVS — Lab SOC training API")

app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuditMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# catch-all for validation errors to avoid info leak (SI-10)
@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail, "trace_id": request.headers.get("X-Request-ID", str(uuid.uuid4()))})

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

# --- AUTH ---
@app.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent","-")
    if is_locked(req.username):
        emit_custom({"svc":"api","src_ip":ip,"user_agent":ua,"actor":req.username,"action":"auth_fail","object":"/auth/login","result":"fail","reason":"locked","mitre_technique":"T1110"})
        raise HTTPException(status_code=423, detail="Account locked — try later")

    user = get_user(req.username)
    if not user or not user.get("active") or not verify_password(req.password, user["password_hash"]):
        record_failed(req.username)
        emit_custom({"svc":"api","src_ip":ip,"user_agent":ua,"actor":req.username,"action":"auth_fail","object":"/auth/login","result":"fail","mitre_technique":"T1110"})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # password ok — check MFA
    if user.get("mfa_enabled"):
        # require second factor — return mfa_required token (short lived placeholder)
        emit_custom({"svc":"api","src_ip":ip,"user_agent":ua,"actor":req.username,"action":"auth_mfa_required","object":"/auth/login","result":"success","mitre_technique": None})
        return TokenResponse(access_token="", refresh_token="", token_type="bearer", mfa_required=True)

    clear_failed(req.username)
    set_last_login(req.username)
    access = create_access_token(user["username"], user["role"])
    refresh = create_refresh_token(user["username"])
    emit_custom({"svc":"api","src_ip":ip,"user_agent":ua,"actor":req.username,"action":"auth_success","object":"/auth/login","result":"success","role": user["role"]})
    return TokenResponse(access_token=access, refresh_token=refresh)

@app.post("/auth/mfa/setup", response_model=MFASetupResponse)
def mfa_setup(current=Depends(get_current_user)):
    user = get_user(current["username"])
    secret = generate_secret()
    url = otpauth_url(secret, current["username"])
    codes = generate_backup_codes()
    update_user(current["username"], mfa_secret=secret, backup_codes=codes, mfa_enabled=False)
    return MFASetupResponse(otpauth_url=url, secret=secret, backup_codes=codes)

@app.post("/auth/mfa/verify", response_model=TokenResponse)
def mfa_verify(req: MFAVerifyRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent","-")
    user = get_user(req.username)
    if not user or not user.get("mfa_secret"):
        raise HTTPException(status_code=400, detail="MFA not setup")
    if not verify_totp(user["mfa_secret"], req.code):
        # check backup codes
        if req.code in user.get("backup_codes", []):
            # consume backup code
            remaining = [c for c in user["backup_codes"] if c != req.code]
            update_user(req.username, backup_codes=remaining, mfa_enabled=True)
        else:
            emit_custom({"svc":"api","src_ip":ip,"user_agent":ua,"actor":req.username,"action":"auth_mfa_fail","object":"/auth/mfa/verify","result":"fail","mitre_technique":"T1110"})
            raise HTTPException(status_code=401, detail="Invalid MFA code")
    # success — enable if not already
    update_user(req.username, mfa_enabled=True)
    clear_failed(req.username)
    set_last_login(req.username)
    access = create_access_token(user["username"], user["role"])
    refresh = create_refresh_token(user["username"])
    emit_custom({"svc":"api","src_ip":ip,"user_agent":ua,"actor":req.username,"action":"auth_mfa_success","object":"/auth/mfa/verify","result":"success","role":user["role"]})
    return TokenResponse(access_token=access, refresh_token=refresh)

@app.post("/auth/refresh", response_model=TokenResponse)
def refresh(req: RefreshRequest):
    payload = verify_token(req.refresh_token, "refresh")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid refresh")
    new_refresh = rotate_refresh(payload["jti"], payload["sub"])
    if not new_refresh:
        raise HTTPException(status_code=401, detail="Refresh revoked")
    user = get_user(payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User gone")
    access = create_access_token(user["username"], user["role"])
    return TokenResponse(access_token=access, refresh_token=new_refresh)

@app.post("/auth/logout")
def logout(request: Request, current=Depends(get_current_user)):
    # revoke access jti and optionally refresh via header
    revoke_jti(current["jti"])
    # try refresh token in body json
    emit_custom({"svc":"api","src_ip":request.client.host if request.client else "unknown","actor":current["username"],"action":"auth_logout","object":"/auth/logout","result":"success"})
    return {"detail":"logged out"}

# --- USERS ---
@app.get("/users/me")
def me(current=Depends(get_current_user)):
    user = get_user(current["username"])
    return {"username": user["username"], "role": user["role"], "mfa_enabled": user["mfa_enabled"], "created_at": user["created_at"]}

@app.get("/admin/users")
def admin_list(current=Depends(require_permission("read:users"))):
    # AC-3 fail will be 403 and SIEM rule priv_esc will pick burst 403
    users = list_users()
    # don't leak hashes
    return [{"username": u["username"], "role": u["role"], "active": u["active"], "mfa_enabled": u["mfa_enabled"], "last_login": u["last_login"]} for u in users.values()]

@app.post("/admin/users")
def admin_create(payload: UserCreate, current=Depends(require_permission("write:users"))):
    try:
        u = create_user(payload.username, payload.password, payload.role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"detail": f"user {payload.username} created", "role": payload.role}

# --- RECORDS ---
@app.post("/records", response_model=RecordOut)
def create(rec: RecordCreate, current=Depends(require_permission("write:records")), request: Request=None):
    # SI-10: note already validated by pydantic; we also detect suspicious patterns for SIEM but don't block (hunting)
    suspicious = False
    if rec.note and any(s in rec.note for s in [";", "$(", "`", "flag", "|"]):
        # emit detection but allow — simulates vulnerable field to hunt
        emit_custom({"svc":"api","src_ip": request.client.host if request.client else "unknown" ,"actor": current["username"],"action":"suspicious_note","object":"/records","result":"success","note_len": len(rec.note or ""), "mitre_technique":"T1059"})
    r = create_record(rec.title, rec.value, rec.note, current["username"])
    return RecordOut(id=r["id"], title=r["title"], value=r["value"], note=r["note"], owner=r["owner"])

@app.get("/records", response_model=list[RecordOut])
def list_rec(current=Depends(require_permission("read:records")), owner: str | None = Query(None)):
    # RBAC: viewer can only see own? For demo: viewer sees only own, others see all (least privilege variation)
    if current["role"] == "viewer":
        owner = current["username"]
    recs = list_records(owner_filter=owner if current["role"]=="viewer" else owner)
    return [RecordOut(id=r["id"], title=r["title"], value=r["value"], note=r["note"], owner=r["owner"]) for r in recs]

@app.get("/records/{rid}", response_model=RecordOut)
def get_one(rid: int, current=Depends(require_permission("read:records"))):
    r = get_record(rid)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")
    if current["role"]=="viewer" and r["owner"]!=current["username"]:
        # IDOR protection — AC-3
        raise HTTPException(status_code=403, detail="Forbidden: not your record")
    return RecordOut(id=r["id"], title=r["title"], value=r["value"], note=r["note"], owner=r["owner"])

# --- AUDIT SEARCH (analyst+) ---
@app.get("/audit/search")
def audit_search(q: str = Query("", max_length=64), current=Depends(require_permission("read:audit"))):
    # In prod would query OpenSearch; here parse logs/siem.jsonl
    import pathlib, json
    log_path = pathlib.Path(__file__).parent.parent.parent.parent / "logs" / "siem.jsonl"
    alt = pathlib.Path("/tmp/soc_siem.jsonl")
    p = log_path if log_path.exists() else alt
    results = []
    if p.exists():
        for line in p.read_text().splitlines()[-500:]:
            try:
                e = json.loads(line)
                if q.lower() in json.dumps(e).lower():
                    results.append(e)
            except: continue
    return {"query": q, "count": len(results), "results": results[:50]}

@app.get("/alerts")
def get_alerts(current=Depends(require_permission("read:alerts"))):
    import pathlib, json, glob
    # alerts generated by SIEM engine
    alerts = []
    for pat in ["alerts/*.json", "../alerts/*.json", "../../alerts/*.json", "labs/evidence/*/alert.json"]:
        for f in glob.glob(str(pathlib.Path(__file__).parent.parent.parent / pat)):
            try:
                alerts.append(json.loads(pathlib.Path(f).read_text()))
            except: pass
    # also from siem engine memory file
    siem_alerts = pathlib.Path(__file__).parent.parent.parent / "logs" / "alerts.jsonl"
    if siem_alerts.exists():
        for line in siem_alerts.read_text().splitlines()[-100:]:
            try: alerts.append(json.loads(line))
            except: pass
    return {"count": len(alerts), "alerts": alerts[-50:]}
