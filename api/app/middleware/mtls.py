"""
Middleware mTLS — SC-8
Si MTLS_ENABLED=true, exige cert y emite evento si falta (para SIEM T1078)
"""
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Response
from ..core.mtls import MTLS_ENABLED, verify_client_cert
from ..repositories.audit_repository import get_audit_repository

class MTLSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if MTLS_ENABLED:
            # uvicorn ya validó el handshake, pero podemos loggear fingerprint
            # Si viene sin cert (ej: health sin cliente), no bloqueamos health
            if request.url.path not in ("/health", "/docs", "/openapi.json"):
                ok = verify_client_cert(request)
                if not ok:
                    repo = get_audit_repository()
                    repo.emit({"actor": request.client.host if request.client else "unknown", "action":"mtls_fail","object": request.url.path,"result":"fail","mitre_technique":"T1078"})
                    return Response(content='{"detail":"mTLS client certificate required"}', status_code=496, media_type="application/json")
        return await call_next(request)
