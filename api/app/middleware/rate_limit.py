"""
SC-5, AC-7 — Rate limiting + brute force protection
Token bucket per IP: 60 req/min, burst 20. Auth endpoints stricter: 5/15min
"""
from __future__ import annotations
import time
from collections import defaultdict, deque
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# config
GLOBAL_LIMIT = 60  # per minute
AUTH_LIMIT = 5     # per 15 min for /auth/login

buckets: dict[str, deque] = defaultdict(deque)
auth_buckets: dict[str, deque] = defaultdict(deque)
blocked: dict[str, float] = {}

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        # cleanup blocked
        if ip in blocked and now > blocked[ip]:
            del blocked[ip]
        if ip in blocked:
            return Response(content='{"detail":"Too many requests - blocked"}', status_code=429, media_type="application/json",
                            headers={"Retry-After": str(int(blocked[ip]-now))})

        path = request.url.path
        is_auth = path.startswith("/auth/login")
        bucket = auth_buckets[ip] if is_auth else buckets[ip]
        limit = AUTH_LIMIT if is_auth else GLOBAL_LIMIT
        window = 900 if is_auth else 60

        # evict old
        while bucket and now - bucket[0] > window:
            bucket.popleft()
        if len(bucket) >= limit:
            blocked[ip] = now + 900 if is_auth else now + 60
            return Response(content='{"detail":"Rate limit exceeded"}', status_code=429, media_type="application/json",
                            headers={"Retry-After": "60"})
        bucket.append(now)
        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(limit - len(bucket))
        return response
