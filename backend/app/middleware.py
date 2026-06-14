import json
import secrets
import time
import uuid
from contextvars import ContextVar
from typing import Dict, Optional, Set

from fastapi import Request
from fastapi.responses import JSONResponse
from loguru import logger

from app.config import settings
from app.core.rate_limiter import rate_limiter
from app.core.dfx import performance_monitor

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")


class QueryCountState:
    def __init__(self):
        self.start_count: int = 0
        self.current_count: int = 0
        self._lock = None

    def snapshot(self) -> Dict[str, int]:
        try:
            from app.core.db_performance import get_query_metrics
            metrics = get_query_metrics()
            return {
                "total_queries": metrics.get("total_queries", 0),
                "slow_queries": metrics.get("slow_queries", 0),
            }
        except Exception:
            return {"total_queries": 0, "slow_queries": 0}


query_count_state = QueryCountState()

# API Key 验证缓存：{cache_key: (data, timestamp)}
_api_key_cache: Dict[str, tuple] = {}


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app
        self._csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob: https:; "
            "font-src 'self' data:; "
            "connect-src 'self' ws: wss: https:; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "object-src 'none'"
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = ""
        for header in scope.get("headers", []):
            if header[0] == b":path":
                path = header[1].decode("utf-8", errors="replace").split("?")[0]
                break

        frame_options = "SAMEORIGIN" if path.startswith("/api/v1") else "DENY"
        hsts = "max-age=31536000; includeSubDomains"
        if settings.is_production:
            hsts += "; preload"

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                security_headers = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": frame_options.encode(),
                    b"x-xss-protection": b"0",
                    b"referrer-policy": b"strict-origin-when-cross-origin",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=(), payment=()",
                    b"content-security-policy": self._csp.encode(),
                    b"strict-transport-security": hsts.encode(),
                    b"cross-origin-opener-policy": b"same-origin",
                    b"cross-origin-resource-policy": b"same-origin",
                }
                headers.update(security_headers)
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestIDMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = None
        for header in scope.get("headers", []):
            if header[0] == b"x-request-id":
                request_id = header[1].decode("utf-8", errors="replace")
                break

        if not request_id:
            request_id = str(uuid.uuid4())

        request_id_ctx.set(request_id)

        async def send_with_request_id(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers[b"x-request-id"] = request_id.encode()
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_with_request_id)


_CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_CSRF_TOKEN_HEADER = "x-csrf-token"
_CSRF_EXEMPT_PREFIXES = ("/api/v1/auth/", "/health", "/metrics", "/docs", "/openapi.json", "/redoc", "/ws")


class CSRFMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")
        if not path:
            for header in scope.get("headers", []):
                if header[0] == b":path":
                    path = header[1].decode("utf-8", errors="replace").split("?")[0]
                    break

        if method in _CSRF_SAFE_METHODS:
            await self.app(scope, receive, send)
            return

        if any(path.startswith(prefix) for prefix in _CSRF_EXEMPT_PREFIXES):
            await self.app(scope, receive, send)
            return

        auth_header = None
        for header in scope.get("headers", []):
            if header[0] == b"authorization":
                auth_header = header[1]
                break

        if auth_header:
            await self.app(scope, receive, send)
            return

        csrf_token = None
        for header in scope.get("headers", []):
            if header[0] == _CSRF_TOKEN_HEADER.encode():
                csrf_token = header[1]
                break

        if not csrf_token:
            response = JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing. Provide x-csrf-token header or Authorization header."},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


_unauthenticated_limiter = rate_limiter.__class__(requests_per_minute=30)
_authenticated_limiter = rate_limiter.__class__(requests_per_minute=120)


class MetricsState:
    intelligence_total: int = 0
    search_total: int = 0
    api_requests_total: Dict[str, int] = {}


metrics_state = MetricsState()


async def query_count_middleware(request: Request, call_next):
    from app.core.db_performance import _query_metrics
    start_total = _query_metrics["total_queries"]
    start_slow = _query_metrics["slow_queries"]
    try:
        response = await call_next(request)
    except Exception:
        raise

    end_total = _query_metrics["total_queries"]
    delta = end_total - start_total
    slow_delta = _query_metrics["slow_queries"] - start_slow

    if isinstance(response.headers, dict):
        pass

    if hasattr(response, "headers"):
        try:
            response.headers["X-DB-Query-Count"] = str(delta)
            response.headers["X-DB-Slow-Query-Count"] = str(slow_delta)
        except Exception:
            pass
    return response


async def rate_limit_middleware(request: Request, call_next):
    if request.url.path in ("/health", "/metrics", "/docs", "/openapi.json", "/redoc"):
        return await call_next(request)

    path = request.url.path
    metrics_state.api_requests_total[path] = metrics_state.api_requests_total.get(path, 0) + 1

    from app.core.db_performance import _query_metrics
    start_total = _query_metrics["total_queries"]
    start_slow = _query_metrics["slow_queries"]

    client_ip = request.client.host if request.client else "unknown"

    user_id: Optional[str] = None
    user_tier: Optional[str] = None
    api_key_id: Optional[str] = None
    api_key_rpm: Optional[int] = None

    api_header = request.headers.get("x-api-key", "")
    if api_header:
        try:
            from app.core.security import parse_api_key_header, hash_api_key_secret
            from app.models.api_key import UserApiKeyTable
            from app.db.database import async_session_factory
            from sqlalchemy import select, and_
            from datetime import datetime, timezone
            parsed = parse_api_key_header(api_header)
            if parsed:
                key_id, secret = parsed
                key_hash = hash_api_key_secret(secret)

                # Check cache first (TTL from config)
                _cache_key = f"{key_id}:{key_hash}"
                cached = _api_key_cache.get(_cache_key)
                if cached and (time.time() - cached[1]) < settings.API_KEY_CACHE_TTL:
                    api_key_id = cached[0]["api_key_id"]
                    api_key_rpm = cached[0]["api_key_rpm"]
                    user_id = cached[0]["user_id"]
                else:
                    async with async_session_factory() as db:
                        result = await db.execute(
                            select(UserApiKeyTable).where(
                                and_(
                                    UserApiKeyTable.key_id == key_id,
                                    UserApiKeyTable.key_hash == key_hash,
                                    UserApiKeyTable.is_active == True,  # noqa: E712
                                )
                            )
                        )
                        row = result.scalar_one_or_none()
                        if row is not None:
                            if row.expires_at is None or row.expires_at > datetime.now(timezone.utc).replace(tzinfo=None):
                                api_key_id = row.id
                                api_key_rpm = row.rate_limit
                                user_id = row.user_id
                                _api_key_cache[_cache_key] = (
                                    {"api_key_id": api_key_id, "api_key_rpm": api_key_rpm, "user_id": user_id},
                                    time.time(),
                                )
        except Exception as exc:
            logger.debug(f"API key rate limit detection failed: {exc}")

    if not user_id:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from app.core.auth import decode_access_token, is_token_blacklisted
                token = auth_header[7:]
                if not is_token_blacklisted(token):
                    token_data = decode_access_token(token)
                    user_id = token_data.user_id
                    role_value = token_data.role.value if token_data.role else "viewer"
                    tier_map = {"admin": "enterprise", "analyst": "pro", "viewer": "free"}
                    user_tier = tier_map.get(role_value, "free")
            except Exception:
                pass

    start_time = time.time()
    endpoint_type = rate_limiter.classify_endpoint(path, request.method)
    allowed, retry_after, info = await rate_limiter.check_granular(
        client_ip=client_ip,
        user_id=user_id,
        user_tier=user_tier,
        api_key_id=api_key_id,
        api_key_rpm=api_key_rpm,
        endpoint_type=endpoint_type,
    )

    if not allowed:
        response = JSONResponse(
            status_code=429,
            content={
                "success": False,
                "data": None,
                "message": f"请求过于频繁,请稍后重试 ({info.get('scope', 'unknown')} limit)",
                "code": 429,
                "error_code": "RATE_LIMIT_EXCEEDED",
                "scope": info.get("scope", "unknown"),
            },
        )
        response.headers["X-RateLimit-Limit"] = str(info.get("limit", 0))
        response.headers["X-RateLimit-Remaining"] = "0"
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + int(retry_after) if retry_after else 0)
        response.headers["Retry-After"] = str(max(int(retry_after), 1))
        return response

    response = await call_next(request)
    elapsed = (time.time() - start_time) * 1000
    performance_monitor.record_request(path, elapsed, response.status_code)

    try:
        end_total = _query_metrics["total_queries"]
        delta = end_total - start_total
        slow_delta = _query_metrics["slow_queries"] - start_slow
        response.headers["X-DB-Query-Count"] = str(delta)
        response.headers["X-DB-Slow-Query-Count"] = str(slow_delta)
        if slow_delta > 0:
            logger.warning(f"Request {request.method} {path} used {delta} DB queries ({slow_delta} slow)")
    except Exception:
        pass

    if info.get("limit"):
        response.headers["X-RateLimit-Limit"] = str(info["limit"])
        response.headers["X-RateLimit-Remaining"] = str(info.get("remaining", 0))
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + 60)
        response.headers["X-RateLimit-Scope"] = info.get("scope", "none")

    if request.method == "GET" and response.status_code == 200:
        cacheable_prefixes = ("/api/v1/analysis/stats", "/api/v1/innovation", "/api/v1/dashboard")
        if any(path.startswith(prefix) for prefix in cacheable_prefixes):
            response.headers["Cache-Control"] = "private, max-age=30"
        elif path.startswith("/api/v1/"):
            response.headers["Cache-Control"] = "no-store"
        elif path.startswith("/assets/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        elif path.endswith((".js", ".css", ".woff", ".woff2", ".ttf", ".svg", ".png", ".jpg", ".webp")):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        elif path.endswith("index.html") or path == "/":
            response.headers["Cache-Control"] = "no-cache, must-revalidate"

    return response
