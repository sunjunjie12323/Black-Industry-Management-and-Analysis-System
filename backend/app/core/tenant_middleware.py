from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from loguru import logger

from app.core.tenant import tenant_manager
from app.core.billing import ResourceType


_PUBLIC_PATHS = {"/health", "/health/live", "/health/ready", "/metrics", "/docs", "/redoc", "/openapi.json", "/api/v1/version"}


class TenantMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in _PUBLIC_PATHS:
            return await call_next(request)

        if request.method == "OPTIONS":
            return await call_next(request)

        tenant_id = await self._extract_tenant_id(request)
        request.state.tenant_id = tenant_id

        quota_ok = await self._check_quota(tenant_id, request)
        if not quota_ok:
            return JSONResponse(
                status_code=429,
                content={"detail": "Tenant quota exceeded", "tenant_id": tenant_id},
            )

        response = await call_next(request)

        self._record_usage(request, tenant_id)

        return response

    async def _extract_tenant_id(self, request: Request) -> str:
        tenant_id = request.headers.get("X-Tenant-ID")
        if tenant_id:
            return tenant_id

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from app.core.auth import decode_access_token
                token = auth_header[7:]
                token_data = decode_access_token(token)
                if hasattr(token_data, "tenant_id") and token_data.tenant_id:
                    return token_data.tenant_id
            except Exception:
                pass

        api_key_header = request.headers.get("X-API-Key")
        if api_key_header:
            try:
                from app.core.api_key_manager import api_key_manager
                api_key = await api_key_manager.validate_api_key(api_key_header)
                if api_key and api_key.tenant_id:
                    return api_key.tenant_id
            except Exception:
                pass

        return "default"

    async def _check_quota(self, tenant_id: str, request: Request) -> bool:
        try:
            if request.method in ("POST", "PUT", "PATCH"):
                ok = await tenant_manager.check_quota(tenant_id, "intelligence_count")
                if not ok:
                    return False
            ok = await tenant_manager.check_quota(tenant_id, "api_call_count")
            if not ok:
                return False
        except Exception as exc:
            logger.warning(f"Quota check failed for tenant {tenant_id}: {exc}")
        return True

    def _record_usage(self, request: Request, tenant_id: str):
        try:
            billing_engine = getattr(request.app.state, "billing_engine", None)
            if billing_engine:
                billing_engine.record_usage(
                    tenant_id=tenant_id,
                    resource_type=ResourceType.API_CALL.value,
                    amount=1,
                    metadata={"path": request.url.path, "method": request.method},
                )
        except Exception as exc:
            logger.warning(f"Usage recording failed for tenant {tenant_id}: {exc}")
