from fastapi import Depends, HTTPException, Query, Request
from loguru import logger

from app.core.api_key_manager import api_key_manager, ApiKey, ApiPermission


async def require_api_key(
    request: Request,
    x_api_key: str = None,
    api_key: str = Query(None, alias="api_key"),
) -> ApiKey:
    raw_key = x_api_key or api_key
    if not raw_key:
        raw_key = request.headers.get("X-API-Key")
    if not raw_key:
        raise HTTPException(status_code=401, detail="API Key required")

    validated = await api_key_manager.validate_api_key(raw_key)
    if validated is None:
        raise HTTPException(status_code=401, detail="Invalid or expired API Key")

    rate_ok = await api_key_manager.check_rate_limit(validated.key_id)
    if not rate_ok:
        raise HTTPException(status_code=429, detail="API Key rate limit exceeded")

    await api_key_manager.record_usage(validated.key_id)

    return validated


def require_permission(permission: str):
    async def _check(api_key: ApiKey = Depends(require_api_key)) -> ApiKey:
        has_perm = await api_key_manager.check_permission(api_key.key_id, permission)
        if not has_perm:
            raise HTTPException(status_code=403, detail=f"Permission denied: {permission}")
        return api_key

    return _check
