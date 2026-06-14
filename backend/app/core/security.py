import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional, Tuple

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from loguru import logger
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import UnauthorizedException
from app.db.database import get_db
from app.models.api_key import ApiKeyAuthResult, UserApiKeyTable


security_scheme = HTTPBearer(auto_error=False)


def hash_api_key_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_api_key_pair() -> Tuple[str, str, str]:
    key_id = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    full_token = f"{key_id}.{secret}"
    secret_prefix = secret[:8]
    return key_id, secret, full_token


def parse_api_key_header(raw: str) -> Optional[Tuple[str, str]]:
    if not raw:
        return None
    raw = raw.strip()
    if not raw:
        return None
    if "." in raw:
        parts = raw.split(".", 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            return parts[0], parts[1]
    return None


async def verify_api_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> ApiKeyAuthResult:
    raw_header: Optional[str] = None
    for name in ("x-api-key", "X-API-Key"):
        value = request.headers.get(name)
        if value:
            raw_header = value
            break
    if not raw_header:
        auth_value = request.headers.get("authorization", "")
        if auth_value.lower().startswith("apikey "):
            raw_header = auth_value[7:].strip()
    if not raw_header:
        raise UnauthorizedException(
            detail="API Key 缺失,请在请求头 X-API-Key 中提供 key_id.secret",
            error_code="AUTH_API_KEY_MISSING",
        )

    parsed = parse_api_key_header(raw_header)
    if not parsed:
        raise UnauthorizedException(
            detail="API Key 格式错误,应为 key_id.secret",
            error_code="AUTH_API_KEY_INVALID",
        )
    key_id, secret = parsed

    key_hash = hash_api_key_secret(secret)
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
    if row is None:
        raise UnauthorizedException(
            detail="API Key 无效或已禁用",
            error_code="AUTH_API_KEY_INVALID",
        )

    now = datetime.now(timezone.utc)
    if row.expires_at is not None:
        expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
        if expires < now:
            raise UnauthorizedException(
                detail="API Key 已过期",
                error_code="AUTH_API_KEY_EXPIRED",
            )

    import json as _json
    try:
        scopes = _json.loads(row.scopes) if row.scopes else []
        if not isinstance(scopes, list):
            scopes = []
    except (ValueError, TypeError):
        scopes = []

    row.last_used_at = now
    try:
        await db.commit()
    except Exception as exc:
        logger.warning(f"Failed to update api_key last_used_at: {exc}")
        await db.rollback()

    return ApiKeyAuthResult(
        user_id=row.user_id,
        key_id=row.key_id,
        api_key_id=row.id,
        scopes=scopes,
        rate_limit=row.rate_limit,
    )
