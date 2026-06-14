from typing import List

import json
import hashlib
import secrets as sec
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import select, and_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.auth import (
    Permission,
    Role,
    User,
    UserOut,
    blacklist_token,
    create_access_token,
    create_refresh_token,
    create_user,
    get_all_users,
    get_current_user,
    get_user_by_id,
    get_user_by_username,
    has_permission,
    hash_password,
    is_user_locked,
    record_login_failure,
    record_login_success,
    require_permission,
    require_role,
    revoke_all_refresh_tokens,
    revoke_refresh_token,
    update_user_password,
    verify_password,
    verify_refresh_token,
)
from app.core.audit import audit_log_async
from app.core.exceptions import ForbiddenException, NotFoundException, UnauthorizedException, ValidationException
from app.db.database import get_db
from app.db.tables import UserTable
from app.models.api_key import (
    UserApiKeyCreate,
    UserApiKeyCreateResponse,
    UserApiKeyOut,
    UserApiKeyTable,
)
from app.middleware import request_id_ctx


router = APIRouter(prefix="/auth", tags=["auth"])

_ip_login_attempts: dict[str, list[float]] = {}


def _check_ip_rate_limit(ip: str):
    import time as _time
    now = _time.monotonic()
    attempts = _ip_login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < settings.IP_RATE_WINDOW]
    _ip_login_attempts[ip] = attempts
    if len(attempts) >= settings.IP_RATE_LIMIT:
        from app.core.exceptions import ForbiddenException
        raise ForbiddenException(detail="登录尝试过于频繁，请稍后重试")
    attempts.append(now)


def _validate_password_strength(password: str):
    from app.core.auth import validate_password_strength
    is_strong, msg = validate_password_strength(password)
    if not is_strong:
        raise ValidationException(detail=msg)


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 86400
    user: UserOut
    must_change_password: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1, max_length=512)


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 86400


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=128)
    password: str = Field(..., min_length=8, max_length=128)
    role: Role = Role.VIEWER


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=8, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


@router.post("/login", response_model=LoginResponse)
async def login(data: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    _check_ip_rate_limit(client_ip)
    if await is_user_locked(data.username, db_session=db):
        await audit_log_async(
            action="LOGIN_FAILURE",
            username=data.username,
            ip_address=client_ip,
            request_id=request_id_ctx.get(),
            status="failure",
            details={"reason": "account_locked"},
        )
        raise ForbiddenException(detail="账号已锁定，请稍后重试")
    user = await get_user_by_username(data.username)
    if user is None:
        hash_password(data.username)
        await audit_log_async(
            action="LOGIN_FAILURE",
            username=data.username,
            ip_address=client_ip,
            request_id=request_id_ctx.get(),
            status="failure",
            details={"reason": "user_not_found"},
        )
        raise UnauthorizedException(detail="用户名或密码错误")
    if not user.is_active:
        await audit_log_async(
            action="LOGIN_FAILURE",
            username=data.username,
            user_id=user.id,
            ip_address=client_ip,
            request_id=request_id_ctx.get(),
            status="failure",
            details={"reason": "account_disabled"},
        )
        raise UnauthorizedException(detail="用户账号已被停用")
    if not verify_password(data.password, user.hashed_password):
        await record_login_failure(data.username, db_session=db)
        await audit_log_async(
            action="LOGIN_FAILURE",
            username=data.username,
            user_id=user.id,
            ip_address=client_ip,
            request_id=request_id_ctx.get(),
            status="failure",
            details={"reason": "invalid_password"},
        )
        raise UnauthorizedException(detail="用户名或密码错误")
    access_token = create_access_token(user)
    refresh_token = await create_refresh_token(user)
    await record_login_success(user.id, db_session=db)
    logger.info(f"User logged in: {data.username}")
    await audit_log_async(
        action="LOGIN_SUCCESS",
        user_id=user.id,
        username=data.username,
        ip_address=client_ip,
        request_id=request_id_ctx.get(),
        status="success",
    )
    must_change = False
    if user.hashed_password and hasattr(user, 'must_change_password') and user.must_change_password:
        must_change = True
    elif user.hashed_password and any(verify_password(weak, user.hashed_password) for weak in settings.WEAK_PASSWORDS):
        must_change = True

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserOut(
            id=user.id,
            username=user.username,
            role=user.role,
            is_active=user.is_active,
            totp_enabled=user.totp_enabled,
            last_login_at=user.last_login_at,
            created_at=user.created_at,
        ),
        must_change_password=must_change,
    )


@router.post("/register", response_model=UserOut, status_code=201)
async def register(data: RegisterRequest, request: Request):
    # 公开注册接口，添加 IP 限流防止滥用
    client_ip = request.client.host if request.client else "unknown"
    _check_ip_rate_limit(client_ip)
    _validate_password_strength(data.password)
    existing = await get_user_by_username(data.username)
    if existing is not None:
        raise ValidationException(detail=f"用户名 '{data.username}' 已存在")
    try:
        user = await create_user(
            username=data.username,
            password=data.password,
            role=Role.VIEWER,
        )
    except ValueError as exc:
        raise ValidationException(detail="验证失败")
    except Exception as exc:
        logger.error(f"Failed to create user: {exc}")
        raise ValidationException(detail="创建用户失败，请稍后重试")
    logger.info(f"New user registered: {data.username} from {client_ip}")
    await audit_log_async(
        action="USER_REGISTER",
        username=data.username,
        ip_address=client_ip,
        request_id=request_id_ctx.get(),
        status="success",
    )
    return UserOut(
        id=user.id,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
        totp_enabled=user.totp_enabled,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )


@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserOut(
        id=current_user.id,
        username=current_user.username,
        role=current_user.role,
        is_active=current_user.is_active,
        totp_enabled=current_user.totp_enabled,
        last_login_at=current_user.last_login_at,
        created_at=current_user.created_at,
    )


@router.put("/password")
async def change_password(
    data: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    client_ip = request.client.host if request.client else None
    if not verify_password(data.current_password, current_user.hashed_password):
        await audit_log_async(
            action="PASSWORD_CHANGE_FAILURE",
            user_id=current_user.id,
            username=current_user.username,
            ip_address=client_ip,
            request_id=request_id_ctx.get(),
            status="failure",
            details={"reason": "invalid_current_password"},
        )
        raise ValidationException(detail="当前密码不正确")
    if data.current_password == data.new_password:
        raise ValidationException(detail="新密码不能与当前密码相同")
    _validate_password_strength(data.new_password)
    try:
        await update_user_password(current_user.username, data.new_password)
    except Exception as e:
        logger.error(f"Failed to update password for user {current_user.username}: {e}")
        raise ValidationException(detail="密码修改失败，请稍后重试")
    await audit_log_async(
        action="PASSWORD_CHANGE",
        user_id=current_user.id,
        username=current_user.username,
        ip_address=client_ip,
        request_id=request_id_ctx.get(),
        status="success",
    )
    return {"message": "密码修改成功"}


@router.put("/profile")
async def update_profile(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    body = await request.json()
    display_name = body.get("display_name")
    email = body.get("email")
    async with get_db() as db:
        updates = {}
        if display_name is not None:
            updates["display_name"] = display_name
        if email is not None:
            updates["email"] = email
        if updates:
            stmt = update(UserTable).where(UserTable.id == current_user.id).values(**updates)
            await db.execute(stmt)
            await db.commit()
    return {"message": "资料更新成功"}


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
):
    token = credentials.credentials
    await blacklist_token(token)
    logger.info(f"User logged out: {current_user.username}")
    client_ip = request.client.host if request.client else None
    await audit_log_async(
        action="LOGOUT",
        user_id=current_user.id,
        username=current_user.username,
        ip_address=client_ip,
        request_id=request_id_ctx.get(),
        status="success",
    )
    return {"message": "退出登录成功"}


@router.post("/refresh", response_model=RefreshResponse)
async def refresh_token(data: RefreshRequest):
    user = await verify_refresh_token(data.refresh_token)
    if user is None:
        raise UnauthorizedException(detail="刷新令牌无效或已过期")
    if not user.is_active:
        raise UnauthorizedException(detail="用户账号已被停用")

    await revoke_refresh_token(data.refresh_token)
    new_access_token = create_access_token(user)
    new_refresh_token = await create_refresh_token(user)

    return RefreshResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
    )


@router.get("/permissions")
async def get_permissions(current_user: User = Depends(get_current_user)):
    from app.core.auth import ROLE_PERMISSIONS, Permission
    user_perms = ROLE_PERMISSIONS.get(current_user.role, set())
    return {
        "role": current_user.role.value,
        "permissions": [p.value for p in user_perms],
    }


@router.post("/revoke-all-sessions")
async def revoke_all_sessions(current_user: User = Depends(get_current_user)):
    count = await revoke_all_refresh_tokens(current_user.id)
    return {"message": f"已撤销{count}个会话", "revoked_count": count}


@router.get("/users", response_model=List[UserOut])
async def list_users(current_user: User = Depends(require_role(Role.ADMIN))):
    users = await get_all_users()
    return [
        UserOut(
            id=u.id,
            username=u.username,
            role=u.role,
            is_active=u.is_active,
            totp_enabled=u.totp_enabled,
            last_login_at=u.last_login_at,
            created_at=u.created_at,
        )
        for u in users
    ]


@router.get("/csrf-token")
async def get_csrf_token(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """生成 CSRF token，包含时间戳和用户 ID 防止重放攻击"""
    import hmac
    import time
    import hashlib

    secret = getattr(request.app.state, 'csrf_secret', None)
    if not secret:
        from pathlib import Path
        csrf_path = Path(__file__).resolve().parent.parent.parent / ".csrf_secret"
        if csrf_path.exists():
            secret = csrf_path.read_text().strip()
            request.app.state.csrf_secret = secret
        else:
            import secrets as sec
            secret = sec.token_urlsafe(32)
            request.app.state.csrf_secret = secret

    # 添加时间戳和用户 ID 作为盐值，防止重放攻击
    timestamp = str(int(time.time()))
    user_salt = f"{current_user.id}:{timestamp}"
    token = hmac.new(secret.encode(), user_salt.encode(), "sha256").hexdigest()

    return {
        "csrf_token": token,
        "expires_at": int(timestamp) + settings.CSRF_TOKEN_EXPIRY_SECONDS,
        "user_id": current_user.id
    }


api_keys_router = APIRouter(prefix="/api-keys", tags=["api-keys"])


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _row_to_key_out(row: UserApiKeyTable) -> UserApiKeyOut:
    try:
        scopes = json.loads(row.scopes) if row.scopes else []
        if not isinstance(scopes, list):
            scopes = []
    except (ValueError, TypeError):
        scopes = []
    return UserApiKeyOut(
        id=row.id,
        key_id=row.key_id,
        secret_prefix=row.secret_prefix,
        name=row.name,
        scopes=scopes,
        rate_limit=row.rate_limit,
        is_active=row.is_active,
        last_used_at=row.last_used_at,
        expires_at=row.expires_at,
        created_at=row.created_at,
    )


@api_keys_router.post("", response_model=UserApiKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    data: UserApiKeyCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    key_id = sec.token_hex(8)
    secret = sec.token_urlsafe(32)
    secret_prefix = secret[:8]
    key_hash = _hash_secret(secret)
    now = datetime.now(timezone.utc)
    expires_at = None
    if data.expires_in_days:
        expires_at = now + timedelta(days=data.expires_in_days)

    new_id = uuid4().hex
    row = UserApiKeyTable(
        id=new_id,
        user_id=current_user.id,
        key_id=key_id,
        key_hash=key_hash,
        secret_prefix=secret_prefix,
        name=data.name,
        scopes=json.dumps(data.scopes, ensure_ascii=False),
        rate_limit=data.rate_limit,
        is_active=True,
        expires_at=expires_at,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    client_ip = request.client.host if request.client else None
    await audit_log_async(
        action="API_KEY_CREATED",
        user_id=current_user.id,
        username=current_user.username,
        resource_type="api_key",
        resource_id=new_id,
        ip_address=client_ip,
        request_id=request_id_ctx.get(),
        status="success",
        details={"name": data.name, "key_id": key_id, "scopes": data.scopes},
    )
    logger.info(f"API key created: user={current_user.username} key_id={key_id} name={data.name}")

    out = _row_to_key_out(row)
    return UserApiKeyCreateResponse(**out.model_dump(), secret=secret)


@api_keys_router.get("", response_model=List[UserApiKeyOut])
async def list_api_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserApiKeyTable)
        .where(UserApiKeyTable.user_id == current_user.id)
        .order_by(UserApiKeyTable.created_at.desc())
    )
    rows = result.scalars().all()
    return [_row_to_key_out(r) for r in rows]


@api_keys_router.delete("/{key_id}")
async def revoke_api_key(
    key_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserApiKeyTable).where(
            and_(
                UserApiKeyTable.id == key_id,
                UserApiKeyTable.user_id == current_user.id,
            )
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        raise NotFoundException(detail="API Key 不存在")
    row.is_active = False
    row.updated_at = datetime.now(timezone.utc)
    await db.commit()

    client_ip = request.client.host if request.client else None
    await audit_log_async(
        action="API_KEY_REVOKED",
        user_id=current_user.id,
        username=current_user.username,
        resource_type="api_key",
        resource_id=key_id,
        ip_address=client_ip,
        request_id=request_id_ctx.get(),
        status="success",
        details={"key_id_public": row.key_id},
    )
    logger.info(f"API key revoked: user={current_user.username} key_id={row.key_id}")
    return {"message": "API Key 已撤销", "id": key_id}
