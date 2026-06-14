import re
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

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
    record_login_success,
    require_permission,
    require_role,
    revoke_all_refresh_tokens,
    revoke_refresh_token,
    update_user_password,
    verify_password,
    verify_refresh_token,
)
from app.core.exceptions import ForbiddenException, UnauthorizedException, ValidationException
from app.db.database import get_db
from app.db.tables import UserTable


router = APIRouter(prefix="/auth", tags=["auth"])

_MAX_LOGIN_ATTEMPTS = 5
_LOCKOUT_SECONDS = 300
_IP_RATE_LIMIT = 20
_IP_RATE_WINDOW = 300
_ip_login_attempts: dict[str, list[float]] = {}


def _check_ip_rate_limit(ip: str):
    import time as _time
    now = _time.monotonic()
    attempts = _ip_login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < _IP_RATE_WINDOW]
    _ip_login_attempts[ip] = attempts
    if len(attempts) >= _IP_RATE_LIMIT:
        from app.core.exceptions import ForbiddenException
        raise ForbiddenException(detail="登录尝试过于频繁，请5分钟后重试")
    attempts.append(now)


async def _check_login_lockout(username: str):
    user = await get_user_by_username(username)
    if user is None:
        return
    if user.locked_until and datetime.now(timezone.utc) < user.locked_until.replace(tzinfo=timezone.utc):
        remaining = int((user.locked_until.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds())
        raise ForbiddenException(detail=f"账号已锁定，请{remaining}秒后重试")


async def _record_failed_login(username: str, db_session=None):
    user = await get_user_by_username(username)
    if user is None:
        return
    new_count = user.login_fail_count + 1
    values = {"login_fail_count": new_count}
    if new_count >= _MAX_LOGIN_ATTEMPTS:
        from datetime import timedelta
        values["locked_until"] = datetime.now(timezone.utc) + timedelta(seconds=_LOCKOUT_SECONDS)
        logger.warning(f"Account locked due to brute force: {username}")
    if db_session is not None:
        await db_session.execute(
            update(UserTable).where(UserTable.username == username).values(**values)
        )
        await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            await session.execute(
                update(UserTable).where(UserTable.username == username).values(**values)
            )
            await session.commit()


async def _clear_failed_logins(username: str, db_session=None):
    if db_session is not None:
        await db_session.execute(
            update(UserTable).where(UserTable.username == username).values(
                login_fail_count=0, locked_until=None
            )
        )
        await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            await session.execute(
                update(UserTable).where(UserTable.username == username).values(
                    login_fail_count=0, locked_until=None
                )
            )
            await session.commit()


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
    await _check_login_lockout(data.username)
    user = await get_user_by_username(data.username)
    if user is None:
        hash_password(data.username)
        raise UnauthorizedException(detail="用户名或密码错误")
    if not user.is_active:
        raise UnauthorizedException(detail="用户账号已被停用")
    if not verify_password(data.password, user.hashed_password):
        await _record_failed_login(data.username, db_session=db)
        raise UnauthorizedException(detail="用户名或密码错误")
    await _clear_failed_logins(data.username, db_session=db)
    access_token = create_access_token(user)
    refresh_token = await create_refresh_token(user)
    await record_login_success(user.id)
    logger.info(f"User logged in: {data.username}")
    must_change = False
    if user.hashed_password and hasattr(user, 'must_change_password') and user.must_change_password:
        must_change = True
    elif user.hashed_password and verify_password("admin", user.hashed_password):
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
async def register(
    data: RegisterRequest,
    current_user: User = Depends(require_role(Role.ADMIN)),
):
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
    current_user: User = Depends(get_current_user),
):
    if not verify_password(data.current_password, current_user.hashed_password):
        raise ValidationException(detail="当前密码不正确")
    if data.current_password == data.new_password:
        raise ValidationException(detail="新密码不能与当前密码相同")
    _validate_password_strength(data.new_password)
    try:
        await update_user_password(current_user.username, data.new_password)
    except Exception as e:
        logger.error(f"Failed to update password for user {current_user.username}: {e}")
        raise ValidationException(detail="密码修改失败，请稍后重试")
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
    secret = getattr(request.app.state, 'csrf_secret', None)
    if not secret:
        from pathlib import Path
        csrf_path = Path(__file__).resolve().parent.parent.parent / ".csrf_secret"
        if csrf_path.exists():
            secret = csrf_path.read_text().strip()
        else:
            import secrets as sec
            secret = sec.token_urlsafe(32)
    import hmac
    token = hmac.new(secret.encode(), b"csrf", "sha256").hexdigest()
    return {"csrf_token": token}
