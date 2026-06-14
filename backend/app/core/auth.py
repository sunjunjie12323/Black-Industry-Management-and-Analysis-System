import asyncio
import base64
import hashlib
import hmac as hmac_module
import ipaddress
import re
import secrets
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from loguru import logger
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

from app.config import settings
from app.core.exceptions import ForbiddenException, UnauthorizedException


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Permission(str, Enum):
    PROMPT_READ = "prompt:read"
    PROMPT_WRITE = "prompt:write"
    PROMPT_DELETE = "prompt:delete"
    PIPELINE_READ = "pipeline:read"
    PIPELINE_WRITE = "pipeline:write"
    PIPELINE_EXECUTE = "pipeline:execute"
    FINETUNE_READ = "finetune:read"
    FINETUNE_WRITE = "finetune:write"
    FINETUNE_EXECUTE = "finetune:execute"
    QA_READ = "qa:read"
    QA_WRITE = "qa:write"
    TRANSLATION_READ = "translation:read"
    TRANSLATION_WRITE = "translation:write"
    CONTENT_READ = "content:read"
    CONTENT_WRITE = "content:write"
    CONTENT_REVIEW = "content:review"
    ANALYTICS_READ = "analytics:read"
    ANALYTICS_WRITE = "analytics:write"
    INDUSTRY_READ = "industry:read"
    INDUSTRY_WRITE = "industry:write"
    DEPLOYMENT_READ = "deployment:read"
    DEPLOYMENT_WRITE = "deployment:write"
    DFX_READ = "dfx:read"
    USER_MANAGE = "user:manage"
    SYSTEM_ADMIN = "system:admin"


ROLE_PERMISSIONS: Dict[Role, set] = {
    Role.ADMIN: set(Permission),
    Role.ANALYST: {
        Permission.PROMPT_READ, Permission.PROMPT_WRITE,
        Permission.PIPELINE_READ, Permission.PIPELINE_WRITE, Permission.PIPELINE_EXECUTE,
        Permission.FINETUNE_READ, Permission.FINETUNE_WRITE, Permission.FINETUNE_EXECUTE,
        Permission.QA_READ, Permission.QA_WRITE,
        Permission.TRANSLATION_READ, Permission.TRANSLATION_WRITE,
        Permission.CONTENT_READ, Permission.CONTENT_WRITE, Permission.CONTENT_REVIEW,
        Permission.ANALYTICS_READ, Permission.ANALYTICS_WRITE,
        Permission.INDUSTRY_READ, Permission.INDUSTRY_WRITE,
        Permission.DEPLOYMENT_READ,
        Permission.DFX_READ,
    },
    Role.VIEWER: {
        Permission.PROMPT_READ,
        Permission.PIPELINE_READ,
        Permission.FINETUNE_READ,
        Permission.QA_READ,
        Permission.TRANSLATION_READ,
        Permission.CONTENT_READ,
        Permission.ANALYTICS_READ,
        Permission.INDUSTRY_READ,
        Permission.DEPLOYMENT_READ,
        Permission.DFX_READ,
    },
}


class User(BaseModel):
    id: str
    username: str
    hashed_password: str
    role: Role = Role.VIEWER
    is_active: bool = True
    totp_secret: Optional[str] = None
    totp_enabled: bool = False
    last_login_at: Optional[datetime] = None
    login_fail_count: int = 0
    locked_until: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserOut(BaseModel):
    id: str
    username: str
    role: Role
    is_active: bool
    totp_enabled: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime


class TokenData(BaseModel):
    user_id: str
    username: str
    role: Role
    exp: int
    jti: str = ""


def has_permission(user: User, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(user.role, set())


def require_permission(permission: Permission):
    async def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if not has_permission(current_user, permission):
            raise ForbiddenException(
                detail=f"权限不足: 需要 '{permission.value}' 权限，当前角色 '{current_user.role.value}'"
            )
        return current_user
    return permission_checker


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

REFRESH_TOKEN_EXPIRE_DAYS = 7
MAX_REFRESH_TOKENS_PER_USER = 5


class HTTPBearer401(HTTPBearer):
    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials | None:
        try:
            return await super().__call__(request)
        except Exception:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=401,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )


security_scheme = HTTPBearer401()


def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return False, f"密码长度不能少于{settings.PASSWORD_MIN_LENGTH}位"
    if password.lower() in settings.forbidden_passwords_set:
        return False, "该密码过于常见，请使用更复杂的密码"
    if settings.PASSWORD_REQUIRE_UPPER and not re.search(r"[A-Z]", password):
        return False, "密码必须包含至少一个大写字母"
    if settings.PASSWORD_REQUIRE_LOWER and not re.search(r"[a-z]", password):
        return False, "密码必须包含至少一个小写字母"
    if settings.PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", password):
        return False, "密码必须包含至少一个数字"
    if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        return False, "密码必须包含至少一个特殊字符"
    return True, ""


def hash_password(password: str) -> str:
    return pwd_context.hash(password[:72])


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password[:72], hashed_password)
    except Exception:
        return False


def create_access_token(user: User) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = uuid4().hex
    payload = {
        "sub": user.id,
        "username": user.username,
        "role": user.role.value,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": jti,
    }
    return jwt.encode(payload, settings.secret_key_resolved, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, settings.secret_key_resolved, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise UnauthorizedException(detail="无效令牌: 缺少用户标识")
        username: str = payload.get("username", "")
        role_str: str = payload.get("role", "viewer")
        try:
            role = Role(role_str)
        except ValueError:
            role = Role.VIEWER
        exp: int = payload.get("exp", 0)
        jti: str = payload.get("jti", "")
        return TokenData(user_id=user_id, username=username, role=role, exp=exp, jti=jti)
    except JWTError as exc:
        raise UnauthorizedException(detail="无效令牌")


async def blacklist_token(token: str, db_session=None) -> None:
    from app.db.tables import TokenBlacklistTable
    import hashlib

    try:
        payload = jwt.decode(token, settings.secret_key_resolved, algorithms=[settings.ALGORITHM])
        jti = payload.get("jti", uuid4().hex)
        exp = payload.get("exp", 0)
    except JWTError:
        jti = uuid4().hex
        exp = time.time() + 3600

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if db_session is not None:
        existing = await db_session.execute(
            select(TokenBlacklistTable).where(TokenBlacklistTable.jti == jti)
        )
        if existing.scalar_one_or_none() is None:
            db_entry = TokenBlacklistTable(
                jti=jti,
                token_hash=token_hash,
                exp=exp,
            )
            db_session.add(db_entry)
            await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            existing = await session.execute(
                select(TokenBlacklistTable).where(TokenBlacklistTable.jti == jti)
            )
            if existing.scalar_one_or_none() is None:
                db_entry = TokenBlacklistTable(
                    jti=jti,
                    token_hash=token_hash,
                    exp=exp,
                )
                session.add(db_entry)
                await session.commit()
    logger.info(f"Token blacklisted: jti={jti[:8]}...")


async def is_token_blacklisted(token: str, db_session=None) -> bool:
    from app.db.tables import TokenBlacklistTable
    import hashlib

    try:
        payload = jwt.decode(token, settings.secret_key_resolved, algorithms=[settings.ALGORITHM])
        jti = payload.get("jti", "")
    except JWTError:
        return False

    if not jti:
        return False

    if db_session is not None:
        result = await db_session.execute(
            select(TokenBlacklistTable).where(TokenBlacklistTable.jti == jti)
        )
        entry = result.scalar_one_or_none()
        if entry is None:
            return False
        if entry.exp < time.time():
            await db_session.delete(entry)
            await db_session.commit()
            return False
        return True
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(TokenBlacklistTable).where(TokenBlacklistTable.jti == jti)
            )
            entry = result.scalar_one_or_none()
            if entry is None:
                return False
            if entry.exp < time.time():
                await session.delete(entry)
                await session.commit()
                return False
            return True


async def cleanup_expired_blacklisted_tokens(db_session=None) -> int:
    from app.db.tables import TokenBlacklistTable

    now = time.time()
    cleaned = 0
    if db_session is not None:
        result = await db_session.execute(
            delete(TokenBlacklistTable).where(TokenBlacklistTable.exp < now)
        )
        cleaned = result.rowcount
        await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                delete(TokenBlacklistTable).where(TokenBlacklistTable.exp < now)
            )
            cleaned = result.rowcount
            await session.commit()
    if cleaned > 0:
        logger.info(f"Cleaned up {cleaned} expired blacklisted tokens")
    return cleaned


async def log_audit(
    action: str,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    resource: Optional[str] = None,
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    db_session=None,
):
    from app.core.audit import audit_log_async
    resource_type = None
    resource_id = None
    if resource and ":" in resource:
        resource_type, resource_id = resource.split(":", 1)
    elif resource:
        resource_type = resource
    await audit_log_async(
        action=action,
        user_id=user_id,
        username=username,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        db_session=db_session,
        details=detail,
    )


async def get_user_by_username(username: str, db_session=None) -> Optional[User]:
    from app.db.tables import UserTable

    if db_session is not None:
        result = await db_session.execute(
            select(UserTable).where(UserTable.username == username)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_user(row)
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(UserTable).where(UserTable.username == username)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None
            return _row_to_user(row)


async def get_user_by_id(user_id: str, db_session=None) -> Optional[User]:
    from app.db.tables import UserTable

    if db_session is not None:
        result = await db_session.execute(
            select(UserTable).where(UserTable.id == user_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_user(row)
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(UserTable).where(UserTable.id == user_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None
            return _row_to_user(row)


async def get_all_users(db_session=None) -> List[User]:
    from app.db.tables import UserTable

    if db_session is not None:
        result = await db_session.execute(select(UserTable))
        return [_row_to_user(row) for row in result.scalars().all()]
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(select(UserTable))
            return [_row_to_user(row) for row in result.scalars().all()]


async def create_user(username: str, password: str, role: Role = Role.VIEWER, skip_strength_check: bool = False, db_session=None) -> User:
    from app.db.tables import UserTable

    existing = await get_user_by_username(username, db_session=db_session)
    if existing:
        raise ValueError(f"用户名 '{username}' 已存在")

    if not skip_strength_check:
        is_strong, msg = validate_password_strength(password)
        if not is_strong:
            raise ValueError(msg)

    user_id = uuid4().hex
    hashed = hash_password(password)
    now = datetime.now(timezone.utc)

    if db_session is not None:
        db_user = UserTable(
            id=user_id,
            username=username,
            hashed_password=hashed,
            role=role.value,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        db_session.add(db_user)
        await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            db_user = UserTable(
                id=user_id,
                username=username,
                hashed_password=hashed,
                role=role.value,
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            session.add(db_user)
            await session.commit()

    user = User(
        id=user_id,
        username=username,
        hashed_password=hashed,
        role=role,
        is_active=True,
        created_at=now,
    )
    logger.info(f"User created: {username} (role={role.value})")
    await log_audit(action="user_created", username=username, detail=f"role={role.value}", db_session=db_session)
    return user


async def update_user_password(username: str, new_password: str, skip_strength_check: bool = False, db_session=None) -> bool:
    from app.db.tables import UserTable

    if not skip_strength_check:
        is_strong, msg = validate_password_strength(new_password)
        if not is_strong:
            raise ValueError(msg)

    if db_session is not None:
        result = await db_session.execute(
            select(UserTable).where(UserTable.username == username)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        row.hashed_password = hash_password(new_password)
        row.updated_at = datetime.now(timezone.utc)
        await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(UserTable).where(UserTable.username == username)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return False
            row.hashed_password = hash_password(new_password)
            row.updated_at = datetime.now(timezone.utc)
            await session.commit()

    logger.info(f"Password updated for user: {username}")
    await log_audit(action="password_changed", username=username, db_session=db_session)
    return True


async def deactivate_user(username: str, db_session=None) -> bool:
    from app.db.tables import UserTable

    if db_session is not None:
        result = await db_session.execute(
            select(UserTable).where(UserTable.username == username)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        row.is_active = False
        row.updated_at = datetime.now(timezone.utc)
        await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(UserTable).where(UserTable.username == username)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return False
            row.is_active = False
            row.updated_at = datetime.now(timezone.utc)
            await session.commit()

    logger.info(f"User deactivated: {username}")
    await log_audit(action="user_deactivated", username=username, db_session=db_session)
    return True


async def record_login_success(user_id: str, db_session=None):
    from app.db.tables import UserTable

    if db_session is not None:
        result = await db_session.execute(
            select(UserTable).where(UserTable.id == user_id)
        )
        row = result.scalar_one_or_none()
        if row:
            row.login_fail_count = 0
            row.locked_until = None
            row.last_login_at = datetime.now(timezone.utc)
            row.updated_at = datetime.now(timezone.utc)
            await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(UserTable).where(UserTable.id == user_id)
            )
            row = result.scalar_one_or_none()
            if row:
                row.login_fail_count = 0
                row.locked_until = None
                row.last_login_at = datetime.now(timezone.utc)
                row.updated_at = datetime.now(timezone.utc)
                await session.commit()


async def record_login_failure(username: str, db_session=None):
    from app.db.tables import UserTable

    if db_session is not None:
        result = await db_session.execute(
            select(UserTable).where(UserTable.username == username)
        )
        row = result.scalar_one_or_none()
        if row:
            row.login_fail_count = (row.login_fail_count or 0) + 1
            if row.login_fail_count >= settings.MAX_LOGIN_FAILS:
                row.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.LOCKOUT_MINUTES)
                logger.warning(f"User {username} locked until {row.locked_until}")
            row.updated_at = datetime.now(timezone.utc)
            await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(UserTable).where(UserTable.username == username)
            )
            row = result.scalar_one_or_none()
            if row:
                row.login_fail_count = (row.login_fail_count or 0) + 1
                if row.login_fail_count >= settings.MAX_LOGIN_FAILS:
                    row.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.LOCKOUT_MINUTES)
                    logger.warning(f"User {username} locked until {row.locked_until}")
                row.updated_at = datetime.now(timezone.utc)
                await session.commit()


async def is_user_locked(username: str, db_session=None) -> bool:
    from app.db.tables import UserTable

    if db_session is not None:
        result = await db_session.execute(
            select(UserTable).where(UserTable.username == username)
        )
        row = result.scalar_one_or_none()
        if row and row.locked_until:
            if row.locked_until and datetime.now(timezone.utc) < row.locked_until.replace(tzinfo=timezone.utc):
                return True
            else:
                row.locked_until = None
                row.login_fail_count = 0
                await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(UserTable).where(UserTable.username == username)
            )
            row = result.scalar_one_or_none()
            if row and row.locked_until:
                if row.locked_until and datetime.now(timezone.utc) < row.locked_until.replace(tzinfo=timezone.utc):
                    return True
                else:
                    row.locked_until = None
                    row.login_fail_count = 0
                    await session.commit()
    return False


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> User:
    token = credentials.credentials
    if await is_token_blacklisted(token):
        raise UnauthorizedException(detail="令牌已被撤销，请重新登录")
    token_data = decode_access_token(token)
    user = await get_user_by_id(token_data.user_id)
    if user is None:
        raise UnauthorizedException(detail="用户不存在")
    if not user.is_active:
        raise UnauthorizedException(detail="用户账号已被停用")
    return user


def require_role(*allowed_roles: Role):
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise ForbiddenException(
                detail=f"权限不足: 当前角色 '{current_user.role.value}'，"
                       f"需要: {[r.value for r in allowed_roles]}"
            )
        return current_user
    return role_checker


async def create_default_admin() -> User:
    username = settings.DEFAULT_ADMIN_USERNAME
    existing = await get_user_by_username(username)
    if existing is not None:
        logger.info(f"Default admin user '{username}' already exists")
        return existing

    admin_password = settings.DEFAULT_ADMIN_PASSWORD
    if not admin_password:
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        admin_password = ''.join(secrets.choice(alphabet) for _ in range(16))

    user = await create_user(
        username=username,
        password=admin_password,
        role=Role.ADMIN,
        skip_strength_check=True,
    )
    logger.warning(
        f"DEFAULT ADMIN CREATED — username: {username} — "
        f"auto-generated password (shown once only): {admin_password}"
    )
    return user


def _row_to_user(row) -> User:
    return User(
        id=row.id,
        username=row.username,
        hashed_password=row.hashed_password,
        role=Role(row.role),
        is_active=row.is_active,
        totp_secret=row.totp_secret,
        totp_enabled=row.totp_enabled,
        last_login_at=row.last_login_at,
        login_fail_count=row.login_fail_count or 0,
        locked_until=row.locked_until,
        created_at=row.created_at,
    )


async def create_refresh_token(user: User, db_session=None) -> str:
    import hashlib
    raw = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    from app.db.tables import RefreshTokenTable
    if db_session is not None:
        count_result = await db_session.execute(
            select(RefreshTokenTable)
            .where(RefreshTokenTable.user_id == user.id)
            .where(RefreshTokenTable.is_revoked == False)
            .order_by(RefreshTokenTable.created_at)
        )
        existing = count_result.scalars().all()
        if len(existing) >= MAX_REFRESH_TOKENS_PER_USER:
            oldest = existing[0]
            oldest.is_revoked = True

        entry = RefreshTokenTable(
            id=uuid4().hex,
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            is_revoked=False,
            created_at=now,
        )
        db_session.add(entry)
        await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            count_result = await session.execute(
                select(RefreshTokenTable)
                .where(RefreshTokenTable.user_id == user.id)
                .where(RefreshTokenTable.is_revoked == False)
                .order_by(RefreshTokenTable.created_at)
            )
            existing = count_result.scalars().all()
            if len(existing) >= MAX_REFRESH_TOKENS_PER_USER:
                oldest = existing[0]
                oldest.is_revoked = True

            entry = RefreshTokenTable(
                id=uuid4().hex,
                user_id=user.id,
                token_hash=token_hash,
                expires_at=expires_at,
                is_revoked=False,
                created_at=now,
            )
            session.add(entry)
            await session.commit()

    return raw


async def verify_refresh_token(raw_token: str, db_session=None) -> Optional[User]:
    import hashlib
    from app.db.tables import RefreshTokenTable

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    now = datetime.now(timezone.utc)

    if db_session is not None:
        result = await db_session.execute(
            select(RefreshTokenTable).where(
                RefreshTokenTable.token_hash == token_hash,
                RefreshTokenTable.is_revoked == False,
            )
        )
        entry = result.scalar_one_or_none()
        if entry is None:
            return None
        if entry.expires_at.replace(tzinfo=timezone.utc) < now:
            entry.is_revoked = True
            await db_session.commit()
            return None

        user = await get_user_by_id(entry.user_id, db_session=db_session)
        return user
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(RefreshTokenTable).where(
                    RefreshTokenTable.token_hash == token_hash,
                    RefreshTokenTable.is_revoked == False,
                )
            )
            entry = result.scalar_one_or_none()
            if entry is None:
                return None
            if entry.expires_at.replace(tzinfo=timezone.utc) < now:
                entry.is_revoked = True
                await session.commit()
                return None

            user = await get_user_by_id(entry.user_id)
            return user


async def revoke_refresh_token(raw_token: str, db_session=None) -> bool:
    import hashlib
    from app.db.tables import RefreshTokenTable

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    if db_session is not None:
        result = await db_session.execute(
            select(RefreshTokenTable).where(RefreshTokenTable.token_hash == token_hash)
        )
        entry = result.scalar_one_or_none()
        if entry is None:
            return False
        entry.is_revoked = True
        await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(RefreshTokenTable).where(RefreshTokenTable.token_hash == token_hash)
            )
            entry = result.scalar_one_or_none()
            if entry is None:
                return False
            entry.is_revoked = True
            await session.commit()
    return True


async def revoke_all_refresh_tokens(user_id: str, db_session=None) -> int:
    from app.db.tables import RefreshTokenTable

    if db_session is not None:
        result = await db_session.execute(
            select(RefreshTokenTable).where(
                RefreshTokenTable.user_id == user_id,
                RefreshTokenTable.is_revoked == False,
            )
        )
        entries = result.scalars().all()
        for entry in entries:
            entry.is_revoked = True
        await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(RefreshTokenTable).where(
                    RefreshTokenTable.user_id == user_id,
                    RefreshTokenTable.is_revoked == False,
                )
            )
            entries = result.scalars().all()
            for entry in entries:
                entry.is_revoked = True
            await session.commit()
    return len(entries)


async def cleanup_expired_refresh_tokens(db_session=None) -> int:
    from app.db.tables import RefreshTokenTable

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cleaned = 0
    if db_session is not None:
        result = await db_session.execute(
            delete(RefreshTokenTable).where(RefreshTokenTable.expires_at < now)
        )
        cleaned = result.rowcount
        await db_session.commit()
    else:
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                delete(RefreshTokenTable).where(RefreshTokenTable.expires_at < now)
            )
            cleaned = result.rowcount
            await session.commit()
    return cleaned


class TOTP:
    """基于RFC 6238手动实现的TOTP(基于时间的一次性密码)生成与验证类。"""

    DIGITS: int = 6
    TIME_STEP: int = 30
    HASH_ALGORITHM: str = "sha1"

    @staticmethod
    def generate_secret() -> str:
        """生成一个随机的TOTP密钥，返回base32编码字符串。

        Returns:
            str: base32编码的随机密钥，长度为32字符(20字节随机数据)。
        """
        random_bytes = secrets.token_bytes(20)
        return base64.b32encode(random_bytes).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_base32_secret(secret: str) -> bytes:
        """将base32编码的密钥解码为原始字节，自动补齐填充字符。

        Args:
            secret: base32编码的密钥字符串。

        Returns:
            bytes: 解码后的原始字节。
        """
        padding = (8 - len(secret) % 8) % 8
        padded = secret + "=" * padding
        return base64.b32decode(padded.upper())

    @classmethod
    def _generate_hotp(cls, secret: bytes, counter: int) -> str:
        """根据密钥和计数器生成HOTP码(RFC 4226)。

        Args:
            secret: 原始密钥字节。
            counter: HOTP计数器值。

        Returns:
            str: 指定位数的HOTP数字码。
        """
        counter_bytes = struct.pack(">Q", counter)
        hmac_hash = hmac_module.new(secret, counter_bytes, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        truncated = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
        code = truncated % (10 ** cls.DIGITS)
        return str(code).zfill(cls.DIGITS)

    @classmethod
    def generate_qr_code_uri(cls, username: str, secret: str, issuer: str = "ThreatIntel") -> str:
        """生成otpauth://格式的URI，用于二维码扫描绑定TOTP。

        Args:
            username: 用户名，用于URI中的账户标识。
            secret: base32编码的TOTP密钥。
            issuer: 发行者名称，默认为"ThreatIntel"。

        Returns:
            str: 符合otpauth://totp/格式的URI字符串。
        """
        from urllib.parse import quote
        account = quote(username)
        issuer_encoded = quote(issuer)
        return f"otpauth://totp/{issuer_encoded}:{account}?secret={secret}&issuer={issuer_encoded}&algorithm=SHA1&digits={cls.DIGITS}&period={cls.TIME_STEP}"

    @classmethod
    def verify_totp(cls, secret: str, code: str, valid_window: int = 1) -> bool:
        """验证TOTP码是否匹配，支持时间窗口容差。

        Args:
            secret: base32编码的TOTP密钥。
            code: 用户输入的TOTP验证码。
            valid_window: 允许的时间窗口偏移量，默认为1(前后各1个时间步)。
                         0表示仅验证当前时间步，1表示前后各1步。

        Returns:
            bool: 验证码是否匹配。
        """
        secret_bytes = cls._decode_base32_secret(secret)
        current_counter = int(time.time()) // cls.TIME_STEP
        for offset in range(-valid_window, valid_window + 1):
            counter = current_counter + offset
            expected = cls._generate_hotp(secret_bytes, counter)
            if hmac_module.compare_digest(expected, code):
                return True
        return False


class PasswordHistory:
    """密码历史检查与记录类，防止用户重复使用近期密码。"""

    MAX_HISTORY: int = 5

    @staticmethod
    async def check_password_history(user_id: str, new_password: str, db_session=None) -> bool:
        """检查新密码是否与用户最近N次密码历史重复。

        Args:
            user_id: 用户ID。
            new_password: 待检查的新密码明文。
            db_session: 可选的数据库会话。

        Returns:
            bool: True表示密码未重复(可以使用)，False表示密码与历史重复。
        """
        from app.db.tables import PasswordHistoryTable

        if db_session is not None:
            result = await db_session.execute(
                select(PasswordHistoryTable)
                .where(PasswordHistoryTable.user_id == user_id)
                .order_by(PasswordHistoryTable.created_at.desc())
                .limit(PasswordHistory.MAX_HISTORY)
            )
            records = result.scalars().all()
        else:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                result = await session.execute(
                    select(PasswordHistoryTable)
                    .where(PasswordHistoryTable.user_id == user_id)
                    .order_by(PasswordHistoryTable.created_at.desc())
                    .limit(PasswordHistory.MAX_HISTORY)
                )
                records = result.scalars().all()

        for record in records:
            if verify_password(new_password, record.password_hash):
                return False
        return True

    @staticmethod
    async def record_password_history(user_id: str, password_hash: str, db_session=None) -> None:
        """记录密码哈希到历史表，并自动清理超出保留数量的旧记录。

        Args:
            user_id: 用户ID。
            password_hash: 密码的bcrypt哈希值。
            db_session: 可选的数据库会话。
        """
        from app.db.tables import PasswordHistoryTable

        now = datetime.now(timezone.utc)

        if db_session is not None:
            entry = PasswordHistoryTable(
                id=uuid4().hex,
                user_id=user_id,
                password_hash=password_hash,
                created_at=now,
            )
            db_session.add(entry)
            await db_session.commit()

            count_result = await db_session.execute(
                select(PasswordHistoryTable)
                .where(PasswordHistoryTable.user_id == user_id)
                .order_by(PasswordHistoryTable.created_at.desc())
            )
            all_records = count_result.scalars().all()
            if len(all_records) > PasswordHistory.MAX_HISTORY:
                for old_record in all_records[PasswordHistory.MAX_HISTORY:]:
                    await db_session.delete(old_record)
                await db_session.commit()
        else:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                entry = PasswordHistoryTable(
                    id=uuid4().hex,
                    user_id=user_id,
                    password_hash=password_hash,
                    created_at=now,
                )
                session.add(entry)
                await session.commit()

                count_result = await session.execute(
                    select(PasswordHistoryTable)
                    .where(PasswordHistoryTable.user_id == user_id)
                    .order_by(PasswordHistoryTable.created_at.desc())
                )
                all_records = count_result.scalars().all()
                if len(all_records) > PasswordHistory.MAX_HISTORY:
                    for old_record in all_records[PasswordHistory.MAX_HISTORY:]:
                        await session.delete(old_record)
                    await session.commit()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """安全响应头中间件，为所有HTTP响应添加标准安全头。"""

    async def dispatch(self, request: StarletteRequest, call_next) -> StarletteResponse:
        """处理请求并添加安全响应头。

        Args:
            request: 传入的HTTP请求。
            call_next: 下一个中间件或路由处理函数。

        Returns:
            StarletteResponse: 添加了安全头的HTTP响应。
        """
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), "
            "microphone=(), "
            "geolocation=(), "
            "payment=(), "
            "usb=()"
        )
        return response


class IPWhitelist:
    """IP白名单与黑名单管理类，支持单IP和CIDR格式的网段匹配。"""

    def __init__(self) -> None:
        """初始化IPWhitelist，创建空的白名单和黑名单存储。"""
        self._whitelist: List[Dict[str, Any]] = []
        self._blacklist: List[Dict[str, Any]] = []

    def add_to_whitelist(self, ip_or_cidr: str, description: str = "") -> None:
        """添加IP或CIDR网段到白名单。

        Args:
            ip_or_cidr: IP地址(如"192.168.1.1")或CIDR格式网段(如"192.168.1.0/24")。
            description: 白名单条目的描述信息。
        """
        network = ipaddress.ip_network(ip_or_cidr, strict=False)
        self._whitelist.append({
            "network": network,
            "description": description,
            "added_at": datetime.now(timezone.utc),
        })
        logger.info(f"IP whitelist added: {ip_or_cidr} ({description})")

    def add_to_blacklist(self, ip_or_cidr: str, reason: str = "", expires_at: Optional[datetime] = None) -> None:
        """添加IP或CIDR网段到黑名单。

        Args:
            ip_or_cidr: IP地址或CIDR格式网段。
            reason: 加入黑名单的原因。
            expires_at: 黑名单条目的过期时间，None表示永不过期。
        """
        network = ipaddress.ip_network(ip_or_cidr, strict=False)
        self._blacklist.append({
            "network": network,
            "reason": reason,
            "added_at": datetime.now(timezone.utc),
            "expires_at": expires_at,
        })
        logger.info(f"IP blacklist added: {ip_or_cidr} ({reason})")

    def is_allowed(self, ip_address: str) -> bool:
        """检查IP地址是否被允许访问。

        优先检查黑名单(黑名单优先)，如果IP在黑名单中且未过期则拒绝。
        如果白名单非空且IP不在白名单中则拒绝。
        其他情况允许。

        Args:
            ip_address: 待检查的IP地址字符串。

        Returns:
            bool: True表示IP被允许访问，False表示被拒绝。
        """
        try:
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return False

        now = datetime.now(timezone.utc)
        for entry in self._blacklist:
            if ip in entry["network"]:
                if entry["expires_at"] is None or entry["expires_at"] > now:
                    return False

        if self._whitelist:
            for entry in self._whitelist:
                if ip in entry["network"]:
                    return True
            return False

        return True

    def remove_from_whitelist(self, ip_or_cidr: str) -> bool:
        """从白名单中移除指定的IP或CIDR网段。

        Args:
            ip_or_cidr: 要移除的IP地址或CIDR网段。

        Returns:
            bool: True表示成功移除，False表示条目不存在。
        """
        network = ipaddress.ip_network(ip_or_cidr, strict=False)
        for i, entry in enumerate(self._whitelist):
            if entry["network"] == network:
                self._whitelist.pop(i)
                logger.info(f"IP whitelist removed: {ip_or_cidr}")
                return True
        return False

    def remove_from_blacklist(self, ip_or_cidr: str) -> bool:
        """从黑名单中移除指定的IP或CIDR网段。

        Args:
            ip_or_cidr: 要移除的IP地址或CIDR网段。

        Returns:
            bool: True表示成功移除，False表示条目不存在。
        """
        network = ipaddress.ip_network(ip_or_cidr, strict=False)
        for i, entry in enumerate(self._blacklist):
            if entry["network"] == network:
                self._blacklist.pop(i)
                logger.info(f"IP blacklist removed: {ip_or_cidr}")
                return True
        return False

    def cleanup_expired_blacklist(self) -> int:
        """清理黑名单中已过期的条目。

        Returns:
            int: 被清理的过期条目数量。
        """
        now = datetime.now(timezone.utc)
        original_len = len(self._blacklist)
        self._blacklist = [
            entry for entry in self._blacklist
            if entry["expires_at"] is None or entry["expires_at"] > now
        ]
        cleaned = original_len - len(self._blacklist)
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} expired blacklist entries")
        return cleaned


class SessionManager:

    def __init__(self) -> None:
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._user_sessions: Dict[str, Set[str]] = {}
        self._lock = threading.Lock()
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False

    def start_cleanup(self) -> None:
        """启动后台会话清理线程。"""
        if self._cleanup_thread is not None and self._cleanup_thread.is_alive():
            return
        self._running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        logger.info("Session cleanup thread started")

    def stop_cleanup(self) -> None:
        """停止后台会话清理线程。"""
        self._running = False
        if self._cleanup_thread is not None:
            self._cleanup_thread.join(timeout=10)
            self._cleanup_thread = None
        logger.info("Session cleanup thread stopped")

    def _cleanup_loop(self) -> None:
        """会话清理循环，定期清理过期会话。"""
        while self._running:
            time.sleep(settings.CLEANUP_INTERVAL_SECONDS)
            self.cleanup_expired_sessions()

    def create_session(self, user_id: str, ip_address: str, user_agent: str) -> str:
        """创建新的用户会话，如果超过并发会话数限制则销毁最旧的会话。

        Args:
            user_id: 用户ID。
            ip_address: 客户端IP地址。
            user_agent: 客户端User-Agent字符串。

        Returns:
            str: 新创建的会话ID。
        """
        session_id = uuid4().hex
        now = datetime.now(timezone.utc)

        with self._lock:
            if user_id not in self._user_sessions:
                self._user_sessions[user_id] = set()

            user_session_ids = self._user_sessions[user_id]
            if len(user_session_ids) >= settings.MAX_CONCURRENT_SESSIONS:
                oldest_sid = None
                oldest_time = None
                for sid in user_session_ids:
                    if sid in self._sessions:
                        created = self._sessions[sid].get("created_at")
                        if oldest_time is None or created < oldest_time:
                            oldest_time = created
                            oldest_sid = sid
                if oldest_sid is not None:
                    self._destroy_session_internal(oldest_sid)

            self._sessions[session_id] = {
                "user_id": user_id,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "created_at": now,
                "last_activity": now,
            }
            self._user_sessions[user_id].add(session_id)

        logger.info(f"Session created: user={user_id}, session={session_id[:8]}..., ip={ip_address}")
        return session_id

    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """验证会话是否有效，如果有效则更新最后活动时间。

        Args:
            session_id: 待验证的会话ID。

        Returns:
            Optional[Dict[str, Any]]: 会话信息字典，如果会话无效或已过期则返回None。
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None

            now = datetime.now(timezone.utc)
            timeout = timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES)
            if now - session["last_activity"] > timeout:
                self._destroy_session_internal(session_id)
                return None

            session["last_activity"] = now
            return dict(session)

    def destroy_session(self, session_id: str) -> bool:
        """销毁指定会话。

        Args:
            session_id: 要销毁的会话ID。

        Returns:
            bool: True表示成功销毁，False表示会话不存在。
        """
        with self._lock:
            if session_id not in self._sessions:
                return False
            self._destroy_session_internal(session_id)
            return True

    def _destroy_session_internal(self, session_id: str) -> None:
        """内部方法：销毁会话(调用方需持有锁)。

        Args:
            session_id: 要销毁的会话ID。
        """
        session = self._sessions.pop(session_id, None)
        if session is not None:
            user_id = session["user_id"]
            if user_id in self._user_sessions:
                self._user_sessions[user_id].discard(session_id)
                if not self._user_sessions[user_id]:
                    del self._user_sessions[user_id]

    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """获取用户所有活跃会话的信息列表。

        Args:
            user_id: 用户ID。

        Returns:
            List[Dict[str, Any]]: 活跃会话信息列表，每个字典包含session_id、ip_address、user_agent、created_at、last_activity。
        """
        with self._lock:
            session_ids = self._user_sessions.get(user_id, set()).copy()

        result = []
        now = datetime.now(timezone.utc)
        timeout = timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES)

        for sid in session_ids:
            with self._lock:
                session = self._sessions.get(sid)
                if session is None:
                    continue
                if now - session["last_activity"] > timeout:
                    continue
                result.append({
                    "session_id": sid,
                    "ip_address": session["ip_address"],
                    "user_agent": session["user_agent"],
                    "created_at": session["created_at"],
                    "last_activity": session["last_activity"],
                })

        return result

    def destroy_all_sessions(self, user_id: str) -> int:
        """销毁用户所有活跃会话(强制下线)。

        Args:
            user_id: 用户ID。

        Returns:
            int: 被销毁的会话数量。
        """
        with self._lock:
            session_ids = list(self._user_sessions.get(user_id, set()))

        count = 0
        for sid in session_ids:
            with self._lock:
                if sid in self._sessions:
                    self._destroy_session_internal(sid)
                    count += 1

        if count > 0:
            logger.info(f"Destroyed {count} sessions for user {user_id}")
        return count

    def cleanup_expired_sessions(self) -> int:
        """清理所有过期会话。

        Returns:
            int: 被清理的过期会话数量。
        """
        now = datetime.now(timezone.utc)
        timeout = timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES)
        expired = []

        with self._lock:
            for sid, session in self._sessions.items():
                if now - session["last_activity"] > timeout:
                    expired.append(sid)

        for sid in expired:
            with self._lock:
                self._destroy_session_internal(sid)

        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")
        return len(expired)


class BruteForceProtection:

    def __init__(self) -> None:
        self._ip_attempts: Dict[str, Dict[str, Any]] = {}

    def record_failed_attempt(self, ip_address: str, username: str = "") -> None:
        """记录来自指定IP的登录失败尝试，并根据失败次数应用指数退避锁定。

        Args:
            ip_address: 发起登录请求的IP地址。
            username: 尝试登录的用户名(可选，用于审计)。
        """
        now = datetime.now(timezone.utc)

        if ip_address not in self._ip_attempts:
            if len(self._ip_attempts) >= settings.MAX_TRACKED_IPS:
                self._evict_oldest()
            self._ip_attempts[ip_address] = {
                "count": 0,
                "first_attempt": now,
                "last_attempt": now,
                "locked_until": None,
                "usernames": [],
            }

        record = self._ip_attempts[ip_address]
        record["count"] += 1
        record["last_attempt"] = now
        if username and username not in record["usernames"]:
            record["usernames"].append(username)
            if len(record["usernames"]) > 10:
                record["usernames"] = record["usernames"][-10:]

        backoff_minutes = settings.brute_force_backoff.get(record["count"])
        if backoff_minutes is not None:
            record["locked_until"] = now + timedelta(minutes=backoff_minutes)
            logger.warning(
                f"IP {ip_address} brute force lockout: {record['count']} attempts, "
                f"locked for {backoff_minutes} minutes"
            )

    def check_ip_brute_force(self, ip_address: str) -> Tuple[bool, Optional[int]]:
        """检查指定IP是否处于暴力破解锁定状态。

        Args:
            ip_address: 待检查的IP地址。

        Returns:
            Tuple[bool, Optional[int]]: 第一个元素为True表示IP被锁定(拒绝)，
                第二个元素为锁定剩余秒数(未锁定时为None)。
        """
        record = self._ip_attempts.get(ip_address)
        if record is None:
            return False, None

        if record["locked_until"] is not None:
            now = datetime.now(timezone.utc)
            if now < record["locked_until"]:
                remaining = int((record["locked_until"] - now).total_seconds())
                return True, remaining
            else:
                record["locked_until"] = None

        return False, None

    def get_brute_force_status(self) -> Dict[str, Any]:
        """获取当前暴力破解防护的全局状态摘要。

        Returns:
            Dict[str, Any]]: 包含total_tracked_ips(追踪的IP总数)、
                currently_locked(当前被锁定的IP数)、
                locked_ips(被锁定IP的详细信息列表)。
        """
        now = datetime.now(timezone.utc)
        locked_ips = []
        currently_locked = 0

        for ip, record in self._ip_attempts.items():
            if record["locked_until"] is not None and now < record["locked_until"]:
                currently_locked += 1
                remaining = int((record["locked_until"] - now).total_seconds())
                locked_ips.append({
                    "ip_address": ip,
                    "attempt_count": record["count"],
                    "locked_remaining_seconds": remaining,
                    "usernames_tried": record["usernames"],
                })

        return {
            "total_tracked_ips": len(self._ip_attempts),
            "currently_locked": currently_locked,
            "locked_ips": locked_ips,
        }

    def reset_ip(self, ip_address: str) -> bool:
        """重置指定IP的失败记录(例如登录成功后调用)。

        Args:
            ip_address: 要重置的IP地址。

        Returns:
            bool: True表示成功重置，False表示IP无记录。
        """
        if ip_address in self._ip_attempts:
            del self._ip_attempts[ip_address]
            return True
        return False

    def _evict_oldest(self) -> None:
        """淘汰最旧的IP记录，当追踪IP数量超过上限时调用。"""
        if not self._ip_attempts:
            return
        oldest_ip = min(
            self._ip_attempts,
            key=lambda ip: self._ip_attempts[ip]["last_attempt"]
        )
        del self._ip_attempts[oldest_ip]

    def cleanup_expired(self) -> int:
        """清理超过TTL的IP失败记录。

        Returns:
            int: 被清理的记录数量。
        """
        now = datetime.now(timezone.utc)
        expired_ips = []

        for ip, record in self._ip_attempts.items():
            if (now - record["last_attempt"]).total_seconds() > settings.ATTEMPT_TTL_SECONDS:
                if record["locked_until"] is None or now >= record["locked_until"]:
                    expired_ips.append(ip)

        for ip in expired_ips:
            del self._ip_attempts[ip]

        if expired_ips:
            logger.info(f"Cleaned up {len(expired_ips)} expired brute force records")
        return len(expired_ips)


ip_whitelist = IPWhitelist()
session_manager = SessionManager()
brute_force_protection = BruteForceProtection()
