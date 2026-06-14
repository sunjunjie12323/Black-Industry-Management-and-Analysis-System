import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import uuid4

from loguru import logger
from sqlalchemy import select, and_


class ApiPermission(str, Enum):
    INTEL_READ = "intel:read"
    INTEL_WRITE = "intel:write"
    ENTITY_READ = "entity:read"
    ALERT_READ = "alert:read"
    SEARCH_QUERY = "search:query"
    EXPORT_STIX = "export:stix"
    ADMIN = "admin"


@dataclass
class ApiKey:
    key_id: str
    key_hash: str
    key_prefix: str
    tenant_id: str
    name: str
    permissions: List[str] = field(default_factory=list)
    rate_limit: int = 60
    daily_quota: int = 1000
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    is_active: bool = True


class ApiKeyManager:
    async def generate_api_key(
        self,
        tenant_id: str,
        name: str,
        permissions: List[str],
        expires_days: int = 365,
        rate_limit: int = 60,
        daily_quota: int = 1000,
        db_session=None,
    ) -> tuple[str, str]:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.generate_api_key(tenant_id, name, permissions, expires_days, rate_limit, daily_quota, db_session=session)
        from app.db.tables import ApiKeyTable
        key_id = uuid4().hex
        raw_key = f"tia_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_prefix = f"tia_{raw_key[4:12]}"
        now = datetime.now(timezone.utc)
        expires_at = now.replace(year=now.year + expires_days // 365) if expires_days > 0 else None
        if expires_days > 0 and expires_days <= 365:
            from datetime import timedelta
            expires_at = now + timedelta(days=expires_days)
        db_key = ApiKeyTable(
            id=key_id,
            key_hash=key_hash,
            key_prefix=key_prefix,
            tenant_id=tenant_id,
            name=name,
            permissions_json=json.dumps(permissions, ensure_ascii=False),
            rate_limit=rate_limit,
            daily_quota=daily_quota,
            created_at=now,
            expires_at=expires_at,
            is_active=True,
        )
        db_session.add(db_key)
        await db_session.commit()
        logger.info(f"API key generated: {key_prefix} (tenant={tenant_id})")
        return key_id, raw_key

    async def validate_api_key(self, raw_key: str, db_session=None) -> Optional[ApiKey]:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.validate_api_key(raw_key, db_session=session)
        from app.db.tables import ApiKeyTable
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        result = await db_session.execute(
            select(ApiKeyTable).where(
                and_(
                    ApiKeyTable.key_hash == key_hash,
                    ApiKeyTable.is_active == True,
                )
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        if row.expires_at and row.expires_at.replace(tzinfo=None) < datetime.now(timezone.utc):
            return None
        row.last_used_at = datetime.now(timezone.utc)
        await db_session.commit()
        permissions = []
        if row.permissions_json:
            try:
                permissions = json.loads(row.permissions_json)
            except (json.JSONDecodeError, TypeError):
                pass
        return ApiKey(
            key_id=row.id,
            key_hash=row.key_hash,
            key_prefix=row.key_prefix,
            tenant_id=row.tenant_id,
            name=row.name,
            permissions=permissions,
            rate_limit=row.rate_limit,
            daily_quota=row.daily_quota,
            created_at=row.created_at,
            expires_at=row.expires_at,
            last_used_at=row.last_used_at,
            is_active=row.is_active,
        )

    async def revoke_api_key(self, key_id: str, db_session=None) -> bool:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.revoke_api_key(key_id, db_session=session)
        from app.db.tables import ApiKeyTable
        result = await db_session.execute(
            select(ApiKeyTable).where(ApiKeyTable.id == key_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        row.is_active = False
        await db_session.commit()
        logger.info(f"API key revoked: {key_id}")
        return True

    async def list_api_keys(self, tenant_id: str, db_session=None) -> List[ApiKey]:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.list_api_keys(tenant_id, db_session=session)
        from app.db.tables import ApiKeyTable
        result = await db_session.execute(
            select(ApiKeyTable).where(ApiKeyTable.tenant_id == tenant_id)
        )
        keys = []
        for row in result.scalars().all():
            permissions = []
            if row.permissions_json:
                try:
                    permissions = json.loads(row.permissions_json)
                except (json.JSONDecodeError, TypeError):
                    pass
            keys.append(ApiKey(
                key_id=row.id,
                key_hash=row.key_hash,
                key_prefix=row.key_prefix,
                tenant_id=row.tenant_id,
                name=row.name,
                permissions=permissions,
                rate_limit=row.rate_limit,
                daily_quota=row.daily_quota,
                created_at=row.created_at,
                expires_at=row.expires_at,
                last_used_at=row.last_used_at,
                is_active=row.is_active,
            ))
        return keys

    async def check_permission(self, key_id: str, permission: str, db_session=None) -> bool:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.check_permission(key_id, permission, db_session=session)
        from app.db.tables import ApiKeyTable
        result = await db_session.execute(
            select(ApiKeyTable).where(
                and_(ApiKeyTable.id == key_id, ApiKeyTable.is_active == True)
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        permissions = []
        if row.permissions_json:
            try:
                permissions = json.loads(row.permissions_json)
            except (json.JSONDecodeError, TypeError):
                pass
        return ApiPermission.ADMIN.value in permissions or permission in permissions

    async def check_rate_limit(self, key_id: str, db_session=None) -> bool:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.check_rate_limit(key_id, db_session=session)
        from app.db.tables import ApiKeyTable, ApiKeyUsageTable
        now = datetime.now(timezone.utc)
        window_start = now.replace(second=0, microsecond=0)
        result = await db_session.execute(
            select(ApiKeyTable).where(ApiKeyTable.id == key_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        rate_limit = row.rate_limit
        usage_result = await db_session.execute(
            select(ApiKeyUsageTable).where(
                and_(
                    ApiKeyUsageTable.key_id == key_id,
                    ApiKeyUsageTable.window_start == window_start,
                )
            )
        )
        usage_row = usage_result.scalar_one_or_none()
        if usage_row is None:
            return True
        return usage_row.request_count < rate_limit

    async def record_usage(self, key_id: str, db_session=None) -> None:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.record_usage(key_id, db_session=session)
        from app.db.tables import ApiKeyUsageTable
        now = datetime.now(timezone.utc)
        window_start = now.replace(second=0, microsecond=0)
        result = await db_session.execute(
            select(ApiKeyUsageTable).where(
                and_(
                    ApiKeyUsageTable.key_id == key_id,
                    ApiKeyUsageTable.window_start == window_start,
                )
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            row = ApiKeyUsageTable(
                id=uuid4().hex,
                key_id=key_id,
                window_start=window_start,
                request_count=1,
                created_at=now,
            )
            db_session.add(row)
        else:
            row.request_count += 1
        await db_session.commit()


api_key_manager = ApiKeyManager()
