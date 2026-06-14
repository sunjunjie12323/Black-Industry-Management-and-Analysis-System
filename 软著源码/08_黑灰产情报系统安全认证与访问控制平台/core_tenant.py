import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from loguru import logger
from sqlalchemy import select, update, and_


class TenantPlan(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


PLAN_QUOTAS = {
    TenantPlan.FREE: {
        "intelligence_per_day": 100,
        "api_calls_per_day": 1000,
        "max_users": 1,
    },
    TenantPlan.PRO: {
        "intelligence_per_day": 10000,
        "api_calls_per_day": 50000,
        "max_users": 10,
    },
    TenantPlan.ENTERPRISE: {
        "intelligence_per_day": -1,
        "api_calls_per_day": -1,
        "max_users": -1,
    },
}


@dataclass
class Tenant:
    tenant_id: str
    name: str
    plan: TenantPlan = TenantPlan.FREE
    settings: Dict[str, Any] = field(default_factory=dict)
    quotas: Dict[str, int] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_deleted: bool = False


class TenantManager:
    async def create_tenant(self, name: str, plan: TenantPlan = TenantPlan.FREE, db_session=None) -> Tenant:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.create_tenant(name, plan, db_session=session)
        from app.db.tables import TenantTable, TenantQuotaTable
        tenant_id = uuid4().hex
        now = datetime.now(timezone.utc)
        quotas = PLAN_QUOTAS.get(plan, PLAN_QUOTAS[TenantPlan.FREE]).copy()
        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            plan=plan,
            settings={},
            quotas=quotas,
            created_at=now,
        )
        db_tenant = TenantTable(
            id=tenant_id,
            name=name,
            plan=plan.value,
            settings_json=json.dumps({}, ensure_ascii=False),
            is_deleted=False,
            created_at=now,
            updated_at=now,
        )
        db_session.add(db_tenant)
        await db_session.flush()
        db_quota = TenantQuotaTable(
            id=uuid4().hex,
            tenant_id=tenant_id,
            intelligence_per_day=quotas["intelligence_per_day"],
            api_calls_per_day=quotas["api_calls_per_day"],
            max_users=quotas["max_users"],
            created_at=now,
            updated_at=now,
        )
        db_session.add(db_quota)
        await db_session.commit()
        logger.info(f"Tenant created: {name} (plan={plan.value})")
        return tenant

    async def get_tenant(self, tenant_id: str, db_session=None) -> Optional[Tenant]:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.get_tenant(tenant_id, db_session=session)
        from app.db.tables import TenantTable, TenantQuotaTable
        result = await db_session.execute(
            select(TenantTable).where(
                and_(TenantTable.id == tenant_id, TenantTable.is_deleted == False)
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        quota_result = await db_session.execute(
            select(TenantQuotaTable).where(TenantQuotaTable.tenant_id == tenant_id)
        )
        quota_row = quota_result.scalar_one_or_none()
        quotas = {}
        if quota_row:
            quotas = {
                "intelligence_per_day": quota_row.intelligence_per_day,
                "api_calls_per_day": quota_row.api_calls_per_day,
                "max_users": quota_row.max_users,
            }
        settings = {}
        if row.settings_json:
            try:
                settings = json.loads(row.settings_json)
            except (json.JSONDecodeError, TypeError):
                pass
        return Tenant(
            tenant_id=row.id,
            name=row.name,
            plan=TenantPlan(row.plan),
            settings=settings,
            quotas=quotas,
            created_at=row.created_at,
            is_deleted=row.is_deleted,
        )

    async def update_tenant(self, tenant_id: str, db_session=None, **kwargs) -> bool:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.update_tenant(tenant_id, db_session=session, **kwargs)
        from app.db.tables import TenantTable, TenantQuotaTable
        result = await db_session.execute(
            select(TenantTable).where(
                and_(TenantTable.id == tenant_id, TenantTable.is_deleted == False)
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        if "name" in kwargs:
            row.name = kwargs["name"]
        if "plan" in kwargs:
            row.plan = TenantPlan(kwargs["plan"]).value
            new_quotas = PLAN_QUOTAS.get(TenantPlan(kwargs["plan"]), {})
            quota_result = await db_session.execute(
                select(TenantQuotaTable).where(TenantQuotaTable.tenant_id == tenant_id)
            )
            quota_row = quota_result.scalar_one_or_none()
            if quota_row and new_quotas:
                quota_row.intelligence_per_day = new_quotas.get("intelligence_per_day", -1)
                quota_row.api_calls_per_day = new_quotas.get("api_calls_per_day", -1)
                quota_row.max_users = new_quotas.get("max_users", -1)
                quota_row.updated_at = datetime.now(timezone.utc)
        if "settings" in kwargs:
            row.settings_json = json.dumps(kwargs["settings"], ensure_ascii=False)
        row.updated_at = datetime.now(timezone.utc)
        await db_session.commit()
        logger.info(f"Tenant updated: {tenant_id}")
        return True

    async def delete_tenant(self, tenant_id: str, db_session=None) -> bool:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.delete_tenant(tenant_id, db_session=session)
        from app.db.tables import TenantTable
        result = await db_session.execute(
            select(TenantTable).where(TenantTable.id == tenant_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        row.is_deleted = True
        row.updated_at = datetime.now(timezone.utc)
        await db_session.commit()
        logger.info(f"Tenant soft-deleted: {tenant_id}")
        return True

    async def check_quota(self, tenant_id: str, resource: str, db_session=None) -> bool:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.check_quota(tenant_id, resource, db_session=session)
        from app.db.tables import TenantQuotaTable, TenantUsageTable
        quota_result = await db_session.execute(
            select(TenantQuotaTable).where(TenantQuotaTable.tenant_id == tenant_id)
        )
        quota_row = quota_result.scalar_one_or_none()
        if quota_row is None:
            return True
        quota_value = getattr(quota_row, resource, -1)
        if quota_value == -1:
            return True
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        usage_result = await db_session.execute(
            select(TenantUsageTable).where(
                and_(
                    TenantUsageTable.tenant_id == tenant_id,
                    TenantUsageTable.date == today,
                )
            )
        )
        usage_row = usage_result.scalar_one_or_none()
        used = 0
        if usage_row:
            used = getattr(usage_row, resource, 0) or 0
        return used < quota_value

    async def record_usage(self, tenant_id: str, resource: str, amount: int = 1, db_session=None) -> None:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.record_usage(tenant_id, resource, amount, db_session=session)
        from app.db.tables import TenantUsageTable
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        result = await db_session.execute(
            select(TenantUsageTable).where(
                and_(
                    TenantUsageTable.tenant_id == tenant_id,
                    TenantUsageTable.date == today,
                )
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            row = TenantUsageTable(
                id=uuid4().hex,
                tenant_id=tenant_id,
                date=today,
                intelligence_count=0,
                api_call_count=0,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db_session.add(row)
        current = getattr(row, resource, 0) or 0
        setattr(row, resource, current + amount)
        row.updated_at = datetime.now(timezone.utc)
        await db_session.commit()


class TenantIsolation:
    @staticmethod
    def get_tenant_filter(model_class, tenant_id: str):
        from sqlalchemy import and_
        if hasattr(model_class, "tenant_id"):
            return model_class.tenant_id == tenant_id
        return None

    @staticmethod
    def get_vector_collection_namespace(tenant_id: str) -> str:
        return f"tenant_{tenant_id}"

    @staticmethod
    def get_cache_key_prefix(tenant_id: str) -> str:
        return f"tenant:{tenant_id}:"

    @staticmethod
    def build_cache_key(tenant_id: str, key: str) -> str:
        return f"tenant:{tenant_id}:{key}"


tenant_manager = TenantManager()
tenant_isolation = TenantIsolation()
