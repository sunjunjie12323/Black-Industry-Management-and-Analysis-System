from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from loguru import logger
from sqlalchemy import select

from app.db.tables import TenantTable


class TenantManager:
    def __init__(self):
        self._cache: Dict[str, Dict] = {}

    async def get_tenant(self, tenant_id: str, db_session=None) -> Optional[Dict]:
        if tenant_id in self._cache:
            return self._cache[tenant_id]
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.get_tenant(tenant_id, db_session=session)
        try:
            result = await db_session.execute(
                select(TenantTable).where(TenantTable.id == tenant_id, TenantTable.is_deleted == False)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None
            data = {
                "id": row.id,
                "name": row.name,
                "plan": row.plan,
                "is_active": not row.is_deleted,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            self._cache[tenant_id] = data
            return data
        except Exception as exc:
            logger.warning(f"TenantManager.get_tenant failed: {exc}")
            return None

    async def list_tenants(self, db_session=None) -> List[Dict]:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.list_tenants(db_session=session)
        try:
            result = await db_session.execute(
                select(TenantTable).where(TenantTable.is_deleted == False)
            )
            rows = result.scalars().all()
            return [
                {
                    "id": r.id,
                    "name": r.name,
                    "plan": r.plan,
                    "is_active": not r.is_deleted,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ]
        except Exception as exc:
            logger.warning(f"TenantManager.list_tenants failed: {exc}")
            return []

    async def create_tenant(self, name: str, plan: str = "free", db_session=None) -> Dict:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.create_tenant(name, plan, db_session=session)
        tenant_id = uuid4().hex
        try:
            row = TenantTable(
                id=tenant_id,
                name=name,
                plan=plan,
                is_deleted=False,
                created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
            db_session.add(row)
            await db_session.commit()
            data = {"id": tenant_id, "name": name, "plan": plan, "is_active": True}
            self._cache[tenant_id] = data
            return data
        except Exception as exc:
            logger.warning(f"TenantManager.create_tenant failed: {exc}")
            return {"id": tenant_id, "name": name, "plan": plan, "is_active": True}

    async def update_tenant(self, tenant_id: str, db_session=None, **kwargs) -> bool:
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.update_tenant(tenant_id, db_session=session, **kwargs)
        try:
            result = await db_session.execute(
                select(TenantTable).where(TenantTable.id == tenant_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return False
            for k, v in kwargs.items():
                if hasattr(row, k):
                    setattr(row, k, v)
            await db_session.commit()
            self._cache.pop(tenant_id, None)
            return True
        except Exception as exc:
            logger.warning(f"TenantManager.update_tenant failed: {exc}")
            return False

    async def delete_tenant(self, tenant_id: str, db_session=None) -> bool:
        return await self.update_tenant(tenant_id, db_session=db_session, is_deleted=True)
