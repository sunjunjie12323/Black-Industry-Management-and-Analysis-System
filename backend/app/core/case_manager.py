import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from loguru import logger
from sqlalchemy import select, and_, or_

from app.db.database import async_session_factory


class CaseStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CaseEventType(str, Enum):
    CREATED = "created"
    UPDATED = "updated"
    INTELLIGENCE_ADDED = "intelligence_added"
    ENTITY_LINKED = "entity_linked"
    COMMENT_ADDED = "comment_added"
    STATUS_CHANGED = "status_changed"
    ESCALATED = "escalated"
    RESOLVED = "resolved"


@dataclass
class CaseEvent:
    event_id: str
    case_id: str
    event_type: CaseEventType
    description: str
    operator: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Case:
    case_id: str
    title: str
    description: str
    status: CaseStatus = CaseStatus.OPEN
    severity: str = "medium"
    assignee: Optional[str] = None
    related_intelligence_ids: List[str] = field(default_factory=list)
    related_entity_ids: List[str] = field(default_factory=list)
    timeline: List[CaseEvent] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None


class CaseManager:
    async def create_case(self, title: str, description: str, severity: str = "medium") -> Case:
        from app.db.tables import CaseTable, CaseEventTable
        case_id = uuid4().hex
        now = datetime.now(timezone.utc)
        case = Case(
            case_id=case_id,
            title=title,
            description=description,
            severity=severity,
            created_at=now,
            updated_at=now,
        )
        async with async_session_factory() as session:
            db_case = CaseTable(
                id=case_id,
                title=title,
                description=description,
                status=CaseStatus.OPEN.value,
                severity=severity,
                created_at=now,
                updated_at=now,
            )
            session.add(db_case)
            event_id = uuid4().hex
            db_event = CaseEventTable(
                id=event_id,
                case_id=case_id,
                event_type=CaseEventType.CREATED.value,
                description=f"案件创建: {title}",
                operator="system",
                timestamp=now,
            )
            session.add(db_event)
            await session.commit()
        logger.info(f"Case created: {case_id} ({title})")
        return case

    async def get_case(self, case_id: str) -> Optional[Case]:
        from app.db.tables import CaseTable, CaseEventTable, CaseIntelligenceTable, CaseEntityTable
        async with async_session_factory() as session:
            result = await session.execute(
                select(CaseTable).where(CaseTable.id == case_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None
            events_result = await session.execute(
                select(CaseEventTable)
                .where(CaseEventTable.case_id == case_id)
                .order_by(CaseEventTable.timestamp)
            )
            events = []
            for e in events_result.scalars().all():
                events.append(CaseEvent(
                    event_id=e.id,
                    case_id=e.case_id,
                    event_type=CaseEventType(e.event_type),
                    description=e.description,
                    operator=e.operator,
                    timestamp=e.timestamp,
                ))
            intel_result = await session.execute(
                select(CaseIntelligenceTable).where(CaseIntelligenceTable.case_id == case_id)
            )
            intel_ids = [r.intelligence_id for r in intel_result.scalars().all()]
            entity_result = await session.execute(
                select(CaseEntityTable).where(CaseEntityTable.case_id == case_id)
            )
            entity_ids = [r.entity_id for r in entity_result.scalars().all()]
            return Case(
                case_id=row.id,
                title=row.title,
                description=row.description,
                status=CaseStatus(row.status),
                severity=row.severity,
                assignee=row.assignee,
                related_intelligence_ids=intel_ids,
                related_entity_ids=entity_ids,
                timeline=events,
                created_at=row.created_at,
                updated_at=row.updated_at,
                resolved_at=row.resolved_at,
            )

    async def update_case(self, case_id: str, **kwargs) -> bool:
        from app.db.tables import CaseTable
        async with async_session_factory() as session:
            result = await session.execute(
                select(CaseTable).where(CaseTable.id == case_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return False
            if "title" in kwargs:
                row.title = kwargs["title"]
            if "description" in kwargs:
                row.description = kwargs["description"]
            if "severity" in kwargs:
                row.severity = kwargs["severity"]
            if "assignee" in kwargs:
                row.assignee = kwargs["assignee"]
            row.updated_at = datetime.now(timezone.utc)
            await session.commit()
        await self._add_event(case_id, CaseEventType.UPDATED, f"案件更新: {list(kwargs.keys())}", "system")
        return True

    async def add_intelligence_to_case(self, case_id: str, intelligence_id: str) -> bool:
        from app.db.tables import CaseIntelligenceTable
        async with async_session_factory() as session:
            existing = await session.execute(
                select(CaseIntelligenceTable).where(
                    and_(
                        CaseIntelligenceTable.case_id == case_id,
                        CaseIntelligenceTable.intelligence_id == intelligence_id,
                    )
                )
            )
            if existing.scalar_one_or_none():
                return True
            link = CaseIntelligenceTable(
                id=uuid4().hex,
                case_id=case_id,
                intelligence_id=intelligence_id,
                created_at=datetime.now(timezone.utc),
            )
            session.add(link)
            await session.commit()
        await self._add_event(case_id, CaseEventType.INTELLIGENCE_ADDED, f"关联情报: {intelligence_id[:8]}...", "system")
        return True

    async def add_entity_to_case(self, case_id: str, entity_id: str) -> bool:
        from app.db.tables import CaseEntityTable
        async with async_session_factory() as session:
            existing = await session.execute(
                select(CaseEntityTable).where(
                    and_(
                        CaseEntityTable.case_id == case_id,
                        CaseEntityTable.entity_id == entity_id,
                    )
                )
            )
            if existing.scalar_one_or_none():
                return True
            link = CaseEntityTable(
                id=uuid4().hex,
                case_id=case_id,
                entity_id=entity_id,
                created_at=datetime.now(timezone.utc),
            )
            session.add(link)
            await session.commit()
        await self._add_event(case_id, CaseEventType.ENTITY_LINKED, f"关联实体: {entity_id[:8]}...", "system")
        return True

    async def add_comment(self, case_id: str, comment: str, operator: str = "system") -> None:
        await self._add_event(case_id, CaseEventType.COMMENT_ADDED, comment, operator)

    async def change_status(self, case_id: str, new_status: CaseStatus, operator: str, reason: str = "") -> bool:
        from app.db.tables import CaseTable
        async with async_session_factory() as session:
            result = await session.execute(
                select(CaseTable).where(CaseTable.id == case_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return False
            old_status = row.status
            row.status = new_status.value
            row.updated_at = datetime.now(timezone.utc)
            if new_status in (CaseStatus.RESOLVED, CaseStatus.CLOSED):
                row.resolved_at = datetime.now(timezone.utc)
            await session.commit()
        desc = f"状态变更: {old_status} → {new_status.value}"
        if reason:
            desc += f" (原因: {reason})"
        await self._add_event(case_id, CaseEventType.STATUS_CHANGED, desc, operator)
        return True

    async def escalate(self, case_id: str, to_assignee: str, reason: str) -> bool:
        from app.db.tables import CaseTable
        async with async_session_factory() as session:
            result = await session.execute(
                select(CaseTable).where(CaseTable.id == case_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return False
            row.status = CaseStatus.ESCALATED.value
            row.assignee = to_assignee
            row.updated_at = datetime.now(timezone.utc)
            await session.commit()
        await self._add_event(case_id, CaseEventType.ESCALATED, f"升级至 {to_assignee}: {reason}", "system")
        return True

    async def resolve(self, case_id: str, resolution: str, operator: str) -> bool:
        from app.db.tables import CaseTable
        now = datetime.now(timezone.utc)
        async with async_session_factory() as session:
            result = await session.execute(
                select(CaseTable).where(CaseTable.id == case_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return False
            row.status = CaseStatus.RESOLVED.value
            row.resolved_at = now
            row.updated_at = now
            await session.commit()
        await self._add_event(case_id, CaseEventType.RESOLVED, f"案件解决: {resolution}", operator)
        return True

    async def search_cases(self, query: str = "", filters: Optional[Dict[str, Any]] = None) -> List[Case]:
        from app.db.tables import CaseTable
        filters = filters or {}
        async with async_session_factory() as session:
            stmt = select(CaseTable)
            conditions = []
            if query:
                conditions.append(or_(
                    CaseTable.title.contains(query),
                    CaseTable.description.contains(query),
                ))
            if "status" in filters:
                conditions.append(CaseTable.status == filters["status"])
            if "severity" in filters:
                conditions.append(CaseTable.severity == filters["severity"])
            if "assignee" in filters:
                conditions.append(CaseTable.assignee == filters["assignee"])
            if conditions:
                stmt = stmt.where(and_(*conditions))
            stmt = stmt.order_by(CaseTable.created_at.desc()).limit(100)
            result = await session.execute(stmt)
            cases = []
            for row in result.scalars().all():
                cases.append(Case(
                    case_id=row.id,
                    title=row.title,
                    description=row.description,
                    status=CaseStatus(row.status),
                    severity=row.severity,
                    assignee=row.assignee,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                    resolved_at=row.resolved_at,
                ))
            return cases

    async def get_case_timeline(self, case_id: str) -> List[CaseEvent]:
        from app.db.tables import CaseEventTable
        async with async_session_factory() as session:
            result = await session.execute(
                select(CaseEventTable)
                .where(CaseEventTable.case_id == case_id)
                .order_by(CaseEventTable.timestamp)
            )
            events = []
            for row in result.scalars().all():
                events.append(CaseEvent(
                    event_id=row.id,
                    case_id=row.case_id,
                    event_type=CaseEventType(row.event_type),
                    description=row.description,
                    operator=row.operator,
                    timestamp=row.timestamp,
                ))
            return events

    async def _add_event(self, case_id: str, event_type: CaseEventType, description: str, operator: str) -> None:
        from app.db.tables import CaseEventTable
        async with async_session_factory() as session:
            event = CaseEventTable(
                id=uuid4().hex,
                case_id=case_id,
                event_type=event_type.value,
                description=description,
                operator=operator,
                timestamp=datetime.now(timezone.utc),
            )
            session.add(event)
            await session.commit()


case_manager = CaseManager()
