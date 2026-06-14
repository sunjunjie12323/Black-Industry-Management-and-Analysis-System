import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.tables import (
    AnalyzedIntelligenceTable,
    CleanedIntelligenceTable,
    EntityTable,
    PIRTable,
    PIRTaskTable,
    RawIntelligenceTable,
    RelationTable,
    ReportTable,
)
from app.models.entity import Entity, EntityType, Relation, RelationType
from app.models.intelligence import (
    AnalyzedIntelligence,
    CleanedIntelligence,
    IntelligenceSource,
    IntelligenceStatus,
    RawIntelligence,
    ThreatLevel,
)
from app.models.pir import PIR, PIRPriority, PIRStatus, PIRTask, PIRTaskStatus
from app.models.report import Report, ReportStatus


def _json_dumps(obj: Any) -> str:
    if obj is None:
        return "[]"
    return json.dumps(obj, ensure_ascii=False, default=str)


def _json_loads(raw: str | None, default: Any = None) -> Any:
    if raw is None:
        return default if default is not None else []
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else []


class IntelligenceCRUD:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_raw(self, data: RawIntelligence) -> RawIntelligence:
        if data.content:
            dup_stmt = select(RawIntelligenceTable).where(
                RawIntelligenceTable.content == data.content
            ).limit(1)
            dup_result = await self.session.execute(dup_stmt)
            if dup_result.scalar_one_or_none() is not None:
                return None

        row = RawIntelligenceTable(
            id=data.id,
            source=data.source.value,
            source_url=data.source_url,
            content=data.content,
            raw_content=data.raw_content,
            collected_at=data.collected_at,
            status=IntelligenceStatus.RAW.value,
            metadata_json=_json_dumps(data.metadata),
        )
        self.session.add(row)
        await self.session.flush()
        await self.session.refresh(row)
        return self._raw_row_to_model(row)

    async def get_raw(self, raw_id: str) -> Optional[RawIntelligence]:
        stmt = select(RawIntelligenceTable).where(RawIntelligenceTable.id == raw_id)
        result = await self.session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return self._raw_row_to_model(row)

    async def list_raw(
        self,
        source: Optional[IntelligenceSource] = None,
        status: Optional[IntelligenceStatus] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[List[RawIntelligence], int]:
        stmt = select(RawIntelligenceTable)
        count_stmt = select(func.count()).select_from(RawIntelligenceTable)

        if source is not None:
            stmt = stmt.where(RawIntelligenceTable.source == source.value)
            count_stmt = count_stmt.where(RawIntelligenceTable.source == source.value)
        if status is not None:
            stmt = stmt.where(RawIntelligenceTable.status == status.value)
            count_stmt = count_stmt.where(RawIntelligenceTable.status == status.value)

        total_result = await self.session.execute(count_stmt)
        total = total_result.scalar() or 0

        stmt = stmt.order_by(RawIntelligenceTable.collected_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [self._raw_row_to_model(r) for r in rows], total

    async def update_status(self, raw_id: str, status: IntelligenceStatus) -> Optional[RawIntelligence]:
        stmt = (
            update(RawIntelligenceTable)
            .where(RawIntelligenceTable.id == raw_id)
            .values(status=status.value)
        )
        await self.session.execute(stmt)
        await self.session.flush()
        return await self.get_raw(raw_id)

    async def delete_raw(self, raw_id: str) -> bool:
        stmt = delete(RawIntelligenceTable).where(RawIntelligenceTable.id == raw_id)
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0

    async def create_cleaned(self, data: CleanedIntelligence) -> CleanedIntelligence:
        row = CleanedIntelligenceTable(
            id=data.id,
            raw_id=data.raw_id,
            content=data.content,
            decoded_content=data.decoded_content,
            blacktalk_terms_json=_json_dumps(data.blacktalk_terms),
            entities_json=_json_dumps(data.entities),
            threat_level=data.threat_level.value,
            cleaned_at=data.cleaned_at,
        )
        self.session.add(row)
        await self.session.execute(
            update(RawIntelligenceTable)
            .where(RawIntelligenceTable.id == data.raw_id)
            .values(status=IntelligenceStatus.CLEANED.value)
        )
        await self.session.flush()
        await self.session.refresh(row)
        return self._cleaned_row_to_model(row)

    async def get_cleaned(self, cleaned_id: str) -> Optional[CleanedIntelligence]:
        stmt = select(CleanedIntelligenceTable).where(CleanedIntelligenceTable.id == cleaned_id)
        result = await self.session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return self._cleaned_row_to_model(row)

    async def list_cleaned(
        self,
        threat_level: Optional[ThreatLevel] = None,
        raw_id: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[List[CleanedIntelligence], int]:
        stmt = select(CleanedIntelligenceTable)
        count_stmt = select(func.count()).select_from(CleanedIntelligenceTable)

        if threat_level is not None:
            stmt = stmt.where(CleanedIntelligenceTable.threat_level == threat_level.value)
            count_stmt = count_stmt.where(CleanedIntelligenceTable.threat_level == threat_level.value)
        if raw_id is not None:
            stmt = stmt.where(CleanedIntelligenceTable.raw_id == raw_id)
            count_stmt = count_stmt.where(CleanedIntelligenceTable.raw_id == raw_id)

        total_result = await self.session.execute(count_stmt)
        total = total_result.scalar() or 0

        stmt = stmt.order_by(CleanedIntelligenceTable.cleaned_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [self._cleaned_row_to_model(r) for r in rows], total

    async def create_analyzed(self, data: AnalyzedIntelligence) -> AnalyzedIntelligence:
        row = AnalyzedIntelligenceTable(
            id=data.id,
            cleaned_id=data.cleaned_id,
            threat_level=data.threat_level.value,
            threat_categories_json=_json_dumps(data.threat_categories),
            attack_patterns_json=_json_dumps(data.attack_patterns),
            technique_chain_json=_json_dumps(data.technique_chain),
            confidence_score=data.confidence_score,
            analysis_summary=data.analysis_summary,
            evidence_refs_json=_json_dumps(data.evidence_refs),
            analyzed_at=data.analyzed_at,
        )
        self.session.add(row)
        cleaned_row = await self.session.execute(
            select(CleanedIntelligenceTable).where(CleanedIntelligenceTable.id == data.cleaned_id)
        )
        cleaned = cleaned_row.scalar_one_or_none()
        if cleaned is not None:
            await self.session.execute(
                update(RawIntelligenceTable)
                .where(RawIntelligenceTable.id == cleaned.raw_id)
                .values(status=IntelligenceStatus.ANALYZED.value)
            )
        await self.session.flush()
        await self.session.refresh(row)
        return self._analyzed_row_to_model(row)

    async def get_analyzed(self, analyzed_id: str) -> Optional[AnalyzedIntelligence]:
        stmt = select(AnalyzedIntelligenceTable).where(AnalyzedIntelligenceTable.id == analyzed_id)
        result = await self.session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return self._analyzed_row_to_model(row)

    async def list_analyzed(
        self,
        threat_level: Optional[ThreatLevel] = None,
        cleaned_id: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[List[AnalyzedIntelligence], int]:
        stmt = select(AnalyzedIntelligenceTable)
        count_stmt = select(func.count()).select_from(AnalyzedIntelligenceTable)

        if threat_level is not None:
            stmt = stmt.where(AnalyzedIntelligenceTable.threat_level == threat_level.value)
            count_stmt = count_stmt.where(AnalyzedIntelligenceTable.threat_level == threat_level.value)
        if cleaned_id is not None:
            stmt = stmt.where(AnalyzedIntelligenceTable.cleaned_id == cleaned_id)
            count_stmt = count_stmt.where(AnalyzedIntelligenceTable.cleaned_id == cleaned_id)

        total_result = await self.session.execute(count_stmt)
        total = total_result.scalar() or 0

        stmt = stmt.order_by(AnalyzedIntelligenceTable.analyzed_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [self._analyzed_row_to_model(r) for r in rows], total

    def _raw_row_to_model(self, row: RawIntelligenceTable) -> RawIntelligence:
        return RawIntelligence(
            id=row.id,
            source=IntelligenceSource(row.source),
            source_url=row.source_url,
            content=row.content,
            raw_content=row.raw_content,
            collected_at=row.collected_at,
            metadata=_json_loads(row.metadata_json, {}),
            status=IntelligenceStatus(row.status) if row.status else IntelligenceStatus.RAW,
        )

    def _cleaned_row_to_model(self, row: CleanedIntelligenceTable) -> CleanedIntelligence:
        return CleanedIntelligence(
            id=row.id,
            raw_id=row.raw_id,
            content=row.content,
            decoded_content=row.decoded_content,
            blacktalk_terms=_json_loads(row.blacktalk_terms_json, {}),
            entities=_json_loads(row.entities_json, []),
            threat_level=ThreatLevel(row.threat_level),
            cleaned_at=row.cleaned_at,
        )

    def _analyzed_row_to_model(self, row: AnalyzedIntelligenceTable) -> AnalyzedIntelligence:
        return AnalyzedIntelligence(
            id=row.id,
            cleaned_id=row.cleaned_id,
            threat_level=ThreatLevel(row.threat_level),
            threat_categories=_json_loads(row.threat_categories_json, []),
            attack_patterns=_json_loads(row.attack_patterns_json, []),
            technique_chain=_json_loads(row.technique_chain_json, []),
            confidence_score=row.confidence_score,
            analysis_summary=row.analysis_summary or "",
            evidence_refs=_json_loads(row.evidence_refs_json, []),
            analyzed_at=row.analyzed_at,
        )


class EntityCRUD:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_entity(self, data: Entity) -> Entity:
        if data.value:
            dup_stmt = select(EntityTable).where(
                EntityTable.value == data.value,
                EntityTable.type == data.type.value,
            ).limit(1)
            dup_result = await self.session.execute(dup_stmt)
            existing = dup_result.scalar_one_or_none()
            if existing is not None:
                return self._entity_row_to_model(existing)

        row = EntityTable(
            id=data.id,
            type=data.type.value,
            value=data.value,
            context=data.context,
            source_ids_json=_json_dumps(data.source_ids),
            confidence=data.confidence,
            first_seen=data.first_seen,
            last_seen=data.last_seen,
            metadata_json=_json_dumps(data.metadata),
        )
        self.session.add(row)
        await self.session.flush()
        await self.session.refresh(row)
        return self._entity_row_to_model(row)

    async def get_entity(self, entity_id: str) -> Optional[Entity]:
        stmt = select(EntityTable).where(EntityTable.id == entity_id)
        result = await self.session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return self._entity_row_to_model(row)

    async def list_entities(
        self,
        entity_type: Optional[EntityType] = None,
        min_confidence: Optional[float] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[List[Entity], int]:
        stmt = select(EntityTable)
        count_stmt = select(func.count()).select_from(EntityTable)

        if entity_type is not None:
            stmt = stmt.where(EntityTable.type == entity_type.value)
            count_stmt = count_stmt.where(EntityTable.type == entity_type.value)
        if min_confidence is not None:
            stmt = stmt.where(EntityTable.confidence >= min_confidence)
            count_stmt = count_stmt.where(EntityTable.confidence >= min_confidence)

        total_result = await self.session.execute(count_stmt)
        total = total_result.scalar() or 0

        stmt = stmt.order_by(EntityTable.last_seen.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [self._entity_row_to_model(r) for r in rows], total

    async def search_entities(
        self,
        query: str,
        entity_type: Optional[EntityType] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[List[Entity], int]:
        safe_query = query.replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{safe_query}%"
        stmt = select(EntityTable).where(EntityTable.value.ilike(pattern))
        count_stmt = select(func.count()).select_from(EntityTable).where(
            EntityTable.value.ilike(pattern)
        )

        if entity_type is not None:
            stmt = stmt.where(EntityTable.type == entity_type.value)
            count_stmt = count_stmt.where(EntityTable.type == entity_type.value)

        total_result = await self.session.execute(count_stmt)
        total = total_result.scalar() or 0

        stmt = stmt.order_by(EntityTable.last_seen.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [self._entity_row_to_model(r) for r in rows], total

    async def update_entity(self, entity_id: str, **kwargs: Any) -> Optional[Entity]:
        values: Dict[str, Any] = {}
        field_map = {
            "type": ("type", lambda v: v.value if isinstance(v, EntityType) else v),
            "value": ("value", lambda v: v),
            "context": ("context", lambda v: v),
            "source_ids": ("source_ids_json", lambda v: _json_dumps(v)),
            "confidence": ("confidence", lambda v: v),
            "last_seen": ("last_seen", lambda v: v),
            "metadata": ("metadata_json", lambda v: _json_dumps(v)),
        }
        for key, val in kwargs.items():
            if key in field_map:
                col_name, transform = field_map[key]
                values[col_name] = transform(val)

        if not values:
            return await self.get_entity(entity_id)

        values["last_seen"] = datetime.now(timezone.utc)
        stmt = update(EntityTable).where(EntityTable.id == entity_id).values(**values)
        await self.session.execute(stmt)
        await self.session.flush()
        return await self.get_entity(entity_id)

    async def delete_entity(self, entity_id: str) -> bool:
        stmt = delete(EntityTable).where(EntityTable.id == entity_id)
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0

    async def create_relation(self, data: Relation) -> Relation:
        row = RelationTable(
            id=data.id,
            source_entity_id=data.source_entity_id,
            target_entity_id=data.target_entity_id,
            type=data.type.value,
            confidence=data.confidence,
            evidence=data.evidence,
            first_seen=data.first_seen,
            last_seen=data.last_seen,
        )
        self.session.add(row)
        await self.session.flush()
        await self.session.refresh(row)
        return self._relation_row_to_model(row)

    async def get_relations_for_entity(self, entity_id: str) -> List[Relation]:
        stmt = select(RelationTable).where(
            (RelationTable.source_entity_id == entity_id)
            | (RelationTable.target_entity_id == entity_id)
        )
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [self._relation_row_to_model(r) for r in rows]

    async def delete_relation(self, relation_id: str) -> bool:
        stmt = delete(RelationTable).where(RelationTable.id == relation_id)
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0

    def _entity_row_to_model(self, row: EntityTable) -> Entity:
        return Entity(
            id=row.id,
            type=EntityType(row.type),
            value=row.value,
            context=row.context,
            source_ids=_json_loads(row.source_ids_json, []),
            confidence=row.confidence,
            first_seen=row.first_seen,
            last_seen=row.last_seen,
            metadata=_json_loads(row.metadata_json, {}),
        )

    def _relation_row_to_model(self, row: RelationTable) -> Relation:
        return Relation(
            id=row.id,
            source_entity_id=row.source_entity_id,
            target_entity_id=row.target_entity_id,
            type=RelationType(row.type),
            confidence=row.confidence,
            evidence=row.evidence,
            first_seen=row.first_seen,
            last_seen=row.last_seen,
        )


class PIRCRUD:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_pir(self, data: PIR) -> PIR:
        row = PIRTable(
            id=data.id,
            title=data.title,
            description=data.description,
            priority=data.priority.value,
            status=data.status.value,
            keywords_json=_json_dumps(data.keywords),
            target_sources_json=_json_dumps([s.value for s in data.target_sources]),
            created_at=data.created_at,
            updated_at=data.updated_at,
            fulfilled_at=data.fulfilled_at,
            results_summary=data.results_summary,
        )
        self.session.add(row)
        await self.session.flush()
        await self.session.refresh(row)
        return self._pir_row_to_model(row)

    async def get_pir(self, pir_id: str) -> Optional[PIR]:
        stmt = select(PIRTable).where(PIRTable.id == pir_id)
        result = await self.session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return self._pir_row_to_model(row)

    async def list_pirs(
        self,
        status: Optional[PIRStatus] = None,
        priority: Optional[PIRPriority] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[List[PIR], int]:
        stmt = select(PIRTable)
        count_stmt = select(func.count()).select_from(PIRTable)

        if status is not None:
            stmt = stmt.where(PIRTable.status == status.value)
            count_stmt = count_stmt.where(PIRTable.status == status.value)
        if priority is not None:
            stmt = stmt.where(PIRTable.priority == priority.value)
            count_stmt = count_stmt.where(PIRTable.priority == priority.value)

        total_result = await self.session.execute(count_stmt)
        total = total_result.scalar() or 0

        stmt = stmt.order_by(PIRTable.created_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [self._pir_row_to_model(r) for r in rows], total

    async def update_pir(self, pir_id: str, **kwargs: Any) -> Optional[PIR]:
        values: Dict[str, Any] = {}
        field_map = {
            "title": ("title", lambda v: v),
            "description": ("description", lambda v: v),
            "priority": ("priority", lambda v: v.value if isinstance(v, PIRPriority) else v),
            "status": ("status", lambda v: v.value if isinstance(v, PIRStatus) else v),
            "keywords": ("keywords_json", lambda v: _json_dumps(v)),
            "target_sources": (
                "target_sources_json",
                lambda v: _json_dumps([s.value if isinstance(s, IntelligenceSource) else s for s in v]),
            ),
            "results_summary": ("results_summary", lambda v: v),
            "fulfilled_at": ("fulfilled_at", lambda v: v),
        }
        for key, val in kwargs.items():
            if key in field_map:
                col_name, transform = field_map[key]
                values[col_name] = transform(val)

        if not values:
            return await self.get_pir(pir_id)

        values["updated_at"] = datetime.now(timezone.utc)
        stmt = update(PIRTable).where(PIRTable.id == pir_id).values(**values)
        await self.session.execute(stmt)
        await self.session.flush()
        return await self.get_pir(pir_id)

    async def delete_pir(self, pir_id: str) -> bool:
        stmt = delete(PIRTable).where(PIRTable.id == pir_id)
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0

    async def create_pir_task(self, data: PIRTask) -> PIRTask:
        row = PIRTaskTable(
            id=data.id,
            pir_id=data.pir_id,
            agent_type=data.agent_type,
            task_description=data.task_description,
            status=data.status.value,
            result_json=_json_dumps(data.result) if data.result else None,
            created_at=data.created_at,
            completed_at=data.completed_at,
        )
        self.session.add(row)
        await self.session.flush()
        await self.session.refresh(row)
        return self._pir_task_row_to_model(row)

    async def list_pir_tasks(self, pir_id: str) -> List[PIRTask]:
        stmt = select(PIRTaskTable).where(PIRTaskTable.pir_id == pir_id).order_by(PIRTaskTable.created_at.desc())
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [self._pir_task_row_to_model(r) for r in rows]

    async def update_pir_task(self, task_id: str, **kwargs: Any) -> Optional[PIRTask]:
        values: Dict[str, Any] = {}
        field_map = {
            "status": ("status", lambda v: v.value if isinstance(v, PIRTaskStatus) else v),
            "result": ("result_json", lambda v: _json_dumps(v)),
            "completed_at": ("completed_at", lambda v: v),
        }
        for key, val in kwargs.items():
            if key in field_map:
                col_name, transform = field_map[key]
                values[col_name] = transform(val)

        if not values:
            stmt = select(PIRTaskTable).where(PIRTaskTable.id == task_id)
            result = await self.session.execute(stmt)
            row = result.scalar_one_or_none()
            return self._pir_task_row_to_model(row) if row else None

        stmt = update(PIRTaskTable).where(PIRTaskTable.id == task_id).values(**values)
        await self.session.execute(stmt)
        await self.session.flush()
        stmt = select(PIRTaskTable).where(PIRTaskTable.id == task_id)
        result = await self.session.execute(stmt)
        row = result.scalar_one_or_none()
        return self._pir_task_row_to_model(row) if row else None

    def _pir_row_to_model(self, row: PIRTable) -> PIR:
        sources_raw = _json_loads(row.target_sources_json, [])
        target_sources = []
        for s in sources_raw:
            try:
                target_sources.append(IntelligenceSource(s))
            except ValueError:
                pass
        return PIR(
            id=row.id,
            title=row.title,
            description=row.description or "",
            priority=PIRPriority(row.priority),
            status=PIRStatus(row.status),
            keywords=_json_loads(row.keywords_json, []),
            target_sources=target_sources,
            created_at=row.created_at,
            updated_at=row.updated_at,
            fulfilled_at=row.fulfilled_at,
            results_summary=row.results_summary,
        )

    def _pir_task_row_to_model(self, row: PIRTaskTable) -> PIRTask:
        return PIRTask(
            id=row.id,
            pir_id=row.pir_id,
            agent_type=row.agent_type,
            task_description=row.task_description or "",
            status=PIRTaskStatus(row.status),
            result=_json_loads(row.result_json, {}),
            created_at=row.created_at,
            completed_at=row.completed_at,
        )


class ReportCRUD:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_report(self, data: Report) -> Report:
        row = ReportTable(
            id=data.id,
            title=data.title,
            pir_id=data.pir_id,
            status=data.status.value,
            summary=data.summary,
            key_findings_json=_json_dumps(data.key_findings),
            threat_actors_json=_json_dumps(data.threat_actors),
            iocs_json=_json_dumps(data.iocs),
            attack_chains_json=_json_dumps(data.attack_chains),
            recommendations_json=_json_dumps(data.recommendations),
            evidence_chain_json=_json_dumps(data.evidence_chain),
            confidence_score=data.confidence_score,
            author=data.author,
            created_at=data.created_at,
            updated_at=data.updated_at,
            published_at=data.published_at,
        )
        self.session.add(row)
        await self.session.flush()
        await self.session.refresh(row)
        return self._report_row_to_model(row)

    async def get_report(self, report_id: str) -> Optional[Report]:
        stmt = select(ReportTable).where(ReportTable.id == report_id)
        result = await self.session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return self._report_row_to_model(row)

    async def list_reports(
        self,
        status: Optional[ReportStatus] = None,
        pir_id: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[List[Report], int]:
        stmt = select(ReportTable)
        count_stmt = select(func.count()).select_from(ReportTable)

        if status is not None:
            stmt = stmt.where(ReportTable.status == status.value)
            count_stmt = count_stmt.where(ReportTable.status == status.value)
        if pir_id is not None:
            stmt = stmt.where(ReportTable.pir_id == pir_id)
            count_stmt = count_stmt.where(ReportTable.pir_id == pir_id)

        total_result = await self.session.execute(count_stmt)
        total = total_result.scalar() or 0

        stmt = stmt.order_by(ReportTable.created_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [self._report_row_to_model(r) for r in rows], total

    async def update_report(self, report_id: str, **kwargs: Any) -> Optional[Report]:
        values: Dict[str, Any] = {}
        field_map = {
            "title": ("title", lambda v: v),
            "pir_id": ("pir_id", lambda v: v),
            "status": ("status", lambda v: v.value if isinstance(v, ReportStatus) else v),
            "summary": ("summary", lambda v: v),
            "key_findings": ("key_findings_json", lambda v: _json_dumps(v)),
            "threat_actors": ("threat_actors_json", lambda v: _json_dumps(v)),
            "iocs": ("iocs_json", lambda v: _json_dumps(v)),
            "attack_chains": ("attack_chains_json", lambda v: _json_dumps(v)),
            "recommendations": ("recommendations_json", lambda v: _json_dumps(v)),
            "evidence_chain": ("evidence_chain_json", lambda v: _json_dumps(v)),
            "confidence_score": ("confidence_score", lambda v: v),
            "author": ("author", lambda v: v),
            "published_at": ("published_at", lambda v: v),
        }
        for key, val in kwargs.items():
            if key in field_map:
                col_name, transform = field_map[key]
                values[col_name] = transform(val)

        if not values:
            return await self.get_report(report_id)

        values["updated_at"] = datetime.now(timezone.utc)
        if kwargs.get("status") == ReportStatus.PUBLISHED and "published_at" not in kwargs:
            values["published_at"] = datetime.now(timezone.utc)

        stmt = update(ReportTable).where(ReportTable.id == report_id).values(**values)
        await self.session.execute(stmt)
        await self.session.flush()
        return await self.get_report(report_id)

    async def delete_report(self, report_id: str) -> bool:
        stmt = delete(ReportTable).where(ReportTable.id == report_id)
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0

    def _report_row_to_model(self, row: ReportTable) -> Report:
        return Report(
            id=row.id,
            title=row.title,
            pir_id=row.pir_id,
            status=ReportStatus(row.status),
            summary=row.summary or "",
            key_findings=_json_loads(row.key_findings_json, []),
            threat_actors=_json_loads(row.threat_actors_json, []),
            iocs=_json_loads(row.iocs_json, []),
            attack_chains=_json_loads(row.attack_chains_json, []),
            recommendations=_json_loads(row.recommendations_json, []),
            evidence_chain=_json_loads(row.evidence_chain_json, []),
            confidence_score=row.confidence_score,
            author=row.author or "system",
            created_at=row.created_at,
            updated_at=row.updated_at,
            published_at=row.published_at,
        )
