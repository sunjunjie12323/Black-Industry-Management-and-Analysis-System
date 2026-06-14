import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from loguru import logger
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.evidence_chain import EvidenceChain, Evidence
from app.core.llm import LLMService
from app.core.report_generator import ReportGenerator
from app.core.vector_store import VectorStore
from app.db.tables import PIRTable, PIRTaskTable
from app.models.intelligence import IntelligenceReport, IntelligenceSource
from app.models.pir import PIR, PIRPriority, PIRStatus, PIRTask, PIRTaskStatus


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


def _pir_row_to_model(row: PIRTable) -> PIR:
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


def _pir_task_row_to_model(row: PIRTaskTable) -> PIRTask:
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


class PIREngine:
    def __init__(
        self,
        llm: LLMService,
        vector_store: VectorStore,
        session_factory: async_sessionmaker,
    ):
        self.llm = llm
        self.vector_store = vector_store
        self.evidence_chain = EvidenceChain(llm, vector_store)
        self.report_generator = ReportGenerator(llm, vector_store)
        self._session_factory = session_factory

    async def create_pir(
        self,
        title: str,
        description: str,
        priority: str,
        keywords: List[str],
        target_sources: List[str],
    ) -> PIR:
        try:
            priority_enum = PIRPriority(priority)
        except ValueError:
            priority_enum = PIRPriority.MEDIUM
            logger.warning(f"Invalid priority '{priority}', defaulting to MEDIUM")

        source_enums: List[IntelligenceSource] = []
        for src in target_sources:
            try:
                source_enums.append(IntelligenceSource(src))
            except ValueError:
                logger.warning(f"Invalid source type '{src}', skipping")

        pir = PIR(
            title=title,
            description=description,
            priority=priority_enum,
            keywords=keywords,
            target_sources=source_enums,
        )

        async with self._session_factory() as session:
            row = PIRTable(
                id=pir.id,
                title=pir.title,
                description=pir.description,
                priority=pir.priority.value,
                status=pir.status.value,
                keywords_json=_json_dumps(pir.keywords),
                target_sources_json=_json_dumps([s.value for s in pir.target_sources]),
                created_at=pir.created_at,
                updated_at=pir.updated_at,
                fulfilled_at=pir.fulfilled_at,
                results_summary=pir.results_summary,
            )
            session.add(row)
            await session.commit()

        logger.info(f"Created PIR: {pir.id} - {title} (priority={priority})")
        return pir

    async def decompose_pir(self, pir: PIR) -> List[PIRTask]:
        system_prompt = (
            "你是一个黑灰产情报分析任务分解专家。根据给定的优先情报需求(PIR)，"
            "将其分解为具体的Agent任务。\n\n"
            "可用的Agent类型：\n"
            "- collector: 情报采集Agent，负责从各渠道搜索和收集情报\n"
            "- cleaner: 情报清洗Agent，负责解码黑话、提取实体、标准化数据\n"
            "- analyst: 情报分析Agent，负责识别威胁模式、评估威胁等级、分析攻击链\n"
            "- graph_builder: 图谱构建Agent，负责更新知识图谱、发现关联关系\n\n"
            "返回JSON数组，每个元素包含：\n"
            "- agent_type: agent类型（collector/cleaner/analyst/graph_builder之一）\n"
            "- task_description: 具体任务描述\n\n"
            "只返回JSON数组，不要其他内容。"
        )
        source_list = ", ".join(s.value for s in pir.target_sources) if pir.target_sources else "所有来源"
        keyword_list = ", ".join(pir.keywords) if pir.keywords else "无特定关键词"
        prompt = (
            f"PIR标题：{pir.title}\n"
            f"PIR描述：{pir.description}\n"
            f"优先级：{pir.priority.value}\n"
            f"关键词：{keyword_list}\n"
            f"目标来源：{source_list}\n\n"
            f"请将此PIR分解为具体的Agent任务。"
        )

        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.3,
            )
        except Exception as exc:
            logger.error(f"LLM decomposition failed for PIR {pir.id}: {exc}")
            result = self._fallback_decompose(pir)

        if not isinstance(result, list):
            if isinstance(result, dict):
                result = [result]
            else:
                result = self._fallback_decompose(pir)

        tasks: List[PIRTask] = []
        task_rows: List[PIRTaskTable] = []
        for item in result:
            agent_type = item.get("agent_type", "collector")
            task_desc = item.get("task_description", "")
            if not task_desc:
                continue
            valid_agents = {"collector", "cleaner", "analyst", "graph_builder"}
            if agent_type not in valid_agents:
                agent_type = "collector"
            task = PIRTask(
                pir_id=pir.id,
                agent_type=agent_type,
                task_description=task_desc,
            )
            tasks.append(task)
            task_rows.append(
                PIRTaskTable(
                    id=task.id,
                    pir_id=task.pir_id,
                    agent_type=task.agent_type,
                    task_description=task.task_description,
                    status=task.status.value,
                    created_at=task.created_at,
                    completed_at=task.completed_at,
                )
            )

        if not tasks:
            tasks = self._create_default_tasks(pir)
            for t in tasks:
                task_rows.append(
                    PIRTaskTable(
                        id=t.id,
                        pir_id=t.pir_id,
                        agent_type=t.agent_type,
                        task_description=t.task_description,
                        status=t.status.value,
                        created_at=t.created_at,
                        completed_at=t.completed_at,
                    )
                )

        async with self._session_factory() as session:
            session.add_all(task_rows)
            await session.commit()

        logger.info(f"Decomposed PIR {pir.id} into {len(tasks)} tasks")
        return tasks

    def _fallback_decompose(self, pir: PIR) -> List[dict]:
        return [
            {
                "agent_type": "collector",
                "task_description": f"搜索与「{pir.title}」相关的情报，关键词：{', '.join(pir.keywords[:5])}",
            },
            {
                "agent_type": "cleaner",
                "task_description": f"清洗采集到的情报，解码黑话，提取实体信息",
            },
            {
                "agent_type": "analyst",
                "task_description": f"分析清洗后的情报，识别威胁模式和攻击链",
            },
            {
                "agent_type": "graph_builder",
                "task_description": f"将分析结果更新到知识图谱，建立实体关联关系",
            },
        ]

    def _create_default_tasks(self, pir: PIR) -> List[PIRTask]:
        fallback = self._fallback_decompose(pir)
        tasks: List[PIRTask] = []
        for item in fallback:
            task = PIRTask(
                pir_id=pir.id,
                agent_type=item["agent_type"],
                task_description=item["task_description"],
            )
            tasks.append(task)
        return tasks

    async def evaluate_pir(self, pir_id: str) -> Dict:
        async with self._session_factory() as session:
            stmt = select(PIRTable).where(PIRTable.id == pir_id)
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            if not row:
                logger.warning(f"PIR {pir_id} not found")
                return {"error": f"PIR {pir_id} not found"}
            pir = _pir_row_to_model(row)

            task_stmt = select(PIRTaskTable).where(PIRTaskTable.pir_id == pir_id)
            task_result = await session.execute(task_stmt)
            task_rows = task_result.scalars().all()
            pir_tasks = [_pir_task_row_to_model(r) for r in task_rows]

        if not pir_tasks:
            return {
                "pir_id": pir_id,
                "title": pir.title,
                "status": pir.status.value,
                "fulfillment_percentage": 0.0,
                "total_tasks": 0,
                "completed_tasks": 0,
                "running_tasks": 0,
                "pending_tasks": 0,
                "failed_tasks": 0,
                "summary": "尚未分解任务",
            }

        total = len(pir_tasks)
        completed = sum(1 for t in pir_tasks if t.status == PIRTaskStatus.COMPLETED)
        running = sum(1 for t in pir_tasks if t.status == PIRTaskStatus.RUNNING)
        pending = sum(1 for t in pir_tasks if t.status == PIRTaskStatus.PENDING)
        failed = sum(1 for t in pir_tasks if t.status == PIRTaskStatus.FAILED)

        fulfillment_percentage = (completed / total * 100) if total > 0 else 0.0

        is_fulfilled = False
        summary = ""
        if fulfillment_percentage >= 80.0 and failed == 0:
            is_fulfilled = True
            summary = "PIR已基本完成，所有关键任务均已执行"
        elif fulfillment_percentage >= 50.0:
            summary = f"PIR执行中，已完成{completed}/{total}个任务"
        elif failed > completed:
            summary = f"PIR执行困难，{failed}个任务失败，仅{completed}个完成"
        else:
            summary = f"PIR执行初期，{pending}个任务待执行"

        if is_fulfilled and pir.status == PIRStatus.ACTIVE:
            async with self._session_factory() as session:
                now = datetime.now(timezone.utc)
                stmt = (
                    update(PIRTable)
                    .where(PIRTable.id == pir_id)
                    .values(
                        status=PIRStatus.FULFILLED.value,
                        fulfilled_at=now,
                        updated_at=now,
                        results_summary=summary,
                    )
                )
                await session.execute(stmt)
                await session.commit()
            pir.status = PIRStatus.FULFILLED
            pir.fulfilled_at = now
            pir.updated_at = now
            pir.results_summary = summary

        return {
            "pir_id": pir_id,
            "title": pir.title,
            "status": pir.status.value,
            "fulfillment_percentage": round(fulfillment_percentage, 1),
            "total_tasks": total,
            "completed_tasks": completed,
            "running_tasks": running,
            "pending_tasks": pending,
            "failed_tasks": failed,
            "summary": summary,
        }

    async def generate_pir_report(self, pir_id: str) -> IntelligenceReport:
        async with self._session_factory() as session:
            stmt = select(PIRTable).where(PIRTable.id == pir_id)
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            if not row:
                raise ValueError(f"PIR {pir_id} not found")
            pir = _pir_row_to_model(row)

            task_stmt = select(PIRTaskTable).where(PIRTaskTable.pir_id == pir_id)
            task_result = await session.execute(task_stmt)
            task_rows = task_result.scalars().all()
            pir_tasks = [_pir_task_row_to_model(r) for r in task_rows]

        task_results: List[Dict[str, Any]] = []
        for task in pir_tasks:
            if task.result:
                task_results.append(task.result)

        context_parts: List[str] = []
        for i, r in enumerate(task_results[:10]):
            context_parts.append(f"任务结果{i+1}: {str(r)[:500]}")
        keyword_list = ", ".join(pir.keywords) if pir.keywords else "无特定关键词"
        context_parts.append(f"PIR标题：{pir.title}")
        context_parts.append(f"PIR描述：{pir.description}")
        context_parts.append(f"关键词：{keyword_list}")
        context = "\n\n".join(context_parts) if context_parts else "暂无相关情报数据"

        report = await self.report_generator.generate_report(
            title=pir.title,
            context=context,
            pir_id=pir_id,
        )

        logger.info(
            f"Generated report for PIR {pir_id}: {report.id} "
            f"(confidence={report.confidence_score:.2f})"
        )
        return report

    async def get_pir(self, pir_id: str) -> Optional[PIR]:
        async with self._session_factory() as session:
            stmt = select(PIRTable).where(PIRTable.id == pir_id)
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            if row is None:
                return None
            return _pir_row_to_model(row)

    async def get_all_pirs(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> List[PIR]:
        async with self._session_factory() as session:
            stmt = select(PIRTable)
            if status:
                try:
                    status_enum = PIRStatus(status)
                    stmt = stmt.where(PIRTable.status == status_enum.value)
                except ValueError:
                    logger.warning(f"Invalid status filter: {status}")
            if priority:
                try:
                    priority_enum = PIRPriority(priority)
                    stmt = stmt.where(PIRTable.priority == priority_enum.value)
                except ValueError:
                    logger.warning(f"Invalid priority filter: {priority}")
            stmt = stmt.order_by(PIRTable.created_at.desc()).offset(offset).limit(limit)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_pir_row_to_model(r) for r in rows]

    async def get_pir_tasks(self, pir_id: str) -> List[PIRTask]:
        async with self._session_factory() as session:
            stmt = (
                select(PIRTaskTable)
                .where(PIRTaskTable.pir_id == pir_id)
                .order_by(PIRTaskTable.created_at.desc())
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_pir_task_row_to_model(r) for r in rows]

    async def update_task_status(
        self, task_id: str, status: str, result: Optional[Dict] = None
    ) -> Optional[PIRTask]:
        try:
            status_enum = PIRTaskStatus(status)
        except ValueError:
            logger.warning(f"Invalid task status: {status}")
            return None

        async with self._session_factory() as session:
            values: Dict[str, Any] = {
                "status": status_enum.value,
            }
            if result is not None:
                values["result_json"] = _json_dumps(result)
            if status_enum == PIRTaskStatus.COMPLETED:
                values["completed_at"] = datetime.now(timezone.utc)

            stmt = update(PIRTaskTable).where(PIRTaskTable.id == task_id).values(**values)
            await session.execute(stmt)
            await session.commit()

            stmt2 = select(PIRTaskTable).where(PIRTaskTable.id == task_id)
            result2 = await session.execute(stmt2)
            row = result2.scalar_one_or_none()
            if row is None:
                logger.warning(f"Task {task_id} not found after update")
                return None
            return _pir_task_row_to_model(row)
