import asyncio
import json
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from loguru import logger
from pydantic import BaseModel, Field, field_validator

from app.core.auth import User, get_current_user, require_role, Role
from app.db.crud import IntelligenceCRUD
from app.db.database import async_session_factory

router = APIRouter(prefix="/agent", tags=["agent"])
report_router = APIRouter(prefix="/agent/report", tags=["agent-report"])


class QueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=5000)
    context: Optional[Dict] = None
    max_iterations: int = Field(default=3, ge=1, le=10)

    @field_validator("context")
    @classmethod
    def validate_context_size(cls, v):
        if v is not None and len(json.dumps(v, ensure_ascii=False)) > 10000:
            raise ValueError("context字段序列化后不能超过10000字符")
        return v


class TaskResponse(BaseModel):
    task_id: str
    status: str = "pending"
    message: str = ""


def get_orchestrator(request: Request):
    return getattr(request.app.state, "orchestrator", None)


@router.post("/query")
async def submit_query(
    data: QueryRequest,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    from app.core.task_queue import task_queue
    try:
        task_id = await task_queue.submit(
            task_type="query",
            params={"query": data.query, "context": data.context},
        )
        return {
            "task_id": task_id,
            "status": "pending",
            "message": "查询已提交",
        }
    except Exception as exc:
        logger.error(f"Failed to submit query: {exc}")
        raise HTTPException(status_code=500, detail="查询提交失败，请稍后重试")


@router.get("/status")
async def get_agent_status(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    orchestrator = get_orchestrator(request)
    if not orchestrator:
        return {"agents": []}
    try:
        status = orchestrator.get_agent_status()
        return {"agents": status}
    except Exception as exc:
        logger.error(f"Failed to get agent status: {exc}")
        return {"agents": []}


@router.get("/history")
async def get_execution_history(
    limit: int = 20,
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    orchestrator = get_orchestrator(request)
    if not orchestrator:
        return {"items": [], "total": 0, "message": "编排器未初始化"}
    try:
        history = orchestrator.get_execution_history(limit=limit)
        return {
            "items": history,
            "total": len(history),
        }
    except Exception as exc:
        logger.error(f"Failed to get execution history: {exc}")
        return {"items": [], "total": 0, "message": "获取执行历史失败"}


@router.get("/execution/{execution_id}")
async def get_execution_detail(
    execution_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    orchestrator = get_orchestrator(request)
    if not orchestrator:
        raise HTTPException(status_code=404, detail="执行记录未找到")
    try:
        task = task_queue.get_task(execution_id)
        if task:
            return {
                "execution_id": task.id,
                "status": task.status.value,
                "result": task.result,
                "error": task.error,
                "progress": task.progress,
                "created_at": str(task.created_at) if task.created_at else None,
                "completed_at": str(task.completed_at) if task.completed_at else None,
            }
        history = orchestrator.get_execution_history(limit=100)
        for h in history:
            if h.get("execution_id") == execution_id:
                return h
        raise HTTPException(status_code=404, detail="执行记录未找到")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Failed to get execution detail: {exc}")
        raise HTTPException(status_code=404, detail="执行记录未找到")


@router.post("/collect")
async def trigger_collection(
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    from app.core.task_queue import task_queue
    try:
        task_id = await task_queue.submit(
            task_type="collect",
            params={"source": "all", "keywords": [], "max_results": 10},
        )
        return {"task_id": task_id, "status": "pending", "message": "情报收集任务已提交"}
    except Exception as exc:
        logger.error(f"Failed to trigger collection: {exc}")
        raise HTTPException(status_code=500, detail="情报收集任务提交失败，请稍后重试")


@router.post("/analyze")
async def trigger_analysis(
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    from app.core.task_queue import task_queue
    try:
        task_id = await task_queue.submit(
            task_type="analyze",
            params={"cleaned_intelligence": {}},
        )
        return {"task_id": task_id, "status": "pending", "message": "情报分析任务已提交"}
    except Exception as exc:
        logger.error(f"Failed to trigger analysis: {exc}")
        raise HTTPException(status_code=500, detail="情报分析任务提交失败，请稍后重试")


def register_agent_handlers(app=None):
    from app.core.task_queue import task_queue

    async def _handle_query(task):
        orchestrator = app.state.orchestrator
        try:
            result = await asyncio.wait_for(
                orchestrator.execute_query(
                    query=task.params.get("query", ""),
                    context=task.params.get("context"),
                ),
                timeout=120.0,
            )
            return result
        except asyncio.TimeoutError:
            return {"status": "error", "error": "查询超时(120s)", "partial_results": None}

    async def _handle_collect(task):
        orchestrator = app.state.orchestrator
        try:
            return await asyncio.wait_for(
                orchestrator.collector.execute({
                    "type": "collect",
                    "source": task.params.get("source", "all"),
                    "keywords": task.params.get("keywords", []),
                    "max_results": task.params.get("max_results", 10),
                }),
                timeout=180.0,
            )
        except asyncio.TimeoutError:
            return {"status": "error", "errors": ["情报采集超时(180s)"]}

    async def _handle_clean(task):
        orchestrator = app.state.orchestrator
        try:
            return await asyncio.wait_for(
                orchestrator.cleaner.execute({
                    "type": "clean",
                    "raw_intelligence": task.params.get("raw_intelligence"),
                }),
                timeout=120.0,
            )
        except asyncio.TimeoutError:
            return {"status": "error", "errors": ["情报清洗超时(120s)"]}

    async def _handle_analyze(task):
        orchestrator = app.state.orchestrator
        try:
            return await asyncio.wait_for(
                orchestrator.analyst.execute({
                    "type": "analyze",
                    "cleaned_intelligence": task.params.get("cleaned_intelligence"),
                }),
                timeout=120.0,
            )
        except asyncio.TimeoutError:
            return {"status": "error", "errors": ["情报分析超时(120s)"]}

    async def _handle_build_graph(task):
        orchestrator = app.state.orchestrator
        try:
            return await asyncio.wait_for(
                orchestrator.graph_builder.execute({
                    "type": "build",
                    "analysis_result": task.params.get("analysis_result"),
                }),
                timeout=120.0,
            )
        except asyncio.TimeoutError:
            return {"status": "error", "errors": ["图谱构建超时(120s)"]}

    task_queue.register_handler("query", _handle_query)
    task_queue.register_handler("collect", _handle_collect)
    task_queue.register_handler("clean", _handle_clean)
    task_queue.register_handler("analyze", _handle_analyze)
    task_queue.register_handler("build_graph", _handle_build_graph)


class ReportRequest(BaseModel):
    intelligence_id: Optional[str] = Field(None, max_length=256)
    content: Optional[str] = Field(None, max_length=50000)


@report_router.post("/report")
async def generate_report(
    data: ReportRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if data.intelligence_id:
        analysis_data = None

        vs = getattr(request.app.state, "vector_store", None)
        if vs:
            try:
                results = vs.search(data.intelligence_id, n_results=1)
                if results and isinstance(results, list) and len(results) > 0:
                    analysis_data = results[0]
            except Exception:
                logger.exception("Unexpected error in vector store search for report")

        if not analysis_data:
            try:
                async with async_session_factory() as db:
                    crud = IntelligenceCRUD(db)
                    raw = await crud.get_raw(data.intelligence_id)
                    if raw:
                        analysis_data = raw.model_dump()
                    else:
                        cleaned = await crud.get_cleaned(data.intelligence_id)
                        if cleaned:
                            analysis_data = cleaned.model_dump()
                        else:
                            analyzed = await crud.get_analyzed(data.intelligence_id)
                            if analyzed:
                                analysis_data = analyzed.model_dump()
            except Exception as exc:
                logger.warning(f"Database lookup for report failed: {exc}")

        if not analysis_data:
            raise HTTPException(status_code=404, detail="Intelligence not found")

        if orchestrator:
            try:
                query = data.intelligence_id
                if isinstance(analysis_data, dict):
                    query = (
                        analysis_data.get("content", "")
                        or analysis_data.get("analysis_summary", "")
                        or data.intelligence_id
                    )[:200]

                aggregated = {
                    "key_findings": analysis_data.get("key_findings", []) if isinstance(analysis_data, dict) else [],
                    "threat_assessment": analysis_data.get("threat_level", "info") if isinstance(analysis_data, dict) else "info",
                    "main_threat_categories": analysis_data.get("threat_categories", []) if isinstance(analysis_data, dict) else [],
                    "confidence": analysis_data.get("confidence_score", 0.5) if isinstance(analysis_data, dict) else 0.5,
                    "summary": (
                        analysis_data.get("analysis_summary", "")
                        or analysis_data.get("content", "")
                    ) if isinstance(analysis_data, dict) else "",
                }

                report = await orchestrator._generate_report(query=query, aggregated=aggregated)
                return {"status": "success", "report": report}
            except Exception as exc:
                logger.error(f"Report generation failed: {exc}")

        content_text = ""
        if isinstance(analysis_data, dict):
            content_text = str(analysis_data.get("content", ""))[:500]

        from app.core.rule_based_extractor import rule_extractor
        categories, cat_conf = rule_extractor.classify_threat(content_text) if content_text else ([], 0)
        entities = rule_extractor.extract_entities(content_text) if content_text else []
        level, level_conf = rule_extractor.assess_threat_level(content_text) if content_text else ("info", 0)

        category_name_map = {
            "fraud": "诈骗", "gambling": "赌博", "hacking": "黑客攻击",
            "money_laundering": "洗钱", "phishing": "钓鱼攻击",
            "ransomware": "勒索软件", "data_theft": "数据盗窃",
            "tool_sales": "工具售卖", "drug": "毒品相关",
        }
        category_labels = [category_name_map.get(c, c) for c in categories]

        iocs = []
        for e in entities:
            if e["type"] in ("ip", "domain", "url", "email", "crypto_wallet", "cve"):
                iocs.append(f"[{e['type'].upper()}] {e['value']}")

        return {
            "status": "success",
            "report": {
                "title": f"情报分析报告: {data.intelligence_id[:50]}",
                "executive_summary": (
                    str(analysis_data.get("analysis_summary", analysis_data.get("content", "")))[:200]
                    if isinstance(analysis_data, dict) else ""
                ),
                "key_findings": [
                    f"威胁分类: {', '.join(category_labels) if category_labels else '未识别'}",
                    f"威胁等级: {level}",
                    f"关键实体数: {len(entities)}",
                ],
                "threat_actors": [e["value"] for e in entities if e["type"] in ("organization", "account")],
                "iocs": iocs,
                "recommendations": ["建议持续监控相关情报动态", "关联分析历史情报", "更新威胁指标库"],
                "confidence_score": cat_conf,
            },
            "fallback": True,
        }

    elif data.content:
        if orchestrator:
            try:
                result = await asyncio.wait_for(
                    orchestrator.execute_query(data.content),
                    timeout=15.0,
                )
                report = result.get("report", {})
                return {"status": "success", "report": report}
            except asyncio.TimeoutError:
                logger.warning("Orchestrator report generation timed out, using fallback")
            except Exception as exc:
                logger.error(f"Pipeline execution for report failed: {exc}")

        from app.core.rule_based_extractor import rule_extractor
        categories, cat_conf = rule_extractor.classify_threat(data.content)
        entities = rule_extractor.extract_entities(data.content)
        level, level_conf = rule_extractor.assess_threat_level(data.content)

        category_labels = [category_name_map.get(c, c) for c in categories]

        iocs = []
        for e in entities:
            if e["type"] in ("ip", "domain", "url", "email", "crypto_wallet", "cve"):
                iocs.append(f"[{e['type'].upper()}] {e['value']}")

        recommendations = []
        if "fraud" in categories:
            recommendations.extend(["追踪诈骗资金流向", "识别受害群体并预警", "封堵诈骗通信渠道"])
        if "hacking" in categories:
            recommendations.extend(["修补相关漏洞", "加强入侵检测", "隔离受影响系统"])
        if "money_laundering" in categories:
            recommendations.extend(["追踪资金链路", "冻结可疑账户", "上报反洗钱机构"])
        if "phishing" in categories:
            recommendations.extend(["下线钓鱼网站", "封堵仿冒域名", "通知潜在受害者"])
        if not recommendations:
            recommendations = ["持续监控相关情报动态", "关联分析历史情报", "更新威胁指标库"]

        return {
            "status": "success",
            "report": {
                "title": f"情报分析报告: {data.content[:50]}",
                "executive_summary": f"经规则引擎分析，该情报涉及{', '.join(category_labels) if category_labels else '未知'}类威胁，威胁等级为{level}，共提取{len(entities)}个关键实体，其中{len(iocs)}个可作为威胁指标(IOC)。",
                "key_findings": [
                    f"威胁分类: {', '.join(category_labels) if category_labels else '未识别'}",
                    f"威胁等级: {level} (置信度: {level_conf:.0%})",
                    f"关键实体数: {len(entities)}",
                    f"威胁指标(IOC): {len(iocs)}个",
                ],
                "threat_actors": [e["value"] for e in entities if e["type"] in ("organization", "account")],
                "iocs": iocs,
                "recommendations": recommendations,
                "confidence_score": cat_conf,
            },
            "fallback": True,
        }

    raise HTTPException(status_code=400, detail="Either intelligence_id or content must be provided")


@router.get("/tasks")
async def get_tasks_alias(
    limit: int = 20,
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    from app.core.task_queue import task_queue
    try:
        tasks = task_queue.list_tasks(limit=limit)
        return {"tasks": tasks, "total": len(tasks)}
    except Exception as exc:
        logger.error(f"Failed to list agent tasks: {exc}")
        return {"tasks": [], "total": 0, "message": "获取任务列表失败"}
