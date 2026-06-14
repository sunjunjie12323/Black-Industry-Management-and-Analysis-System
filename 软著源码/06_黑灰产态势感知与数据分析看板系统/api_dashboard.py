from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user
from app.db.database import async_session_factory, get_db
from app.db.tables import (
    AnalyzedIntelligenceTable,
    CleanedIntelligenceTable,
    PIRTable,
    RawIntelligenceTable,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def get_orchestrator(request: Request):
    return getattr(request.app.state, "orchestrator", None)


def get_knowledge_graph(request: Request):
    return getattr(request.app.state, "knowledge_graph", None)


def get_blacktalk_engine(request: Request):
    return getattr(request.app.state, "blacktalk_engine", None)


def get_vector_store(request: Request):
    return getattr(request.app.state, "vector_store", None)


@router.get("/stats")
async def get_dashboard_stats(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    kg = get_knowledge_graph(request)
    bt = get_blacktalk_engine(request)
    vector_store = get_vector_store(request)
    orchestrator = get_orchestrator(request)

    graph_node_count = 0
    graph_edge_count = 0
    entity_types: Dict[str, int] = {}
    try:
        if kg:
            graph_stats = await kg.get_statistics()
            graph_node_count = graph_stats.get("node_count", 0)
            graph_edge_count = graph_stats.get("edge_count", 0)
            entity_types = graph_stats.get("entity_types", {})
    except Exception:
        pass

    blacktalk_stats: Dict = {"total_terms": 0, "categories": {}}
    try:
        if bt:
            bt_terms = await bt.get_all()
            blacktalk_count = len(bt_terms)
            category_counts: Dict[str, int] = {}
            for t in bt_terms:
                category_counts[t.category] = category_counts.get(t.category, 0) + 1
            blacktalk_stats = {"total_terms": blacktalk_count, "categories": category_counts}
    except Exception:
        pass

    db_raw_count = 0
    db_cleaned_count = 0
    db_analyzed_count = 0
    active_pir_count = 0
    threat_alert_count = 0

    try:
        result = await db.execute(
            select(func.count()).select_from(RawIntelligenceTable)
        )
        db_raw_count = result.scalar() or 0

        result = await db.execute(
            select(func.count()).select_from(CleanedIntelligenceTable)
        )
        db_cleaned_count = result.scalar() or 0

        result = await db.execute(
            select(func.count()).select_from(AnalyzedIntelligenceTable)
        )
        db_analyzed_count = result.scalar() or 0

        result = await db.execute(
            select(func.count()).select_from(PIRTable).where(
                PIRTable.status.in_(["active", "executing"])
            )
        )
        active_pir_count = result.scalar() or 0

        result = await db.execute(
            select(func.count()).select_from(CleanedIntelligenceTable).where(
                CleanedIntelligenceTable.threat_level.in_(["critical", "high"])
            )
        )
        high_threats = result.scalar() or 0

        result = await db.execute(
            select(func.count()).select_from(AnalyzedIntelligenceTable).where(
                AnalyzedIntelligenceTable.threat_level.in_(["critical", "high"])
            )
        )
        high_threats += result.scalar() or 0
        threat_alert_count = high_threats
    except Exception as exc:
        logger.warning(f"Failed to query DB stats: {exc}")

    total_intelligence = db_raw_count + db_cleaned_count + db_analyzed_count

    try:
        if vector_store:
            vs_intel_count = await vector_store.count("intelligence")
            if vs_intel_count > total_intelligence:
                total_intelligence = vs_intel_count
    except Exception as exc:
        logger.warning(f"Failed to get VectorStore intelligence count: {exc}")

    threat_level_distribution: Dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    try:
        stmt = (
            select(CleanedIntelligenceTable.threat_level, func.count())
            .group_by(CleanedIntelligenceTable.threat_level)
        )
        result = await db.execute(stmt)
        for level, count in result.all():
            if level in threat_level_distribution:
                threat_level_distribution[level] = count

        stmt = (
            select(AnalyzedIntelligenceTable.threat_level, func.count())
            .group_by(AnalyzedIntelligenceTable.threat_level)
        )
        result = await db.execute(stmt)
        for level, count in result.all():
            if level in threat_level_distribution:
                threat_level_distribution[level] += count
    except Exception as exc:
        logger.warning(f"Failed to query threat distribution: {exc}")

    source_type_distribution: Dict[str, int] = {}
    try:
        stmt = (
            select(RawIntelligenceTable.source, func.count())
            .group_by(RawIntelligenceTable.source)
        )
        result = await db.execute(stmt)
        for source, count in result.all():
            source_type_distribution[source] = count
    except Exception as exc:
        logger.warning(f"Failed to query source distribution: {exc}")

    recent_intelligence: List[Dict] = []
    try:
        stmt = (
            select(RawIntelligenceTable)
            .order_by(RawIntelligenceTable.collected_at.desc())
            .limit(10)
        )
        result = await db.execute(stmt)
        rows = result.scalars().all()
        for row in rows:
            recent_intelligence.append({
                "id": row.id,
                "title": f"[{row.source}] {(row.content[:50] + '...') if row.content and len(row.content) > 50 else (row.content or '')}",
                "content": row.content or "",
                "source": row.source,
                "source_type": row.source,
                "threat_level": "info",
                "collected_at": row.collected_at.isoformat() if row.collected_at else None,
                "is_processed": row.status != "raw",
                "entities": [],
                "tags": [],
            })
    except Exception as exc:
        logger.warning(f"Failed to query recent intelligence: {exc}")

    agent_statuses: List[Dict] = []
    recent_executions: List[Dict] = []
    try:
        if orchestrator:
            status = orchestrator.get_agent_status()
            if isinstance(status, list):
                agent_statuses = status
            elif isinstance(status, dict):
                for name, info in status.items():
                    agent_statuses.append({
                        "name": name,
                        "status": info.get("status", "idle") if isinstance(info, dict) else "idle",
                        "current_task": info.get("current_task") if isinstance(info, dict) else None,
                        "execution_count": info.get("execution_count", 0) if isinstance(info, dict) else 0,
                    })

            history = orchestrator.get_execution_history(limit=10)
            for h in history:
                recent_executions.append({
                    "id": h.get("execution_id", ""),
                    "query": h.get("query", ""),
                    "status": h.get("status", ""),
                    "started_at": h.get("start_time", ""),
                    "completed_at": h.get("end_time", ""),
                    "result_summary": h.get("results_summary"),
                    "agent_name": h.get("agent_name", ""),
                })
    except Exception as exc:
        logger.warning(f"Failed to get agent status: {exc}")

    organism_stats: Dict = {"total": 0, "alive": 0}
    try:
        organism_engine = getattr(request.app.state, "intelligence_organism", None)
        if organism_engine is not None:
            all_organisms = list(organism_engine.organisms.values())
            organism_stats = {
                "total": len(all_organisms),
                "alive": sum(1 for o in all_organisms if o.is_alive),
            }
    except Exception:
        pass

    return {
        "total_intelligence": total_intelligence,
        "knowledge_graph": {"node_count": graph_node_count, "edge_count": graph_edge_count},
        "blacktalk": blacktalk_stats,
        "active_pirs": active_pir_count,
        "threat_alerts": threat_alert_count,
        "threat_level_distribution": threat_level_distribution,
        "source_type_distribution": source_type_distribution,
        "recent_intelligence": recent_intelligence,
        "agent_statuses": agent_statuses,
        "recent_executions": recent_executions,
        "organism_stats": organism_stats,
    }


@router.get("/recent")
async def get_recent_intelligence(
    limit: int = Query(10, ge=1, le=50),
    request: Request = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    items = []
    try:
        stmt = (
            select(RawIntelligenceTable)
            .order_by(RawIntelligenceTable.collected_at.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        rows = result.scalars().all()
        for row in rows:
            items.append({
                "id": row.id,
                "type": "raw",
                "source": row.source,
                "content": (row.content[:200] + "...") if row.content and len(row.content) > 200 else row.content,
                "threat_level": None,
                "collected_at": row.collected_at.isoformat() if row.collected_at else None,
            })

        stmt = (
            select(CleanedIntelligenceTable)
            .order_by(CleanedIntelligenceTable.cleaned_at.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        rows = result.scalars().all()
        for row in rows:
            items.append({
                "id": row.id,
                "type": "cleaned",
                "source": None,
                "content": (row.content[:200] + "...") if row.content and len(row.content) > 200 else row.content,
                "threat_level": row.threat_level,
                "collected_at": row.cleaned_at.isoformat() if row.cleaned_at else None,
            })

        stmt = (
            select(AnalyzedIntelligenceTable)
            .order_by(AnalyzedIntelligenceTable.analyzed_at.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        rows = result.scalars().all()
        for row in rows:
            items.append({
                "id": row.id,
                "type": "analyzed",
                "source": None,
                "content": (row.analysis_summary[:200] + "...") if row.analysis_summary and len(row.analysis_summary) > 200 else row.analysis_summary,
                "threat_level": row.threat_level,
                "collected_at": row.analyzed_at.isoformat() if row.analyzed_at else None,
            })
    except Exception as exc:
        logger.warning(f"Failed to query recent intelligence from DB: {exc}")

    items.sort(key=lambda x: x.get("collected_at") or "", reverse=True)
    return {"items": items[:limit], "total": len(items)}


@router.get("/threat-distribution")
async def get_threat_distribution(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    distribution: Dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    try:
        stmt = (
            select(CleanedIntelligenceTable.threat_level, func.count())
            .group_by(CleanedIntelligenceTable.threat_level)
        )
        result = await db.execute(stmt)
        for level, count in result.all():
            if level in distribution:
                distribution[level] = count

        stmt = (
            select(AnalyzedIntelligenceTable.threat_level, func.count())
            .group_by(AnalyzedIntelligenceTable.threat_level)
        )
        result = await db.execute(stmt)
        for level, count in result.all():
            if level in distribution:
                distribution[level] += count
    except Exception as exc:
        logger.warning(f"Failed to query threat distribution: {exc}")

    try:
        kg = get_knowledge_graph(request)
        graph_stats = await kg.get_statistics()
        entity_types = graph_stats.get("entity_types", {})
    except Exception:
        entity_types = {}

    return {
        "threat_levels": distribution,
        "entity_types": entity_types,
    }


@router.get("/trend")
async def get_trend_data(
    days: int = Query(7, ge=1, le=30),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    trend_data: List[Dict] = []
    try:
        for i in range(days - 1, -1, -1):
            day = datetime.now(timezone.utc) - timedelta(days=i)
            day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            date_label = f"{day.month}/{day.day}"

            raw_count = 0
            stmt = select(func.count()).select_from(RawIntelligenceTable).where(
                RawIntelligenceTable.collected_at >= day_start,
                RawIntelligenceTable.collected_at < day_end,
            )
            result = await db.execute(stmt)
            raw_count = result.scalar() or 0

            critical_count = 0
            high_count = 0
            medium_count = 0
            stmt = select(CleanedIntelligenceTable.threat_level, func.count()).where(
                CleanedIntelligenceTable.cleaned_at >= day_start,
                CleanedIntelligenceTable.cleaned_at < day_end,
            ).group_by(CleanedIntelligenceTable.threat_level)
            result = await db.execute(stmt)
            for level, count in result.all():
                if level == "critical":
                    critical_count = count
                elif level == "high":
                    high_count = count
                elif level == "medium":
                    medium_count = count

            stmt = select(AnalyzedIntelligenceTable.threat_level, func.count()).where(
                AnalyzedIntelligenceTable.analyzed_at >= day_start,
                AnalyzedIntelligenceTable.analyzed_at < day_end,
            ).group_by(AnalyzedIntelligenceTable.threat_level)
            result = await db.execute(stmt)
            for level, count in result.all():
                if level == "critical":
                    critical_count += count
                elif level == "high":
                    high_count += count
                elif level == "medium":
                    medium_count += count

            trend_data.append({
                "date": date_label,
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "total": raw_count,
            })
    except Exception as exc:
        logger.warning(f"Failed to query trend data: {exc}")

    return {"trend": trend_data}


@router.get("/agent-status")
async def get_agent_status(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    orchestrator = get_orchestrator(request)
    if not orchestrator:
        return {"agents": [], "recent_executions": []}
    try:
        status = orchestrator.get_agent_status()
        history = orchestrator.get_execution_history(limit=10)

        recent_executions = []
        for h in history:
            recent_executions.append({
                "execution_id": h.get("execution_id", ""),
                "query": h.get("query", ""),
                "status": h.get("status", ""),
                "duration_seconds": h.get("duration_seconds", 0),
                "start_time": h.get("start_time", ""),
                "end_time": h.get("end_time", ""),
                "steps": h.get("steps", 0),
                "results_summary": h.get("results_summary"),
                "error": h.get("error"),
            })

        return {
            "agents": status,
            "recent_executions": recent_executions,
        }
    except Exception as exc:
        logger.error(f"Failed to get agent status: {exc}")
        raise HTTPException(status_code=500, detail="获取智能体状态失败")


_update_progress: Dict[str, Dict] = {}
_PROGRESS_MAX_AGE_SECONDS = 3600


def _cleanup_old_progress():
    now = datetime.now(timezone.utc)
    expired = [
        tid for tid, info in _update_progress.items()
        if info.get("status") in ("completed", "failed")
        and info.get("_completed_at")
        and (now - info["_completed_at"]).total_seconds() > _PROGRESS_MAX_AGE_SECONDS
    ]
    for tid in expired:
        del _update_progress[tid]


async def _safe_task(coro):
    try:
        await coro
    except Exception as exc:
        logger.error(f"Background task failed: {exc}")


@router.post("/refresh-data")
async def refresh_data(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    import asyncio
    import uuid
    import re as _re
    from app.models.entity import Entity, EntityType, Relation, RelationType

    _cleanup_old_progress()
    task_id = str(uuid.uuid4())[:8]
    _update_progress[task_id] = {"status": "running", "progress": 0, "message": "开始采集数据...", "new_count": 0}

    async def _run_refresh():
        try:
            _update_progress[task_id]["message"] = "正在从威胁情报API采集数据..."
            _update_progress[task_id]["progress"] = 5

            auto_collector = getattr(request.app.state, "auto_collector", None)
            auto_stats = {"intelligence": 0, "entities": 0, "relations": 0}
            if auto_collector:
                try:
                    _update_progress[task_id]["message"] = "正在通过AI引擎生成最新威胁情报..."
                    _update_progress[task_id]["progress"] = 10
                    auto_stats = await auto_collector.collect_once()
                    logger.info(f"AutoCollector collected: {auto_stats}")
                except Exception as exc:
                    logger.warning(f"AutoCollector collect_once failed: {exc}")

            _update_progress[task_id]["message"] = "正在从外部情报源采集数据..."
            _update_progress[task_id]["progress"] = 20

            from app.collectors.darkweb_collector import DarkWebCollector
            from app.collectors.forum_collector import ForumCollector

            items: list = []
            try:
                darkweb = DarkWebCollector()
                darkweb_items = await darkweb.collect(keywords=["malware", "phishing", "fraud", "ransomware"], max_results=30)
                items.extend(darkweb_items)
                await darkweb.close()
            except Exception as exc:
                logger.warning(f"DarkWeb refresh failed: {exc}")

            try:
                forum = ForumCollector()
                forum_items = await forum.collect(keywords=["fraud", "malware", "data breach", "CVE"], max_results=30)
                items.extend(forum_items)
                await forum.close()
            except Exception as exc:
                logger.warning(f"Forum refresh failed: {exc}")

            _update_progress[task_id]["message"] = f"采集到 {len(items)} 条情报，正在写入数据库..."
            _update_progress[task_id]["progress"] = 30

            new_count = 0
            if items:
                async with async_session_factory() as session:
                    for item in items[:50]:
                        raw_id = str(uuid.uuid4())
                        raw = RawIntelligenceTable(
                            id=raw_id,
                            source=item.get("metadata", {}).get("source", "api_refresh"),
                            source_url=item.get("source_url", ""),
                            content=item.get("content", ""),
                            raw_content=item.get("content", ""),
                            collected_at=datetime.now(timezone.utc),
                            status="raw",
                            metadata_json=str(item.get("metadata", {})),
                        )
                        session.add(raw)
                        new_count += 1
                    await session.commit()

            _update_progress[task_id]["new_count"] = new_count
            _update_progress[task_id]["message"] = "正在更新知识图谱..."
            _update_progress[task_id]["progress"] = 50

            knowledge_graph = getattr(request.app.state, "knowledge_graph", None)
            if knowledge_graph and new_count > 0:
                _TG_RE = _re.compile(r'@([a-zA-Z]\w{3,30})')
                _THREAT_KEYWORDS = {
                    "跑分": ("TOOL", "跑分平台/洗钱通道"), "洗钱": ("SERVICE", "资金清洗服务"),
                    "四件套": ("TOOL", "身份证+银行卡+手机卡+U盾"), "猫池": ("TOOL", "批量收发短信设备"),
                    "杀猪盘": ("SERVICE", "长期感情诈骗"), "接码": ("SERVICE", "接收验证码服务"),
                    "养号": ("SERVICE", "培育账号提高权重"), "料子": ("BLACKTALK", "被盗取的个人信息"),
                    "黑料": ("BLACKTALK", "违法数据/隐私信息"), "卡商": ("PERSON", "银行卡贩卖者"),
                    "料商": ("PERSON", "数据贩卖者"), "水房": ("SERVICE", "洗钱环节/资金清洗团队"),
                    "车手": ("PERSON", "取款人/ATM取现执行者"), "马仔": ("PERSON", "底层执行者"),
                    "木马": ("MALWARE", "恶意程序"), "钓鱼": ("SERVICE", "钓鱼攻击"),
                    "勒索": ("SERVICE", "勒索软件/勒索行为"), "DDoS": ("TOOL", "分布式拒绝服务攻击工具"),
                    "肉鸡": ("TOOL", "被控制的僵尸主机"), "僵尸网络": ("TOOL", "受控主机网络"),
                    "暗网": ("SERVICE", "暗网市场/服务"), "挖矿": ("MALWARE", "加密货币挖矿木马"),
                    "诈骗": ("SERVICE", "诈骗活动"), "博彩": ("SERVICE", "网络赌博"),
                    "菠菜": ("SERVICE", "网络赌博(谐音)"), "色流": ("SERVICE", "色情引流"),
                    "引流": ("SERVICE", "为黑产输送用户"), "提现": ("SERVICE", "非法提现/资金转移"),
                    "套现": ("SERVICE", "非法套现"), "代付": ("SERVICE", "代为支付"),
                    "黑卡": ("TOOL", "非法银行卡/信用卡"), "拦截卡": ("TOOL", "可拦截验证码的手机卡"),
                    "实名": ("BLACKTALK", "实名认证相关信息"), "话术": ("TOOL", "诈骗话术模板"),
                    "资金盘": ("SERVICE", "庞氏骗局/资金盘"), "套路贷": ("SERVICE", "欺诈性贷款"),
                    "裸贷": ("SERVICE", "以裸照抵押的借贷"), "免杀": ("TOOL", "绕过杀毒软件检测技术"),
                    "撞库": ("TOOL", "批量尝试登录工具"), "社工库": ("TOOL", "社会工程学数据库"),
                    "群控": ("TOOL", "批量控制设备系统"), "改机": ("TOOL", "修改设备信息工具"),
                }
                _ETYPE_MAP = {"TOOL": EntityType.TOOL, "SERVICE": EntityType.SERVICE, "BLACKTALK": EntityType.BLACKTALK, "PERSON": EntityType.PERSON, "MALWARE": EntityType.MALWARE, "ORGANIZATION": EntityType.ORGANIZATION}

                kg_new = 0
                for item in items[:50]:
                    content = item.get("content", "")
                    if not content:
                        continue
                    doc_ids: list = []
                    tg_matches = _TG_RE.findall(content)
                    for handle in set(tg_matches):
                        val = f"@{handle}"
                        entity = Entity(type=EntityType.ACCOUNT, value=val, context=content[:200], source_ids=[], confidence=0.8)
                        eid = await knowledge_graph.add_entity(entity)
                        doc_ids.append(eid)
                        kg_new += 1
                    for keyword, (etype_str, desc) in _THREAT_KEYWORDS.items():
                        if keyword not in content:
                            continue
                        etype = _ETYPE_MAP.get(etype_str, EntityType.BLACKTALK)
                        entity = Entity(type=etype, value=keyword, context=desc, source_ids=[], confidence=0.7)
                        eid = await knowledge_graph.add_entity(entity)
                        doc_ids.append(eid)
                        kg_new += 1
                await knowledge_graph.save()
                _update_progress[task_id]["message"] = f"知识图谱新增 {kg_new} 个实体"

            _update_progress[task_id]["progress"] = 70
            _update_progress[task_id]["message"] = "正在重新训练引擎..."

            zero_day_detector = getattr(request.app.state, "zero_day_detector", None)
            if zero_day_detector:
                try:
                    async with async_session_factory() as session:
                        result = await session.execute(select(RawIntelligenceTable).limit(300))
                        raw_items = result.scalars().all()
                        corpus = [(row.content or "") for row in raw_items if row.content]
                    if corpus and len(corpus) >= 5:
                        await asyncio.wait_for(zero_day_detector.train(corpus), timeout=30.0)
                except Exception as exc:
                    logger.warning(f"ZeroDay retrain failed: {exc}")

            _update_progress[task_id]["progress"] = 85
            _update_progress[task_id]["message"] = "正在更新攻击链预测..."

            attack_chain_predictor = getattr(request.app.state, "attack_chain_predictor", None)
            if attack_chain_predictor:
                try:
                    attack_chain_predictor.train_from_graph()
                except Exception as exc:
                    logger.warning(f"AttackChain retrain failed: {exc}")

            _update_progress[task_id]["progress"] = 95
            _update_progress[task_id]["message"] = "正在更新进化体..."

            intelligence_organism = getattr(request.app.state, "intelligence_organism", None)
            if intelligence_organism and new_count > 0:
                try:
                    async with async_session_factory() as session:
                        result = await session.execute(select(RawIntelligenceTable).order_by(RawIntelligenceTable.collected_at.desc()).limit(10))
                        recent = result.scalars().all()
                    for raw_item in recent:
                        content = raw_item.content or ""
                        if content and len(content) > 20:
                            await intelligence_organism.spawn_organism(
                                intelligence_id=raw_item.id,
                                species="api_refresh",
                                initial_data={"content": content[:500], "threat_type": "unknown"},
                                skip_save=True,
                            )
                    await intelligence_organism.save_to_disk()
                except Exception as exc:
                    logger.warning(f"Organism spawn failed: {exc}")

            _update_progress[task_id]["progress"] = 100
            _update_progress[task_id]["status"] = "completed"
            _update_progress[task_id]["_completed_at"] = datetime.now(timezone.utc)
            total_new = new_count + auto_stats.get("intelligence", 0)
            total_entities = auto_stats.get("entities", 0)
            total_relations = auto_stats.get("relations", 0)
            _update_progress[task_id]["message"] = f"更新完成！新增 {total_new} 条情报，{total_entities} 个实体，{total_relations} 条关系"
            _update_progress[task_id]["new_count"] = total_new

        except Exception as exc:
            _update_progress[task_id]["status"] = "failed"
            _update_progress[task_id]["_completed_at"] = datetime.now(timezone.utc)
            _update_progress[task_id]["message"] = "更新失败"
            logger.error(f"Refresh data failed: {exc}")

    asyncio.create_task(_safe_task(_run_refresh()))
    return {"task_id": task_id, "status": "started"}


@router.get("/refresh-progress/{task_id}")
async def get_refresh_progress(
    task_id: str,
    current_user: User = Depends(get_current_user),
):
    progress = _update_progress.get(task_id, {"status": "not_found", "progress": 0, "message": "任务不存在"})
    return progress
