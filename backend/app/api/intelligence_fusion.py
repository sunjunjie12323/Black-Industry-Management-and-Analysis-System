"""
情报融合引擎API
实现多源情报去重、冲突解决、证据聚合
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Dict, Any

from app.db.database import get_db
from app.db.tables import RawIntelligenceTable
from app.core.intelligence_fusion import intelligence_fusion_engine
from app.core.auth import get_current_user, User

router = APIRouter(prefix="/intelligence-fusion", tags=["情报融合"])


@router.post("/fuse")
async def fuse_intelligence(
    intelligence_ids: List[str],
    strategy: str = "weighted_average",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    融合多条情报记录
    - 语义去重：识别并合并重复情报
    - 冲突解决：处理矛盾信息
    - 证据聚合：使用Dempster-Shafer理论合并证据
    """
    result = await db.execute(
        RawIntelligenceTable.__table__.select().where(
            RawIntelligenceTable.id.in_(intelligence_ids)
        )
    )
    items = result.fetchall()

    if not items:
        raise HTTPException(status_code=404, detail="未找到情报记录")

    items_dict = [dict(item._mapping) for item in items]

    fusion_result = await intelligence_fusion_engine.fuse_intelligence(
        items=items_dict,
        strategy=strategy
    )

    return {
        "status": "success",
        "fused_result": fusion_result["fused_result"],
        "duplicates_removed": fusion_result["duplicates_removed"],
        "conflicts_resolved": fusion_result["conflicts_resolved"],
        "confidence_boost": fusion_result["confidence_boost"]
    }


@router.post("/deduplicate")
async def deduplicate_intelligence(
    threshold: float = 0.85,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    对情报库进行去重
    使用TF-IDF和余弦相似度识别重复情报
    """
    result = await db.execute(RawIntelligenceTable.__table__.select())
    items = result.fetchall()
    items_dict = [dict(item._mapping) for item in items]

    unique_items, duplicate_groups = await intelligence_fusion_engine.semantic_deduplication(
        items=items_dict,
        threshold=threshold
    )

    return {
        "status": "success",
        "total_items": len(items_dict),
        "unique_items": len(unique_items),
        "duplicate_groups": len(duplicate_groups),
        "duplicates": [
            {
                "group_id": i,
                "items": [item["id"] for item in group],
                "similarity": group[0].get("similarity", 0) if group else 0
            }
            for i, group in enumerate(duplicate_groups)
        ]
    }


@router.post("/resolve-conflicts")
async def resolve_conflicts(
    intelligence_ids: List[str],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    解决情报间的冲突
    使用来源信誉加权和多数投票机制
    """
    result = await db.execute(
        RawIntelligenceTable.__table__.select().where(
            RawIntelligenceTable.id.in_(intelligence_ids)
        )
    )
    items = result.fetchall()

    if not items:
        raise HTTPException(status_code=404, detail="未找到情报记录")

    items_dict = [dict(item._mapping) for item in items]

    resolved = await intelligence_fusion_engine.resolve_conflicts(items_dict)

    return {
        "status": "success",
        "resolved_intelligence": resolved
    }


@router.post("/aggregate-evidence")
async def aggregate_evidence(
    evidence_list: List[Dict[str, Any]],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    聚合多个证据源
    使用Dempster-Shafer证据理论合并信念
    """
    aggregated = await intelligence_fusion_engine.aggregate_evidence(evidence_list)

    return {
        "status": "success",
        "aggregated_evidence": aggregated
    }


@router.get("/contradictions/{intelligence_id}")
async def detect_contradictions(
    intelligence_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    检测与指定情报相矛盾的其他情报
    """
    result = await db.execute(
        RawIntelligenceTable.__table__.select().where(RawIntelligenceTable.id == intelligence_id)
    )
    target = result.fetchone()

    if not target:
        raise HTTPException(status_code=404, detail="未找到情报记录")

    target_dict = dict(target._mapping)

    # 获取相关情报（相同来源或相同分类级别）
    target_source = target_dict.get("source", "")
    target_level = target_dict.get("classification_level", "")
    conditions = [RawIntelligenceTable.id != intelligence_id]
    if target_source:
        conditions.append(RawIntelligenceTable.source == target_source)
    if target_level:
        conditions.append(RawIntelligenceTable.classification_level == target_level)

    from sqlalchemy import or_
    related_result = await db.execute(
        RawIntelligenceTable.__table__.select().where(
            or_(*conditions)
        ).limit(100)
    )
    related_items = related_result.fetchall()
    related_dicts = [dict(item._mapping) for item in related_items]

    contradictions = await intelligence_fusion_engine.detect_contradictions(
        target_dict, related_dicts
    )

    return {
        "status": "success",
        "target_id": intelligence_id,
        "contradictions": contradictions
    }


@router.get("/provenance/{fused_id}")
async def get_fusion_provenance(
    fused_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    获取融合情报的溯源图
    追踪融合过程中每个信息点的来源
    """
    result = await db.execute(
        RawIntelligenceTable.__table__.select().where(RawIntelligenceTable.id == fused_id)
    )
    fused_item = result.fetchone()

    if not fused_item:
        raise HTTPException(status_code=404, detail="未找到融合情报")

    fused_dict = dict(fused_item._mapping)

    provenance = await intelligence_fusion_engine.build_provenance_graph(fused_dict)

    return {
        "status": "success",
        "fused_id": fused_id,
        "provenance_graph": provenance
    }
