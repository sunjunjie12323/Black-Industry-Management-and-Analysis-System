"""
威胁行为画像API
提供TTP指纹提取、行为聚类、攻击者关联接口
"""
import json
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Dict, Any
from pydantic import BaseModel

from app.core.auth import get_current_user, User
from app.db.database import get_db
from app.db.tables import RawIntelligenceTable, AnalysisResultTable
from app.api.utils import raw_intelligence_to_dict

router = APIRouter(prefix="/threat-behavior", tags=["威胁行为画像"])


class BehaviorProfileRequest(BaseModel):
    incident_ids: List[str]


class BehaviorProfileResponse(BaseModel):
    profile: Dict[str, Any]
    ttp_fingerprint: Dict[str, Any]
    behavior_vector: List[float]
    patterns: List[Dict[str, Any]]


@router.post("/profile", response_model=BehaviorProfileResponse)
async def build_threat_behavior_profile(
    request: BehaviorProfileRequest,
    req: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    构建威胁行为画像
    从多个安全事件中提取TTP指纹和行为模式
    """
    behavior_engine = req.app.state.threat_behavior_profiler
    if not behavior_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="威胁行为画像引擎未初始化"
        )

    from sqlalchemy import select

    stmt = select(RawIntelligenceTable).where(RawIntelligenceTable.id.in_(request.incident_ids))
    result = await db.execute(stmt)
    incidents = result.scalars().all()

    if not incidents:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到指定的事件数据"
        )

    incidents_dict = [raw_intelligence_to_dict(e) for e in incidents]

    profile = await behavior_engine.build_behavior_profile(incidents_dict)

    return BehaviorProfileResponse(
        profile=profile["profile"],
        ttp_fingerprint=profile["ttp_fingerprint"],
        behavior_vector=profile["behavior_vector"],
        patterns=profile["patterns"]
    )


@router.post("/extract-ttps")
async def extract_ttps_from_text(
    req: Request,
    text: str,
    current_user: User = Depends(get_current_user)
):
    """
    从文本中提取TTP（战术、技术和程序）
    """
    behavior_engine = req.app.state.threat_behavior_profiler
    if not behavior_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="威胁行为画像引擎未初始化"
        )

    ttps = behavior_engine.extract_ttps(text)

    return {
        "text_length": len(text),
        "ttps_found": len(ttps),
        "ttps": ttps
    }


@router.post("/cluster-actors")
async def cluster_threat_actors(
    req: Request,
    profile_ids: List[str],
    min_similarity: float = 0.6,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    基于行为相似度聚类威胁行为者
    从AnalysisResultTable中加载已存储的行为画像
    """
    behavior_engine = req.app.state.threat_behavior_profiler
    if not behavior_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="威胁行为画像引擎未初始化"
        )

    from sqlalchemy import select

    stmt = select(AnalysisResultTable).where(
        AnalysisResultTable.analysis_type == "threat_behavior_profile",
        AnalysisResultTable.id.in_(profile_ids)
    )
    result = await db.execute(stmt)
    profile_rows = result.scalars().all()

    if not profile_rows:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到指定的行为画像"
        )

    profiles_dict = []
    for row in profile_rows:
        profile_data = {}
        if row.result_data_json:
            try:
                profile_data = json.loads(row.result_data_json)
            except (json.JSONDecodeError, TypeError):
                pass
        profiles_dict.append({
            "id": row.id,
            "name": row.result_summary or row.id,
            "ttp_fingerprint": profile_data.get("ttp_fingerprint", {}),
            "behavior_vector": profile_data.get("behavior_vector", []),
            "metadata": profile_data.get("metadata", {}),
        })

    clusters = behavior_engine.cluster_threat_actors(profiles_dict, min_similarity)

    return {
        "total_profiles": len(profiles_dict),
        "cluster_count": len(clusters),
        "min_similarity": min_similarity,
        "clusters": [
            {
                "cluster_id": i,
                "profile_ids": [p["id"] for p in cluster],
                "profiles": cluster,
                "avg_similarity": sum(
                    behavior_engine.calculate_behavior_similarity(p1, p2)
                    for p1 in cluster
                    for p2 in cluster
                    if p1["id"] < p2["id"]
                ) / max(len(cluster) * (len(cluster) - 1) / 2, 1)
            }
            for i, cluster in enumerate(clusters)
        ]
    }


@router.get("/match-actors/{incident_id}")
async def match_known_threat_actors(
    incident_id: str,
    req: Request,
    top_k: int = 5,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    将事件与已知威胁行为者进行匹配
    从AnalysisResultTable中加载已知行为者画像
    """
    behavior_engine = req.app.state.threat_behavior_profiler
    if not behavior_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="威胁行为画像引擎未初始化"
        )

    from sqlalchemy import select

    stmt = select(RawIntelligenceTable).where(RawIntelligenceTable.id == incident_id)
    result = await db.execute(stmt)
    incident = result.scalar_one_or_none()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到指定的事件"
        )

    # 从AnalysisResultTable加载已知行为者画像
    stmt = select(AnalysisResultTable).where(
        AnalysisResultTable.analysis_type == "known_threat_actor"
    )
    result = await db.execute(stmt)
    known_actor_rows = result.scalars().all()

    if not known_actor_rows:
        return {
            "incident_id": incident_id,
            "matches": [],
            "message": "数据库中暂无已知威胁行为者画像"
        }

    incident_dict = raw_intelligence_to_dict(incident)
    incident_profile = await behavior_engine.build_behavior_profile([incident_dict])

    known_actors_dict = []
    for row in known_actor_rows:
        actor_data = {}
        if row.result_data_json:
            try:
                actor_data = json.loads(row.result_data_json)
            except (json.JSONDecodeError, TypeError):
                pass
        known_actors_dict.append({
            "id": row.id,
            "name": row.result_summary or row.id,
            "ttp_fingerprint": actor_data.get("ttp_fingerprint", {}),
            "behavior_vector": actor_data.get("behavior_vector", []),
        })

    matches = behavior_engine.match_known_actors(
        incident_profile["profile"],
        known_actors_dict,
        top_k
    )

    return {
        "incident_id": incident_id,
        "matches": matches,
        "total_known_actors": len(known_actors_dict)
    }


@router.post("/detect-anomaly")
async def detect_behavior_anomaly(
    req: Request,
    incident_id: str,
    baseline_profile_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    检测事件行为是否偏离基线画像
    基线画像从AnalysisResultTable中加载
    """
    behavior_engine = req.app.state.threat_behavior_profiler
    if not behavior_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="威胁行为画像引擎未初始化"
        )

    from sqlalchemy import select

    stmt = select(RawIntelligenceTable).where(RawIntelligenceTable.id == incident_id)
    result = await db.execute(stmt)
    incident = result.scalar_one_or_none()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到指定的事件"
        )

    stmt = select(AnalysisResultTable).where(
        AnalysisResultTable.id == baseline_profile_id,
        AnalysisResultTable.analysis_type == "threat_behavior_profile"
    )
    result = await db.execute(stmt)
    baseline_row = result.scalar_one_or_none()

    if not baseline_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到指定的基线画像"
        )

    baseline_data = {}
    if baseline_row.result_data_json:
        try:
            baseline_data = json.loads(baseline_row.result_data_json)
        except (json.JSONDecodeError, TypeError):
            pass

    incident_dict = raw_intelligence_to_dict(incident)
    incident_profile = await behavior_engine.build_behavior_profile([incident_dict])

    anomaly_result = behavior_engine.detect_behavior_anomaly(
        incident_profile["profile"],
        {
            "ttp_fingerprint": baseline_data.get("ttp_fingerprint", {}),
            "behavior_vector": baseline_data.get("behavior_vector", [])
        }
    )

    return {
        "incident_id": incident_id,
        "baseline_profile_id": baseline_profile_id,
        "is_anomaly": anomaly_result["is_anomaly"],
        "anomaly_score": anomaly_result["anomaly_score"],
        "deviations": anomaly_result["deviations"],
        "explanation": anomaly_result["explanation"]
    }
