import asyncio
import json
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user, require_role, Role
from app.core.provenance_chain import ProvenanceChain
from app.db.database import async_session_factory, get_db
from app.db.tables import RawIntelligenceTable

router = APIRouter(prefix="/provenance", tags=["provenance"])


class ProvenanceRecordRequest(BaseModel):
    intelligence_id: str = Field(..., min_length=1)
    stage: str = Field(..., min_length=1)
    input_data: Dict = Field(default_factory=dict)
    output_data: Dict = Field(default_factory=dict)
    algorithm_input: Optional[str] = None
    algorithm_output: Optional[str] = None
    confidence_before: Optional[float] = None
    confidence_after: Optional[float] = None
    operator: str = Field(default="automated")


def get_provenance_chain(request: Request) -> ProvenanceChain | None:
    return getattr(request.app.state, "provenance_chain", None)


@router.post("/record")
async def record_provenance(
    data: ProvenanceRecordRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    chain = get_provenance_chain(request)
    if chain is None:
        raise HTTPException(status_code=503, detail="Provenance chain not available")
    try:
        record = await asyncio.wait_for(
            chain.record_provenance(
                intelligence_id=data.intelligence_id,
                stage=data.stage,
                input_data=data.input_data,
                output_data=data.output_data,
                algorithm_input=data.algorithm_input,
                algorithm_output=data.algorithm_output,
                confidence_before=data.confidence_before,
                confidence_after=data.confidence_after,
            ),
            timeout=60,
        )
        return record.to_dict()
    except asyncio.TimeoutError:
        logger.error(f"Provenance recording timed out for intelligence '{data.intelligence_id}'")
        raise HTTPException(status_code=504, detail="Provenance recording timed out")
    except Exception as exc:
        logger.error(f"Provenance recording failed for intelligence '{data.intelligence_id}': {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/verify/{intelligence_id}")
async def verify_provenance(
    intelligence_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    chain = get_provenance_chain(request)
    if chain is None:
        raise HTTPException(status_code=503, detail="Provenance chain not available")
    try:
        result = await asyncio.wait_for(
            chain.verify_provenance(intelligence_id),
            timeout=60,
        )
        return result.to_dict()
    except asyncio.TimeoutError:
        logger.error(f"Provenance verification timed out for intelligence '{intelligence_id}'")
        raise HTTPException(status_code=504, detail="Provenance verification timed out")
    except Exception as exc:
        logger.error(f"Provenance verification failed for intelligence '{intelligence_id}': {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/evolution/{intelligence_id}")
async def get_confidence_evolution(
    intelligence_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    chain = get_provenance_chain(request)
    if chain is None:
        raise HTTPException(status_code=503, detail="Provenance chain not available")
    try:
        evolution = await asyncio.wait_for(
            chain.get_confidence_evolution(intelligence_id),
            timeout=60,
        )
        return {
            "intelligence_id": intelligence_id,
            "evolution": [e.to_dict() for e in evolution],
        }
    except asyncio.TimeoutError:
        logger.error(f"Confidence evolution timed out for intelligence '{intelligence_id}'")
        raise HTTPException(status_code=504, detail="Confidence evolution timed out")
    except Exception as exc:
        logger.error(f"Confidence evolution failed for intelligence '{intelligence_id}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.post("/hallucination-check/{intelligence_id}")
async def detect_hallucination(
    intelligence_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    chain = get_provenance_chain(request)
    if chain is None:
        raise HTTPException(status_code=503, detail="Provenance chain not available")
    try:
        result = await asyncio.wait_for(
            chain.detect_hallucination(intelligence_id),
            timeout=60,
        )
        return result.to_dict()
    except asyncio.TimeoutError:
        logger.error(f"Hallucination check timed out for intelligence '{intelligence_id}'")
        raise HTTPException(status_code=504, detail="Hallucination check timed out")
    except Exception as exc:
        logger.error(f"Hallucination check failed for intelligence '{intelligence_id}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/search-by-content")
async def search_by_content(
    query: str = Query(..., min_length=1),
    limit: int = Query(default=10, ge=1, le=50),
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    chain = get_provenance_chain(request)
    if chain is None:
        raise HTTPException(status_code=503, detail="Provenance chain not available")
    query_lower = query.lower()
    matched = []
    for intel_id, records in chain._chains.items():
        for record in records:
            input_text = json.dumps(record.metadata.get("input_data", {}), ensure_ascii=False, default=str).lower()
            output_text = json.dumps(record.metadata.get("output_data", {}), ensure_ascii=False, default=str).lower()
            algo_input = (record.algorithm_input or "").lower()
            algo_output = (record.algorithm_output or "").lower()
            if query_lower in input_text or query_lower in output_text or query_lower in algo_input or query_lower in algo_output:
                matched.append({
                    "intelligence_id": intel_id,
                    "stage": record.stage,
                    "timestamp": record.timestamp,
                    "snippet": (record.algorithm_output or json.dumps(record.metadata.get("output_data", {}), ensure_ascii=False, default=str))[:200],
                })
                break
    matched = matched[:limit]
    if not matched:
        raise HTTPException(status_code=404, detail=f"No intelligence found matching: {query}")
    return {"query": query, "results": matched, "total": len(matched)}


@router.get("/chain/{intelligence_id}")
async def get_provenance_chain_records(
    intelligence_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    chain = get_provenance_chain(request)
    if chain is None:
        raise HTTPException(status_code=503, detail="Provenance chain not available")
    try:
        records = chain.get_chain(intelligence_id)
        return {
            "intelligence_id": intelligence_id,
            "records": [r.to_dict() for r in records],
        }
    except Exception as exc:
        logger.error(f"Failed to get provenance chain for intelligence '{intelligence_id}': {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/auto-generate")
async def auto_generate_provenance(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    pc = request.app.state.provenance_chain
    if pc is None:
        raise HTTPException(status_code=503, detail="Provenance chain not available")
    try:
        generated = 0
        result = await db.execute(
            select(RawIntelligenceTable).order_by(RawIntelligenceTable.collected_at.desc()).limit(limit)
        )
        intels = result.scalars().all()
        for intel in intels:
            if intel.id not in pc._chains or len(pc._chains[intel.id]) == 0:
                try:
                    await pc.record_provenance(
                        intelligence_id=intel.id,
                        stage="raw_collection",
                        input_data={"source": intel.source, "source_url": intel.source_url},
                        output_data={"content": (intel.content or "")[:500]},
                    )
                    generated += 1
                except Exception:
                    pass
        pc.save_to_disk()
        return {"generated": generated, "total_checked": len(intels)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/recent")
async def get_recent_provenance(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """获取最近的溯源记录列表，页面打开即有数据"""
    pc = get_provenance_chain(request)
    if pc is None:
        raise HTTPException(status_code=503, detail="Provenance chain not available")

    all_records = []
    for intel_id, records in pc._chains.items():
        for record in records:
            all_records.append({
                "intelligence_id": intel_id,
                "stage": record.stage,
                "timestamp": record.timestamp,
                "operator": record.operator,
                "confidence_before": record.confidence_before,
                "confidence_after": record.confidence_after,
                "input_hash": record.input_hash[:16] if record.input_hash else "",
                "output_hash": record.output_hash[:16] if record.output_hash else "",
                "previous_record_id": record.previous_record_id,
            })

    all_records.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    recent = all_records[:limit]

    verified_count = 0
    hallucination_count = 0
    for intel_id in list(pc._chains.keys())[:30]:
        try:
            v = await pc.verify_provenance(intel_id)
            if v.is_valid:
                verified_count += 1
        except Exception:
            pass
        try:
            h = await pc.detect_hallucination(intel_id)
            if h.is_hallucination:
                hallucination_count += 1
        except Exception:
            pass

    return {
        "records": recent,
        "total_records": len(all_records),
        "total_chains": len(pc._chains),
        "verified_count": verified_count,
        "hallucination_count": hallucination_count,
    }


@router.get("/chains")
async def get_chains_alias(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    pc = get_provenance_chain(request)
    if pc is None:
        raise HTTPException(status_code=503, detail="Provenance chain not available")

    chains = []
    for intel_id, records in pc._chains.items():
        if records:
            latest = records[-1]
            chains.append({
                "intelligence_id": intel_id,
                "stage": latest.stage,
                "timestamp": latest.timestamp,
                "record_count": len(records),
                "operator": latest.operator,
            })
    chains.sort(key=lambda c: c.get("timestamp", ""), reverse=True)
    return {"chains": chains[:limit], "total": len(chains)}


@router.get("/trace/{intelligence_id}")
async def trace_intelligence_source(
    intelligence_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await _build_trace(intelligence_id, request, db)
    if result is None:
        raise HTTPException(status_code=404, detail="未找到该情报的溯源信息")
    return result


async def _build_trace(intelligence_id: str, request: Request, db: AsyncSession) -> dict | None:
    import aiohttp

    source_url = None
    source_type = None
    content_preview = None
    collected_at = None
    raw_id = None
    cleaned_id = None
    analyzed_id = None

    from app.db.tables import RawIntelligenceTable, CleanedIntelligenceTable, AnalyzedIntelligenceTable
    from sqlalchemy import select

    async with async_session_factory() as session:
        result = await session.execute(
            select(RawIntelligenceTable).where(RawIntelligenceTable.id == intelligence_id)
        )
        raw = result.scalar_one_or_none()
        if raw:
            source_url = raw.source_url
            source_type = raw.source
            content_preview = (raw.content or "")[:300]
            collected_at = raw.collected_at.isoformat() if raw.collected_at else None
            raw_id = raw.id

        if not raw:
            result = await session.execute(
                select(CleanedIntelligenceTable).where(CleanedIntelligenceTable.id == intelligence_id)
            )
            cleaned = result.scalar_one_or_none()
            if cleaned:
                cleaned_id = cleaned.id
                source_url = cleaned.source_url if hasattr(cleaned, 'source_url') else None
                source_type = getattr(cleaned, 'source', None)
                content_preview = (cleaned.content or "")[:300]
                collected_at = cleaned.cleaned_at.isoformat() if cleaned.cleaned_at else None
                result = await session.execute(
                    select(RawIntelligenceTable).where(RawIntelligenceTable.id == cleaned.raw_intelligence_id)
                )
                raw = result.scalar_one_or_none()
                if raw:
                    source_url = source_url or raw.source_url
                    source_type = source_type or raw.source
                    collected_at = collected_at or (raw.collected_at.isoformat() if raw.collected_at else None)
                    raw_id = raw.id

        if not raw and not cleaned_id:
            result = await session.execute(
                select(AnalyzedIntelligenceTable).where(AnalyzedIntelligenceTable.id == intelligence_id)
            )
            analyzed = result.scalar_one_or_none()
            if analyzed:
                analyzed_id = analyzed.id
                content_preview = (analyzed.analysis_summary or "")[:300]
                collected_at = analyzed.analyzed_at.isoformat() if analyzed.analyzed_at else None
                if hasattr(analyzed, 'raw_intelligence_id') and analyzed.raw_intelligence_id:
                    result = await session.execute(
                        select(RawIntelligenceTable).where(RawIntelligenceTable.id == analyzed.raw_intelligence_id)
                    )
                    raw = result.scalar_one_or_none()
                    if raw:
                        source_url = raw.source_url
                        source_type = raw.source
                        collected_at = raw.collected_at.isoformat() if raw.collected_at else None
                        raw_id = raw.id

    if not raw_id and not source_url:
        return None

    url_accessible = None
    if source_url:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as http:
                async with http.head(source_url, allow_redirects=True, ssl=False) as resp:
                    url_accessible = resp.status < 400
        except Exception:
            url_accessible = False

    chain_stages = []
    if raw_id:
        chain_stages.append({"stage": "原始采集", "id": raw_id, "timestamp": collected_at})
    if cleaned_id:
        chain_stages.append({"stage": "数据清洗", "id": cleaned_id})
    if analyzed_id:
        chain_stages.append({"stage": "深度分析", "id": analyzed_id})

    pc = get_provenance_chain(request)
    provenance_records = []
    if pc and intelligence_id in pc._chains:
        provenance_records = [r.to_dict() for r in pc._chains[intelligence_id]]
    elif pc and raw_id and raw_id in pc._chains:
        provenance_records = [r.to_dict() for r in pc._chains[raw_id]]

    return {
        "intelligence_id": intelligence_id,
        "source_url": source_url,
        "source_type": source_type,
        "content_preview": content_preview,
        "collected_at": collected_at,
        "url_accessible": url_accessible,
        "chain_stages": chain_stages,
        "provenance_records": provenance_records,
    }


@router.get("/source-preview/{intelligence_id}")
async def get_source_preview(
    intelligence_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    import aiohttp
    import re as _re

    async with async_session_factory() as session:
        result = await session.execute(
            select(RawIntelligenceTable).where(RawIntelligenceTable.id == intelligence_id)
        )
        raw = result.scalar_one_or_none()
        if not raw or not raw.source_url:
            raise HTTPException(status_code=404, detail="该情报没有关联的来源URL")

    source_url = raw.source_url
    title = None
    description = None
    site_name = None
    favicon_url = None

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as http:
            async with http.get(source_url, allow_redirects=True, ssl=False) as resp:
                if resp.status < 400:
                    html = await resp.text(errors='ignore')
                    title_match = _re.search(r'<title[^>]*>(.*?)</title>', html, _re.IGNORECASE | _re.DOTALL)
                    if title_match:
                        title = title_match.group(1).strip()[:200]
                    desc_match = _re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', html, _re.IGNORECASE)
                    if desc_match:
                        description = desc_match.group(1).strip()[:500]
                    site_match = _re.search(r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\'](.*?)["\']', html, _re.IGNORECASE)
                    if site_match:
                        site_name = site_match.group(1).strip()[:100]
                    from urllib.parse import urlparse
                    parsed = urlparse(source_url)
                    favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
    except Exception:
        pass

    return {
        "intelligence_id": intelligence_id,
        "source_url": source_url,
        "title": title or source_url,
        "description": description,
        "site_name": site_name,
        "favicon_url": favicon_url,
    }
