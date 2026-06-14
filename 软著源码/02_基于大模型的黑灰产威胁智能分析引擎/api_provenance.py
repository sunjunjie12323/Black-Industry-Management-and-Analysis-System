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
from app.db.database import get_db
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
