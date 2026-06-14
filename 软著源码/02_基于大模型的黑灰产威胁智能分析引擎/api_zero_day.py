import asyncio
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user, require_role, Role
from app.core.zero_day_detector import ZeroDayDetector
from app.db.database import get_db
from app.db.tables import RawIntelligenceTable

router = APIRouter(prefix="/zero-day", tags=["zero-day"])


class ZeroDayDetectRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)


def get_zero_day_detector(request: Request) -> ZeroDayDetector | None:
    return getattr(request.app.state, "zero_day_detector", None)


@router.post("/detect")
async def detect_zero_day_terms(
    data: ZeroDayDetectRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    detector = get_zero_day_detector(request)
    if detector is None:
        raise HTTPException(status_code=503, detail="Zero-day detector not available")
    try:
        zero_day_terms = await asyncio.wait_for(
            detector.detect_zero_day_terms(data.text),
            timeout=60,
        )
        known_count = 0
        try:
            decode_result = await detector.blacktalk_engine.decode(data.text)
            if isinstance(decode_result, dict):
                known_count = decode_result.get("terms_found", 0)
            elif hasattr(decode_result, 'terms_found'):
                known_count = decode_result.terms_found
        except Exception:
            pass
        return {
            "zero_day_terms": [t.to_dict() for t in zero_day_terms],
            "known_terms_count": known_count,
            "total_analyzed": len(zero_day_terms) + known_count,
        }
    except asyncio.TimeoutError:
        logger.error("Zero-day detection timed out")
        raise HTTPException(status_code=504, detail="Zero-day detection timed out")
    except Exception as exc:
        logger.error(f"Zero-day detection failed: {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/drift/{term}")
async def track_semantic_drift(
    term: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    detector = get_zero_day_detector(request)
    if detector is None:
        raise HTTPException(status_code=503, detail="Zero-day detector not available")
    try:
        result = await asyncio.wait_for(
            detector.track_semantic_drift(term),
            timeout=60,
        )
        return result.to_dict()
    except asyncio.TimeoutError:
        logger.error(f"Semantic drift analysis timed out for term '{term}'")
        raise HTTPException(status_code=504, detail="Semantic drift analysis timed out")
    except Exception as exc:
        logger.error(f"Semantic drift analysis failed for term '{term}': {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/migration/{term}")
async def track_cross_platform_migration(
    term: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    detector = get_zero_day_detector(request)
    if detector is None:
        raise HTTPException(status_code=503, detail="Zero-day detector not available")
    try:
        result = await asyncio.wait_for(
            detector.track_cross_platform_migration(term),
            timeout=60,
        )
        return result.to_dict()
    except asyncio.TimeoutError:
        logger.error(f"Cross-platform migration analysis timed out for term '{term}'")
        raise HTTPException(status_code=504, detail="Cross-platform migration analysis timed out")
    except Exception as exc:
        logger.error(f"Cross-platform migration analysis failed for term '{term}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.post("/scan-intelligence")
async def scan_intelligence(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    detector = request.app.state.zero_day_detector
    if detector is None:
        raise HTTPException(status_code=503, detail="Zero day detector not available")

    llm = getattr(request.app.state, "llm_service", None)
    llm_ok = llm is not None and hasattr(llm, "is_available") and llm.is_available

    try:
        result = await db.execute(
            select(RawIntelligenceTable).order_by(RawIntelligenceTable.collected_at.desc()).limit(limit)
        )
        intels = result.scalars().all()

        all_detections = []
        scanned = 0
        sem = asyncio.Semaphore(3)

        async def _scan_one(intel):
            nonlocal scanned
            async with sem:
                content = intel.content or ""
                if not content or len(content) < 10:
                    scanned += 1
                    return
                try:
                    result = await asyncio.wait_for(
                        detector.detect_zero_day_terms(content),
                        timeout=15 if llm_ok else 8,
                    )
                    if result and result.get("detected_terms"):
                        for term in result["detected_terms"]:
                            all_detections.append({
                                "intelligence_id": intel.id,
                                "term": term.get("term", ""),
                                "score": term.get("score", 0),
                                "context": term.get("context", "")[:100],
                            })
                    scanned += 1
                except asyncio.TimeoutError:
                    logger.warning(f"Zero-day scan timed out for intel {intel.id}")
                    scanned += 1
                except Exception:
                    scanned += 1

        tasks = [_scan_one(intel) for intel in intels]
        await asyncio.gather(*tasks)

        all_detections.sort(key=lambda x: x.get("score", 0), reverse=True)
        return {"scanned": scanned, "detections": len(all_detections), "results": all_detections[:30]}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/recent-detections")
async def get_recent_detections(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    detector = get_zero_day_detector(request)
    if detector is None:
        raise HTTPException(status_code=503, detail="Zero-day detector not available")

    llm = getattr(request.app.state, "llm_service", None)
    llm_ok = llm is not None and hasattr(llm, "is_available") and llm.is_available

    try:
        result = await db.execute(
            select(RawIntelligenceTable).order_by(RawIntelligenceTable.collected_at.desc()).limit(limit)
        )
        intels = result.scalars().all()

        detections = []
        drift_results = []
        blacktalk_terms = list(detector.blacktalk_engine._dictionary.keys())[:5] if detector.blacktalk_engine else []

        sem = asyncio.Semaphore(3)

        async def _detect_one(intel):
            async with sem:
                content = intel.content or ""
                if not content or len(content) < 10:
                    return
                try:
                    zterms = await asyncio.wait_for(
                        detector.detect_zero_day_terms(content),
                        timeout=15 if llm_ok else 8,
                    )
                    for t in zterms:
                        detections.append({
                            "intelligence_id": intel.id,
                            "source": intel.source,
                            "term": t.term,
                            "score": t.confidence,
                            "context": t.context[:100] if t.context else "",
                        })
                except asyncio.TimeoutError:
                    logger.warning(f"Zero-day detection timed out for intel {intel.id}")
                except Exception:
                    pass

        tasks = [_detect_one(intel) for intel in intels[:limit]]
        await asyncio.gather(*tasks)

        if llm_ok:
            for term_id in blacktalk_terms:
                bt = detector.blacktalk_engine._dictionary.get(term_id)
                if bt and bt.term:
                    try:
                        drift = await asyncio.wait_for(
                            detector.track_semantic_drift(bt.term),
                            timeout=10,
                        )
                        drift_results.append({
                            "term": bt.term,
                            "original_meaning": drift.original_meaning,
                            "current_meaning": drift.current_meaning,
                            "drift_velocity": drift.drift_velocity,
                            "timeline_count": len(drift.drift_timeline),
                        })
                    except asyncio.TimeoutError:
                        logger.warning(f"Semantic drift timed out for term '{bt.term}'")
                    except Exception:
                        pass

        detections.sort(key=lambda x: x.get("score", 0), reverse=True)
        return {
            "detections": detections[:limit],
            "drift_results": drift_results,
            "total_detections": len(detections),
            "total_intel_scanned": len(intels),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/vulnerabilities")
async def get_vulnerabilities_alias(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    return await get_recent_detections(request, limit, current_user)
