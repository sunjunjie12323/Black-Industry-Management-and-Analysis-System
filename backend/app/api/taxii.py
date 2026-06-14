import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api_key_auth import require_permission
from app.core.api_key_manager import ApiKey, ApiPermission
from app.core.stix_exporter import STIXExporter
from app.db.database import get_db


taxii_router = APIRouter(prefix="/taxii", tags=["TAXII 2.1"])

API_ROOT = "threat-intel"
COLLECTION_ID = "stix-objects"
TAXII_VERSION = "taxii-2.1"


@taxii_router.get("/discovery")
async def taxii_discovery(api_key: ApiKey = Depends(require_permission("intel:read"))):
    return {
        "title": "Threat Intel Agent TAXII Server",
        "description": "TAXII 2.1 endpoint for threat intelligence sharing",
        "default": f"/api/v1/taxii/{API_ROOT}/",
        "api_roots": [f"/api/v1/taxii/{API_ROOT}/"],
    }


@taxii_router.get("/{api_root}/")
async def taxii_api_root(api_root: str, api_key: ApiKey = Depends(require_permission("intel:read"))):
    if api_root != API_ROOT:
        raise HTTPException(status_code=404, detail="API Root not found")
    return {
        "title": f"Threat Intel Agent - {api_root}",
        "description": "Threat intelligence data sharing",
        "versions": [TAXII_VERSION],
        "max_content_length": 10485760,
    }


@taxii_router.get("/{api_root}/collections/")
async def taxii_collections(api_root: str, api_key: ApiKey = Depends(require_permission("intel:read"))):
    if api_root != API_ROOT:
        raise HTTPException(status_code=404, detail="API Root not found")
    return {
        "collections": [
            {
                "id": COLLECTION_ID,
                "title": "STIX Objects",
                "description": "All STIX objects from threat intelligence",
                "can_read": True,
                "can_write": True,
                "media_types": ["application/stix+json;version=2.1"],
            }
        ]
    }


@taxii_router.get("/{api_root}/collections/{collection_id}/objects/")
async def taxii_get_objects(
    api_root: str,
    collection_id: str,
    added_after: Optional[str] = Query(None, description="Filter objects added after this timestamp"),
    type: Optional[str] = Query(None, alias="type", description="Filter by STIX object type"),
    limit: int = Query(100, ge=1, le=10000),
    api_key: ApiKey = Depends(require_permission("intel:read")),
    db: AsyncSession = Depends(get_db),
):
    if api_root != API_ROOT:
        raise HTTPException(status_code=404, detail="API Root not found")
    if collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="Collection not found")

    from app.db.tables import AnalyzedIntelligenceTable, CleanedIntelligenceTable, RawIntelligenceTable
    exporter = STIXExporter()
    objects = []

    stmt = (
        select(AnalyzedIntelligenceTable, CleanedIntelligenceTable, RawIntelligenceTable)
        .join(CleanedIntelligenceTable, AnalyzedIntelligenceTable.cleaned_id == CleanedIntelligenceTable.id)
        .join(RawIntelligenceTable, CleanedIntelligenceTable.raw_id == RawIntelligenceTable.id)
        .order_by(desc(AnalyzedIntelligenceTable.analyzed_at))
        .limit(limit)
    )
    if added_after:
        try:
            from datetime import datetime as dt
            after_dt = dt.fromisoformat(added_after.replace("Z", "+00:00"))
            stmt = stmt.where(AnalyzedIntelligenceTable.analyzed_at >= after_dt)
        except (ValueError, TypeError):
            pass
    result = await db.execute(stmt)
    intel_list = []
    for analyzed, cleaned, raw in result.all():
        intel_list.append({
            "id": raw.id,
            "content": cleaned.content or raw.content,
            "threat_level": analyzed.threat_level or cleaned.threat_level,
            "collected_at": raw.collected_at.isoformat() if raw.collected_at else None,
            "entity_type": "threat-intelligence",
        })

    if intel_list:
        bundle = exporter.export_bundle(intel_list)
        for obj in bundle.get("objects", []):
            if type and obj.get("type") != type:
                continue
            objects.append(obj)

    return {
        "more": False,
        "objects": objects,
    }


@taxii_router.post("/{api_root}/collections/{collection_id}/objects/")
async def taxii_add_objects(
    api_root: str,
    collection_id: str,
    request: Request,
    api_key: ApiKey = Depends(require_permission("intel:write")),
):
    if api_root != API_ROOT:
        raise HTTPException(status_code=404, detail="API Root not found")
    if collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="Collection not found")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    objects = body.get("objects", [])
    if not objects:
        raise HTTPException(status_code=400, detail="No objects provided")

    accepted_ids = []
    for obj in objects:
        obj_id = obj.get("id", str(uuid.uuid4()))
        accepted_ids.append(obj_id)

    logger.info(f"TAXII: {len(accepted_ids)} objects received from {api_key.key_prefix}")

    return {
        "id": str(uuid.uuid4()),
        "status": "complete",
        "request_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_count": len(objects),
        "success_count": len(accepted_ids),
        "failure_count": 0,
        "pending_count": 0,
        "ids": {"success": accepted_ids},
    }
