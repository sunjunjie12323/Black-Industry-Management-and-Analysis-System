import csv
import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, Response
from app.core.auth import get_current_user, User
from app.models.intelligence import IntelligenceSource
from app.core.rule_based_extractor import rule_extractor
import logging

logger = logging.getLogger(__name__)
export_router = APIRouter(prefix="/export", tags=["导出"])

MAX_EXPORT_LIMIT = 1000
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")

STIX_TYPES = {
    "ip": "ipv4-addr",
    "url": "url",
    "domain": "domain-name",
    "email": "email-addr",
    "hash_md5": "file",
    "hash_sha256": "file",
    "cve": "vulnerability",
    "tool": "tool",
    "organization": "threat-actor",
    "person": "threat-actor",
    "location": "location",
    "phone": "phone-number",
    "qq": "software",
    "wechat": "software",
    "cryptocurrency": "cryptocurrency-wallet",
}


def _validate_date(date_str: Optional[str], field_name: str) -> Optional[str]:
    if date_str is None:
        return None
    if not DATE_PATTERN.match(date_str):
        return f"{field_name}格式无效，要求YYYY-MM-DD"
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return f"{field_name}不是有效日期"
    return None


def _entity_to_stix(entity: dict) -> dict:
    etype = entity.get("type", "unknown")
    value = entity.get("value", "")
    stix_type = STIX_TYPES.get(etype, "x-custom-object")

    obj = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": f"{stix_type}--{str(uuid.uuid5(uuid.NAMESPACE_DNS, f'{etype}:{value}'))}",
        "created": datetime.now(timezone.utc).isoformat() + "Z",
        "modified": datetime.now(timezone.utc).isoformat() + "Z",
    }

    if stix_type == "ipv4-addr":
        obj["value"] = value
    elif stix_type == "url":
        obj["value"] = value
    elif stix_type == "domain-name":
        obj["value"] = value
    elif stix_type == "email-addr":
        obj["value"] = value
    elif stix_type == "file":
        if "md5" in etype:
            obj["hashes"] = {"MD5": value}
        else:
            obj["hashes"] = {"SHA-256": value}
    elif stix_type == "vulnerability":
        obj["name"] = value
        obj["external_references"] = [{"source_name": "cve", "external_id": value}]
    elif stix_type == "threat-actor":
        obj["name"] = value
        obj["threat_actor_types"] = ["criminal"]
    elif stix_type == "tool":
        obj["name"] = value
    else:
        obj["name"] = value
        obj["x_type"] = etype

    return obj


@export_router.get("/stix")
async def export_stix(
    content: Optional[str] = Query(None, description="情报文本内容"),
    format: str = Query("bundle", pattern="^(bundle|objects)$"),
    start_date: Optional[str] = Query(None, description="起始日期(YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="结束日期(YYYY-MM-DD)"),
    limit: int = Query(500, ge=1, le=MAX_EXPORT_LIMIT, description="结果数量上限"),
    current_user: User = Depends(get_current_user),
):
    if not content:
        return JSONResponse(
            content={
                "success": False,
                "message": "请提供content参数",
                "code": 422,
            },
            status_code=422,
        )

    date_err = _validate_date(start_date, "start_date")
    if date_err:
        return JSONResponse(
            content={"success": False, "message": date_err, "code": 422},
            status_code=422,
        )
    date_err = _validate_date(end_date, "end_date")
    if date_err:
        return JSONResponse(
            content={"success": False, "message": date_err, "code": 422},
            status_code=422,
        )

    from app.core.stix_exporter import STIXExporter
    exporter = STIXExporter()

    intel_data = {
        "id": "export-content",
        "content": content,
        "threat_level": "info",
        "entity_type": "threat-intelligence",
    }
    bundle = exporter.export_bundle([intel_data])

    if format == "objects":
        stix_objects = bundle.get("objects", [])
        try:
            body = json.dumps(stix_objects, ensure_ascii=False, indent=2)
        except (TypeError, ValueError) as e:
            logger.error(f"STIX objects serialization failed: {e}")
            return JSONResponse(
                content={
                    "success": False,
                    "message": "STIX数据序列化失败",
                    "code": 500,
                },
                status_code=500,
            )
        return Response(
            content=body,
            media_type="application/stix+json",
            headers={
                "Content-Disposition": f"attachment; filename=stix-objects-{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
            },
        )

    try:
        body = json.dumps(bundle, ensure_ascii=False, indent=2)
    except (TypeError, ValueError) as e:
        logger.error(f"STIX bundle serialization failed: {e}")
        return JSONResponse(
            content={
                "success": False,
                "message": "STIX数据序列化失败",
                "code": 500,
            },
            status_code=500,
        )
    return Response(
        content=body,
        media_type="application/stix+json",
        headers={
            "Content-Disposition": f"attachment; filename=stix-bundle-{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
        },
    )


@export_router.get("/ioc")
async def export_ioc(
    content: Optional[str] = Query(None, description="情报文本内容"),
    format: str = Query("json", pattern="^(json|csv)$"),
    start_date: Optional[str] = Query(None, description="起始日期(YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="结束日期(YYYY-MM-DD)"),
    limit: int = Query(500, ge=1, le=MAX_EXPORT_LIMIT, description="结果数量上限"),
    current_user: User = Depends(get_current_user),
):
    if not content:
        return JSONResponse(
            content={
                "success": False,
                "message": "请提供content参数",
                "code": 422,
            },
            status_code=422,
        )

    date_err = _validate_date(start_date, "start_date")
    if date_err:
        return JSONResponse(
            content={"success": False, "message": date_err, "code": 422},
            status_code=422,
        )
    date_err = _validate_date(end_date, "end_date")
    if date_err:
        return JSONResponse(
            content={"success": False, "message": date_err, "code": 422},
            status_code=422,
        )

    entities = rule_extractor.extract_entities(content)
    entities = entities[:limit]
    iocs = []
    for e in entities:
        etype = e.get("type", "unknown")
        value = e.get("value", "")
        iocs.append(
            {
                "indicator": value,
                "type": etype,
                "stix_type": STIX_TYPES.get(etype, "unknown"),
                "confidence": e.get("confidence", 0.8),
                "source": "rule-based-extraction",
                "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            }
        )

    if format == "csv":
        output = io.StringIO()
        try:
            fieldnames = ["indicator", "type", "stix_type", "confidence", "source", "timestamp"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(iocs)
            body = output.getvalue()
        except Exception as e:
            logger.error(f"IOC CSV serialization failed: {e}")
            return JSONResponse(
                content={
                    "success": False,
                    "message": "CSV序列化失败",
                    "code": 500,
                },
                status_code=500,
            )
        finally:
            output.close()
        return Response(
            content=body,
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f"attachment; filename=iocs-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
            },
        )

    try:
        body = json.dumps(iocs, ensure_ascii=False, indent=2)
    except (TypeError, ValueError) as e:
        logger.error(f"IOC JSON serialization failed: {e}")
        return JSONResponse(
            content={
                "success": False,
                "message": "IOC数据序列化失败",
                "code": 500,
            },
            status_code=500,
        )
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=iocs-{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
        },
    )


@export_router.get("/csv")
async def export_csv(
    content: Optional[str] = Query(None, description="情报文本内容"),
    start_date: Optional[str] = Query(None, description="起始日期(YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="结束日期(YYYY-MM-DD)"),
    limit: int = Query(500, ge=1, le=MAX_EXPORT_LIMIT, description="结果数量上限"),
    current_user: User = Depends(get_current_user),
):
    if not content:
        return JSONResponse(
            content={
                "success": False,
                "message": "请提供content参数",
                "code": 422,
            },
            status_code=422,
        )

    date_err = _validate_date(start_date, "start_date")
    if date_err:
        return JSONResponse(
            content={"success": False, "message": date_err, "code": 422},
            status_code=422,
        )
    date_err = _validate_date(end_date, "end_date")
    if date_err:
        return JSONResponse(
            content={"success": False, "message": date_err, "code": 422},
            status_code=422,
        )

    entities = rule_extractor.extract_entities(content)
    entities = entities[:limit]
    rows = []
    for e in entities:
        etype = e.get("type", "unknown")
        value = e.get("value", "")
        rows.append(
            {
                "type": etype,
                "value": value,
                "stix_type": STIX_TYPES.get(etype, "unknown"),
                "confidence": e.get("confidence", 0.8),
                "source": "rule-based-extraction",
                "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            }
        )

    output = io.StringIO()
    try:
        fieldnames = ["type", "value", "stix_type", "confidence", "source", "timestamp"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        body = output.getvalue()
    except Exception as e:
        logger.error(f"CSV export serialization failed: {e}")
        return JSONResponse(
            content={
                "success": False,
                "message": "CSV序列化失败",
                "code": 500,
            },
            status_code=500,
        )
    finally:
        output.close()
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename=threat-intel-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
        },
    )
