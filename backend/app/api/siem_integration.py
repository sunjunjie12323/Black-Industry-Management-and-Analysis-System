import asyncio
import csv
import io
import json
import socket
import struct
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api_key_auth import require_permission
from app.core.api_key_manager import ApiKey, ApiPermission
from app.db.database import get_db


siem_router = APIRouter(prefix="/integration", tags=["SIEM/SOAR Integration"])


class WebhookRegistration(BaseModel):
    url: str
    event_types: List[str] = Field(default_factory=lambda: ["new_intelligence", "new_alert", "entity_update"])
    headers: Dict[str, str] = Field(default_factory=dict)
    auth_header: Optional[str] = None
    name: Optional[str] = None


class SyslogConfig(BaseModel):
    host: str
    port: int = 514
    protocol: str = Field(default="udp", pattern="^(tcp|udp)$")
    format: str = Field(default="cef", pattern="^(cef|json|syslog)$")
    facility: int = Field(default=1, ge=0, le=23)
    severity: int = Field(default=5, ge=0, le=7)


_webhook_registrations: Dict[str, dict] = {}


@siem_router.get("/splunk/ioc")
async def splunk_ioc_export(
    format: str = Query("json", pattern="^(json|csv)$"),
    limit: int = Query(500, ge=1, le=5000),
    api_key: ApiKey = Depends(require_permission("intel:read")),
    db: AsyncSession = Depends(get_db),
):
    from app.db.tables import AnalyzedIntelligenceTable, CleanedIntelligenceTable, EntityTable

    iocs = []
    entity_result = await db.execute(
        select(EntityTable).order_by(desc(EntityTable.last_seen)).limit(limit)
    )
    for entity in entity_result.scalars().all():
        ioc = {
            "ioc_value": entity.value,
            "ioc_type": entity.type,
            "threat_level": "unknown",
            "confidence": entity.confidence,
            "first_seen": entity.first_seen.isoformat() if entity.first_seen else None,
            "last_seen": entity.last_seen.isoformat() if entity.last_seen else None,
            "context": entity.context,
            "source": "threat-intel-agent",
        }
        iocs.append(ioc)

    if format == "csv":
        output = io.StringIO()
        if iocs:
            writer = csv.DictWriter(output, fieldnames=iocs[0].keys())
            writer.writeheader()
            writer.writerows(iocs)
        from fastapi.responses import Response
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=iocs.csv"},
        )

    return {"iocs": iocs, "count": len(iocs)}


@siem_router.post("/webhook")
async def register_webhook(
    registration: WebhookRegistration,
    api_key: ApiKey = Depends(require_permission("admin")),
):
    webhook_id = uuid4().hex
    entry = {
        "id": webhook_id,
        "url": registration.url,
        "event_types": registration.event_types,
        "headers": registration.headers,
        "auth_header": registration.auth_header,
        "name": registration.name or f"webhook-{webhook_id[:8]}",
        "tenant_id": api_key.tenant_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "retry_count": 0,
    }
    _webhook_registrations[webhook_id] = entry
    logger.info(f"Webhook registered: {entry['name']} -> {registration.url}")
    return {"webhook_id": webhook_id, "status": "registered"}


async def _deliver_webhook(webhook: dict, payload: dict, max_retries: int = 3) -> bool:
    import httpx
    headers = {"Content-Type": "application/json"}
    if webhook.get("auth_header"):
        headers["Authorization"] = webhook["auth_header"]
    headers.update(webhook.get("headers", {}))

    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(webhook["url"], json=payload, headers=headers)
                if resp.status_code < 400:
                    logger.info(f"Webhook delivered to {webhook['url']}: {resp.status_code}")
                    return True
                logger.warning(f"Webhook delivery failed: {resp.status_code}")
        except Exception as exc:
            logger.warning(f"Webhook delivery error (attempt {attempt + 1}/{max_retries}): {exc}")
        if attempt < max_retries - 1:
            await asyncio.sleep(2 ** attempt)
    logger.error(f"Webhook delivery failed after {max_retries} retries: {webhook['url']}")
    return False


@siem_router.post("/syslog/config")
async def configure_syslog(
    config: SyslogConfig,
    api_key: ApiKey = Depends(require_permission("admin")),
):
    syslog_config_id = uuid4().hex
    logger.info(f"Syslog configured: {config.host}:{config.port}/{config.protocol} (format={config.format})")
    return {
        "config_id": syslog_config_id,
        "status": "configured",
        "host": config.host,
        "port": config.port,
        "protocol": config.protocol,
        "format": config.format,
    }


def _format_cef(event: dict) -> str:
    severity_map = {"critical": "10", "high": "8", "medium": "5", "low": "3", "info": "1"}
    sev = severity_map.get(event.get("severity", "medium"), "5")
    device_vendor = "ThreatIntelAgent"
    device_product = "TIA"
    device_version = "2.3.0"
    signature_id = event.get("event_type", "unknown")
    name = event.get("title", "Threat Intelligence Event")
    extensions = " ".join(f'{k}={v}' for k, v in event.get("extensions", {}).items())
    return f"CEF:0|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{sev}|{extensions}"


def _format_syslog_message(event: dict, fmt: str) -> str:
    if fmt == "cef":
        return _format_cef(event)
    elif fmt == "json":
        return json.dumps(event, ensure_ascii=False, default=str)
    else:
        timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())
        return f"<{1 * 8 + 5}>{timestamp} threat-intel-agent {event.get('event_type', 'unknown')} {json.dumps(event, ensure_ascii=False, default=str)}"


async def send_syslog(config: SyslogConfig, event: dict) -> bool:
    message = _format_syslog_message(event, config.format)
    try:
        if config.protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.sendto(message.encode("utf-8"), (config.host, config.port))
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((config.host, config.port))
            sock.sendall(message.encode("utf-8"))
            sock.close()
        logger.info(f"Syslog message sent to {config.host}:{config.port}")
        return True
    except Exception as exc:
        logger.error(f"Syslog delivery failed: {exc}")
        return False
