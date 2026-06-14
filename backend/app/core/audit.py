import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union
from uuid import uuid4

from loguru import logger
from sqlalchemy import Index
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import async_session_factory
from app.db.tables import AuditLogTable


_audit_logger = logger.bind(name="audit")


_AUDIT_QUEUE_MAX = 1000
_audit_queue: asyncio.Queue = None  # type: ignore[assignment]
_worker_task: Optional[asyncio.Task] = None


def _serialize_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _normalize_details(details: Optional[Union[Dict[str, Any], str]]) -> Optional[str]:
    if details is None:
        return None
    if isinstance(details, str):
        return details
    try:
        return json.dumps(details, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(details)


def _build_entry(
    action: str,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    status: str = "success",
    details: Optional[Union[Dict[str, Any], str]] = None,
) -> Dict[str, Any]:
    resource = None
    if resource_type and resource_id is not None:
        resource = f"{resource_type}:{resource_id}"
    elif resource_type:
        resource = resource_type
    return {
        "id": uuid4().hex,
        "user_id": user_id,
        "username": username,
        "action": action,
        "resource": resource,
        "resource_type": resource_type,
        "resource_id": resource_id if resource_id is not None else None,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "request_id": request_id,
        "status": status,
        "detail": _normalize_details(details),
        "created_at": datetime.now(timezone.utc).replace(tzinfo=None),
    }


async def _persist_entry_async(entry: Dict[str, Any]) -> None:
    try:
        async with async_session_factory() as session:
            row = AuditLogTable(
                id=entry["id"],
                user_id=entry.get("user_id"),
                username=entry.get("username"),
                action=entry["action"],
                resource=entry.get("resource"),
                detail=entry.get("detail"),
                ip_address=entry.get("ip_address"),
                user_agent=entry.get("user_agent"),
                created_at=entry.get("created_at") or datetime.now(timezone.utc).replace(tzinfo=None),
            )
            session.add(row)
            await session.commit()
    except SQLAlchemyError as exc:
        _audit_logger.warning(f"Audit log SQL error: {exc}")
    except Exception as exc:
        _audit_logger.warning(f"Audit log persist failed: {exc}")


def _enqueue_or_persist(entry: Dict[str, Any]) -> None:
    global _audit_queue, _worker_task
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        _audit_logger.warning("No running event loop; audit log dropped")
        return

    if _audit_queue is None:
        _audit_queue = asyncio.Queue(maxsize=_AUDIT_QUEUE_MAX)
        _worker_task = loop.create_task(_audit_worker())

    try:
        _audit_queue.put_nowait(entry)
    except asyncio.QueueFull:
        _audit_logger.warning("Audit queue full, scheduling inline task")
        loop.create_task(_persist_entry_async(entry))


async def _audit_worker() -> None:
    global _audit_queue
    while True:
        try:
            entry = await _audit_queue.get()
        except asyncio.CancelledError:
            return
        try:
            await _persist_entry_async(entry)
        except Exception as exc:
            _audit_logger.warning(f"Audit worker error: {exc}")
        finally:
            _audit_queue.task_done()


async def audit_log_async(
    action: str,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    status: str = "success",
    details: Optional[Union[Dict[str, Any], str]] = None,
    db_session: Optional[AsyncSession] = None,
) -> None:
    entry = _build_entry(
        action=action,
        user_id=user_id,
        username=username,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        status=status,
        details=details,
    )

    if db_session is not None:
        try:
            row = AuditLogTable(
                id=entry["id"],
                user_id=entry.get("user_id"),
                username=entry.get("username"),
                action=entry["action"],
                resource=entry.get("resource"),
                detail=entry.get("detail"),
                ip_address=entry.get("ip_address"),
                user_agent=entry.get("user_agent"),
                created_at=entry.get("created_at"),
            )
            db_session.add(row)
        except SQLAlchemyError as exc:
            _audit_logger.warning(f"Audit log add failed: {exc}")
        return

    _enqueue_or_persist(entry)


def audit_log(
    action: str,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    status: str = "success",
    details: Optional[Union[Dict[str, Any], str]] = None,
) -> None:
    entry = _build_entry(
        action=action,
        user_id=user_id,
        username=username,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        status=status,
        details=details,
    )
    _enqueue_or_persist(entry)


def ensure_extended_columns_sync() -> None:
    """Ensure extended columns (request_id, status, resource_type, resource_id) exist on existing audit_log table."""
    from sqlalchemy import text, inspect
    from app.db.database import engine as _engine
    try:
        insp = inspect(_engine.sync_engine)
        existing = {c["name"] for c in insp.get_columns("audit_log")}
    except Exception:
        return
    stmts = []
    if "request_id" not in existing:
        stmts.append("ALTER TABLE audit_log ADD COLUMN request_id VARCHAR(64)")
        stmts.append("CREATE INDEX IF NOT EXISTS ix_audit_log_request_id ON audit_log(request_id)")
    if "status" not in existing:
        stmts.append("ALTER TABLE audit_log ADD COLUMN status VARCHAR(16) DEFAULT 'success'")
    if "resource_type" not in existing:
        stmts.append("ALTER TABLE audit_log ADD COLUMN resource_type VARCHAR(64)")
    if "resource_id" not in existing:
        stmts.append("ALTER TABLE audit_log ADD COLUMN resource_id VARCHAR(128)")
    if not stmts:
        return
    try:
        with _engine.sync_engine.begin() as conn:
            for stmt in stmts:
                try:
                    conn.execute(text(stmt))
                except Exception:
                    pass
    except Exception as exc:
        logger.debug(f"AuditLog column migration skipped: {exc}")


def ensure_audit_indexes() -> None:
    """Create additional indexes for AuditLogTable to support new columns. No-op if columns don't exist."""
    try:
        with async_session_factory().sync_engine.begin():  # type: ignore[attr-defined]
            Index("ix_audit_log_request_id", AuditLogTable.__table__.c.get("request_id"))  # type: ignore[arg-type]
    except Exception:
        pass
