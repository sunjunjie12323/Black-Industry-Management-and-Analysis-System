import asyncio
import shutil
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from loguru import logger
from sqlalchemy import event, text
from sqlalchemy.engine import Engine

from app.config import settings


_query_metrics: Dict[str, Dict[str, Any]] = {
    "total_queries": 0,
    "slow_queries": 0,
    "by_table": {},
    "slow_query_log": [],
    "last_reset": time.time(),
}

RETENTION_DEFAULTS: Dict[str, int] = {
    "audit_log": 180,
    "raw_intelligence": 365,
    "cleaned_intelligence": 365,
    "analyzed_intelligence": 365,
    "task_executions": 30,
    "system_metrics": 14,
    "api_request_metrics": 7,
}

SLOW_QUERY_THRESHOLD_MS = 500.0
SLOW_QUERY_KEEP = 200


def init_query_metrics() -> None:
    _query_metrics["total_queries"] = 0
    _query_metrics["slow_queries"] = 0
    _query_metrics["by_table"] = {}
    _query_metrics["slow_query_log"] = []
    _query_metrics["last_reset"] = time.time()


def get_query_metrics() -> Dict[str, Any]:
    elapsed = max(time.time() - _query_metrics["last_reset"], 1.0)
    total = _query_metrics["total_queries"]
    return {
        "total_queries": total,
        "slow_queries": _query_metrics["slow_queries"],
        "qps": round(total / elapsed, 3),
        "by_table": dict(_query_metrics["by_table"]),
        "slow_query_log": list(_query_metrics["slow_query_log"][-50:]),
    }


def _record_table(table: Optional[str], elapsed_ms: float) -> None:
    if not table:
        table = "<unknown>"
    stats = _query_metrics["by_table"].setdefault(table, {"count": 0, "total_ms": 0.0, "max_ms": 0.0})
    stats["count"] += 1
    stats["total_ms"] = round(stats["total_ms"] + elapsed_ms, 3)
    stats["max_ms"] = round(max(stats["max_ms"], elapsed_ms), 3)
    if elapsed_ms > SLOW_QUERY_THRESHOLD_MS:
        _query_metrics["slow_queries"] += 1
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "table": table,
            "elapsed_ms": round(elapsed_ms, 3),
        }
        _query_metrics["slow_query_log"].append(entry)
        if len(_query_metrics["slow_query_log"]) > SLOW_QUERY_KEEP:
            del _query_metrics["slow_query_log"][: len(_query_metrics["slow_query_log"]) - SLOW_QUERY_KEEP]
        logger.warning(f"Slow query: table={table} elapsed_ms={elapsed_ms:.2f}")


def _make_listener() -> Any:
    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        context._query_start_time = time.perf_counter()
        context._query_table = _extract_table_name(statement)

    def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        start = getattr(context, "_query_start_time", None)
        table = getattr(context, "_query_table", None)
        if start is None:
            return
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        _query_metrics["total_queries"] += 1
        _record_table(table, elapsed_ms)

    return before_cursor_execute, after_cursor_execute


def _extract_table_name(statement: str) -> Optional[str]:
    if not statement:
        return None
    s = statement.strip().lower()
    if s.startswith("select"):
        marker = "from "
    elif s.startswith(("insert", "update", "delete")):
        marker = "into " if s.startswith("insert") else ("from " if s.startswith("delete") else "update ")
    else:
        return None
    idx = s.find(marker)
    if idx < 0:
        return None
    rest = s[idx + len(marker):].lstrip()
    parts = rest.split(None, 1)
    if not parts:
        return None
    name = parts[0].strip('"`[]')
    if "." in name:
        name = name.split(".")[-1]
    return name.strip("`\"[]") or None


def slow_query_logger_setup() -> None:
    try:
        engine: Engine = settings.engine  # type: ignore[attr-defined]
    except AttributeError:
        from app.db.database import engine as db_engine
        engine = db_engine

    before, after = _make_listener()
    event.listen(engine.sync_engine, "before_cursor_execute", before)
    event.listen(engine.sync_engine, "after_cursor_execute", after)
    logger.info("Slow query logger installed (threshold: 500ms)")


def setup_sqlite_wal() -> None:
    from app.db.database import engine as db_engine
    if not db_engine.dialect.name.startswith("sqlite"):
        return
    try:
        with db_engine.sync_engine.begin() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.execute(text("PRAGMA synchronous=NORMAL"))
            conn.execute(text("PRAGMA busy_timeout=30000"))
            conn.execute(text("PRAGMA foreign_keys=ON"))
            conn.execute(text("PRAGMA temp_store=MEMORY"))
        logger.info("SQLite WAL mode enabled, busy_timeout=30s, foreign_keys=ON")
    except Exception as exc:
        logger.warning(f"Failed to enable SQLite WAL: {exc}")


async def _prune_table(db_session_factory: Any, table: str, days: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    try:
        async with db_session_factory() as session:
            result = await session.execute(
                text(f"DELETE FROM {table} WHERE created_at < :cutoff"),
                {"cutoff": cutoff},
            )
            await session.commit()
            return result.rowcount or 0
    except Exception as exc:
        logger.debug(f"Prune {table} failed: {exc}")
        return 0


async def retention_prune_loop() -> None:
    from app.db.database import async_session_factory
    while True:
        try:
            await asyncio.sleep(24 * 60 * 60)
            logger.info("Retention prune starting...")
            total = 0
            for table, days in RETENTION_DEFAULTS.items():
                try:
                    deleted = await _prune_table(async_session_factory, table, days)
                    if deleted:
                        logger.info(f"Retention prune: {table} deleted={deleted} older_than={days}d")
                    total += deleted
                except Exception as exc:
                    logger.warning(f"Retention prune failed for {table}: {exc}")
            logger.info(f"Retention prune complete: total_deleted={total}")
        except asyncio.CancelledError:
            return
        except Exception as exc:
            logger.error(f"Retention prune loop error: {exc}")
            await asyncio.sleep(3600)


def check_disk_space(path: str = "/") -> Dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
        free_pct = (usage.free / usage.total) * 100 if usage.total else 0
        healthy = free_pct > 5.0
        return {
            "status": "healthy" if healthy else "unhealthy",
            "free_pct": round(free_pct, 2),
            "free_bytes": usage.free,
            "total_bytes": usage.total,
            "path": path,
        }
    except Exception as exc:
        return {"status": "unhealthy", "error": str(exc)}


def check_memory() -> Dict[str, Any]:
    try:
        import psutil
        vm = psutil.virtual_memory()
        available_mb = vm.available / (1024 * 1024)
        return {
            "status": "healthy" if available_mb > 100 else "unhealthy",
            "available_mb": round(available_mb, 2),
            "total_mb": round(vm.total / (1024 * 1024), 2),
            "percent_used": vm.percent,
        }
    except ImportError:
        try:
            with open("/proc/meminfo", "r") as f:
                lines = f.readlines()
            mem_info: Dict[str, int] = {}
            for line in lines:
                if ":" in line:
                    key, val = line.split(":", 1)
                    mem_info[key.strip()] = int(val.strip().split()[0]) * 1024
            available_mb = mem_info.get("MemAvailable", 0) / (1024 * 1024)
            return {
                "status": "healthy" if available_mb > 100 else "unhealthy",
                "available_mb": round(available_mb, 2),
            }
        except Exception as exc:
            return {"status": "unknown", "error": str(exc)}
    except Exception as exc:
        return {"status": "unhealthy", "error": str(exc)}
