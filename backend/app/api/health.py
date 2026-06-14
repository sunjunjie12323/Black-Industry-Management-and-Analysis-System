import os
import platform
import shutil
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from loguru import logger

router = APIRouter()


async def _check_database(request: Request = None) -> dict:
    try:
        from app.db.database import check_db_connection
        t0 = time.monotonic()
        ok = await check_db_connection()
        latency_ms = round((time.monotonic() - t0) * 1000, 2)
        return {"status": "ok" if ok else "unavailable", "latency_ms": latency_ms}
    except Exception as exc:
        logger.warning(f"Health check database failed: {exc}")
        return {"status": "unavailable", "error": str(exc)[:200]}


async def _check_llm(request: Request) -> dict:
    llm = getattr(request.app.state, "llm", None)
    if llm is None:
        return {"status": "unavailable", "error": "LLM service not initialized"}
    api_key = getattr(llm, "_api_key", None)
    if not api_key:
        return {"status": "unavailable", "error": "LLM API key not configured"}
    cb_state = llm.circuit_breaker_state
    return {
        "status": "ok" if cb_state == "closed" else "degraded" if cb_state == "half_open" else "unavailable",
        "circuit_breaker": cb_state,
        "api_key_configured": True,
        "model": llm.model_name,
        "request_count": llm._request_count,
        "total_tokens": llm._total_tokens,
    }


async def _check_vector_store(request: Request) -> dict:
    vs = getattr(request.app.state, "vector_store", None)
    if vs is None:
        return {"status": "unavailable", "error": "VectorStore not initialized"}
    try:
        counts = {}
        for name in vs.COLLECTION_NAMES:
            counts[name] = await vs.count(name)
        return {"status": "ok", "collections": counts}
    except Exception as exc:
        logger.warning(f"Health check vector store failed: {exc}")
        return {"status": "degraded", "error": str(exc)[:200]}


async def _check_knowledge_graph(request: Request) -> dict:
    kg = getattr(request.app.state, "knowledge_graph", None)
    if kg is None:
        return {"status": "unavailable", "error": "KnowledgeGraph not initialized"}
    try:
        return {
            "status": "ok",
            "entities": kg.graph.number_of_nodes(),
            "relations": kg.graph.number_of_edges(),
        }
    except Exception as exc:
        logger.warning(f"Health check knowledge graph failed: {exc}")
        return {"status": "degraded", "error": str(exc)[:200]}


async def _check_cache(request: Request) -> dict:
    cs = getattr(request.app.state, "cache_service", None)
    if cs is None:
        return {"status": "unavailable", "error": "CacheService not initialized"}
    try:
        mode = "redis" if cs.is_redis else "memory"
        if cs.is_redis:
            try:
                r = cs._cache._redis
                if r:
                    await r.ping()
                    return {"status": "ok", "mode": mode}
                return {"status": "degraded", "mode": mode, "error": "Redis client not connected"}
            except Exception as exc:
                return {"status": "degraded", "mode": mode, "error": str(exc)[:200]}
        return {"status": "ok", "mode": mode}
    except Exception as exc:
        logger.warning(f"Health check cache failed: {exc}")
        return {"status": "degraded", "error": str(exc)[:200]}


async def _check_auto_collector(request: Request) -> dict:
    ac = getattr(request.app.state, "auto_collector", None)
    if ac is None:
        return {"status": "unavailable", "error": "AutoCollector not initialized"}
    try:
        running = ac.is_running
        return {"status": "ok" if running else "stopped", "is_running": running}
    except Exception as exc:
        return {"status": "degraded", "error": str(exc)[:200]}


def _check_disk_space() -> dict:
    try:
        usage = shutil.disk_usage(".")
        total_gb = round(usage.total / (1024 ** 3), 2)
        used_gb = round(usage.used / (1024 ** 3), 2)
        free_gb = round(usage.free / (1024 ** 3), 2)
        percent = round(usage.used / usage.total * 100, 1)
        return {
            "status": "ok" if percent < 90 else "warning" if percent < 95 else "critical",
            "total_gb": total_gb,
            "used_gb": used_gb,
            "free_gb": free_gb,
            "usage_percent": percent,
        }
    except Exception as exc:
        return {"status": "unknown", "error": str(exc)[:200]}


def _check_memory() -> dict:
    try:
        import psutil
        mem = psutil.virtual_memory()
        return {
            "status": "ok" if mem.percent < 85 else "warning" if mem.percent < 95 else "critical",
            "total_mb": round(mem.total / (1024 ** 2), 2),
            "used_mb": round(mem.used / (1024 ** 2), 2),
            "available_mb": round(mem.available / (1024 ** 2), 2),
            "usage_percent": mem.percent,
        }
    except ImportError:
        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            return {
                "status": "unknown",
                "note": "psutil not installed",
                "ru_maxrss_mb": round(usage.ru_maxrss / 1024, 2),
            }
        except ImportError:
            return {
                "status": "unknown",
                "note": "psutil not installed, resource module unavailable",
            }
    except Exception as exc:
        return {"status": "unknown", "error": str(exc)[:200]}


@router.get("/health")
async def health_check(request: Request):
    checks = {}
    overall = "healthy"

    db_check = await _check_database(request)
    checks["database"] = db_check
    checks["llm"] = await _check_llm(request)
    checks["vector_store"] = await _check_vector_store(request)
    checks["knowledge_graph"] = await _check_knowledge_graph(request)
    checks["cache"] = await _check_cache(request)
    checks["auto_collector"] = await _check_auto_collector(request)
    checks["disk"] = _check_disk_space()
    checks["memory"] = _check_memory()

    for name, result in checks.items():
        status = result.get("status", "unknown")
        if name in ("llm", "vector_store", "knowledge_graph", "cache", "auto_collector") and status in ("unavailable", "stopped"):
            if overall == "healthy":
                overall = "degraded"
            continue
        if status in ("unavailable", "critical"):
            overall = "unhealthy"
            break
        if status in ("degraded", "warning", "stopped") and overall == "healthy":
            overall = "degraded"

    services = {k: v for k, v in checks.items() if k not in ("disk", "memory")}
    status_code = 200 if overall in ("healthy", "degraded") else 503

    return JSONResponse(
        status_code=status_code,
        content={
            "status": overall,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "2.3.0",
            "environment": os.environ.get("APP_ENV", "development"),
            "database": db_check.get("status", "unknown"),
            "services": services,
            "checks": checks,
        },
    )


@router.get("/health/live")
async def liveness():
    return {"status": "alive"}


@router.get("/health/ready")
async def readiness(request: Request):
    db_ok = False
    try:
        from app.db.database import check_db_connection
        db_ok = await check_db_connection()
    except Exception:
        pass

    llm_ok = False
    llm = getattr(request.app.state, "llm", None)
    if llm is not None:
        cb = llm.circuit_breaker_state
        llm_ok = cb in ("closed", "half_open")

    if db_ok and llm_ok:
        return {"status": "ready"}
    reasons = []
    if not db_ok:
        reasons.append("database_unavailable")
    if not llm_ok:
        reasons.append("llm_unavailable")
    return JSONResponse(
        status_code=503,
        content={"status": "not_ready", "reasons": reasons},
    )
