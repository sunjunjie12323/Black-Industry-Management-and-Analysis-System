import asyncio
import shutil
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from loguru import logger


_startup_completed: Dict[str, bool] = {"flag": False}
_startup_completed_at: Optional[float] = None
_subsystem_status: Dict[str, Dict[str, Any]] = {}


def mark_startup_complete() -> None:
    global _startup_completed_at
    _startup_completed["flag"] = True
    _startup_completed_at = time.time()
    logger.info("Startup marked complete")


def is_startup_complete() -> bool:
    return bool(_startup_completed["flag"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _measure(coro_factory) -> Dict[str, Any]:
    started_at = _now_iso()
    t0 = time.perf_counter()
    try:
        result = await coro_factory()
        if asyncio.iscoroutine(result):
            result = await result
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        if isinstance(result, dict):
            result.setdefault("latency_ms", latency_ms)
            result.setdefault("last_error", None)
            result.setdefault("last_check", started_at)
            return result
        return {
            "status": "ok" if result else "unavailable",
            "latency_ms": latency_ms,
            "last_error": None,
            "last_check": started_at,
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        logger.debug(f"Subsystem check failed: {exc}")
        return {
            "status": "unhealthy",
            "latency_ms": latency_ms,
            "last_error": str(exc)[:200],
            "last_check": started_at,
        }


async def _check_database() -> Dict[str, Any]:
    async def _do():
        from app.db.database import check_db_connection
        ok = await check_db_connection()
        if not ok:
            return {"status": "unhealthy", "error": "connection_refused"}
        return {"status": "healthy"}
    return await _measure(_do)


async def _check_redis() -> Dict[str, Any]:
    async def _do():
        from app.core.cache_service import cache_service
        if not cache_service.is_redis:
            return {"status": "degraded", "mode": "memory"}
        try:
            r = cache_service._cache._redis
            if r is None:
                return {"status": "unhealthy", "error": "redis_client_missing"}
            await asyncio.wait_for(r.ping(), timeout=2.0)
            return {"status": "healthy", "mode": "redis"}
        except Exception as exc:
            return {"status": "unhealthy", "error": str(exc)[:200]}
    return await _measure(_do)


async def _check_disk() -> Dict[str, Any]:
    async def _do():
        usage = shutil.disk_usage(".")
        free_pct = (usage.free / usage.total) * 100 if usage.total else 0
        status = "healthy" if free_pct > 5.0 else "unhealthy"
        return {
            "status": status,
            "free_pct": round(free_pct, 2),
            "free_gb": round(usage.free / (1024 ** 3), 2),
        }
    return await _measure(_do)


async def _check_memory() -> Dict[str, Any]:
    async def _do():
        try:
            import psutil
            vm = psutil.virtual_memory()
            available_mb = vm.available / (1024 * 1024)
            status = "healthy" if available_mb > 100 else "unhealthy"
            return {
                "status": status,
                "available_mb": round(available_mb, 2),
                "percent_used": vm.percent,
            }
        except ImportError:
            return {"status": "degraded", "note": "psutil not installed"}
    return await _measure(_do)


async def _check_llm(request: Request) -> Dict[str, Any]:
    async def _do():
        llm = getattr(request.app.state, "llm", None)
        if llm is None:
            return {"status": "degraded", "note": "llm not initialized"}
        cb = getattr(llm, "circuit_breaker_state", "closed")
        if cb == "open":
            return {"status": "unhealthy", "circuit_breaker": cb}
        if cb == "half_open":
            return {"status": "degraded", "circuit_breaker": cb}
        return {"status": "healthy", "circuit_breaker": cb}
    return await _measure(_do)


async def _check_background_workers(request: Request) -> Dict[str, Any]:
    async def _do():
        ac = getattr(request.app.state, "auto_collector", None)
        running = bool(ac and getattr(ac, "is_running", False))
        scheduler = getattr(request.app.state, "scheduler", None)
        scheduler_running = bool(scheduler and getattr(scheduler, "_running", False))
        if running and scheduler_running:
            return {"status": "healthy", "auto_collector": True, "scheduler": True}
        if not running and not scheduler_running:
            return {"status": "unhealthy", "auto_collector": False, "scheduler": False}
        return {
            "status": "degraded",
            "auto_collector": running,
            "scheduler": scheduler_running,
        }
    return await _measure(_do)


async def _collect_subsystem_status(request: Request) -> Dict[str, Dict[str, Any]]:
    checks = await asyncio.gather(
        _check_database(),
        _check_redis(),
        _check_disk(),
        _check_memory(),
        _check_llm(request),
        _check_background_workers(request),
        return_exceptions=True,
    )
    names = ["database", "redis", "disk", "memory", "llm", "background_workers"]
    out: Dict[str, Dict[str, Any]] = {}
    for name, res in zip(names, checks):
        if isinstance(res, Exception):
            out[name] = {
                "status": "unhealthy",
                "latency_ms": 0.0,
                "last_error": str(res)[:200],
                "last_check": _now_iso(),
            }
        else:
            out[name] = res
    return out


def _aggregate_overall(statuses: Dict[str, Dict[str, Any]]) -> str:
    weights = {"unhealthy": 2, "degraded": 1, "healthy": 0, "unknown": 1}
    score = 0
    for subsystem, info in statuses.items():
        s = info.get("status", "unknown")
        if s in ("degraded",) and subsystem in ("llm", "redis", "background_workers"):
            s = "healthy"
        if s == "unhealthy":
            return "unhealthy"
        if weights.get(s, 0) > score:
            score = weights.get(s, 0)
    return "healthy" if score == 0 else ("degraded" if score <= 1 else "unhealthy")


def register_health_endpoints(app: FastAPI) -> None:

    @app.get("/health/live", tags=["health"], include_in_schema=False)
    async def liveness():
        return {
            "status": "alive",
            "timestamp": _now_iso(),
            "uptime_seconds": round(time.time() - (app.state.start_time if hasattr(app.state, "start_time") else time.time()), 2),
        }

    @app.get("/health/ready", tags=["health"], include_in_schema=False)
    async def readiness(request: Request):
        statuses = await _collect_subsystem_status(request)
        ready_reasons: List[str] = []
        critical = ("database",)
        for k in critical:
            if statuses.get(k, {}).get("status") in ("unhealthy", "unknown"):
                ready_reasons.append(f"{k}_unavailable")
        if ready_reasons:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "timestamp": _now_iso(),
                    "reasons": ready_reasons,
                    "checks": statuses,
                },
            )
        return {"status": "ready", "timestamp": _now_iso(), "checks": statuses}

    @app.get("/health/startup", tags=["health"], include_in_schema=False)
    async def startup():
        if is_startup_complete():
            return {
                "status": "started",
                "timestamp": _now_iso(),
                "started_at": datetime.fromtimestamp(_startup_completed_at, tz=timezone.utc).isoformat() if _startup_completed_at else None,
            }
        return JSONResponse(
            status_code=503,
            content={"status": "starting", "timestamp": _now_iso()},
        )

    @app.get("/health/full", tags=["health"], include_in_schema=False)
    async def health_full(request: Request):
        statuses = await _collect_subsystem_status(request)
        overall = _aggregate_overall(statuses)
        status_code = 200 if overall in ("healthy", "degraded") else 503
        return JSONResponse(
            status_code=status_code,
            content={
                "status": overall,
                "timestamp": _now_iso(),
                "started": is_startup_complete(),
                "checks": statuses,
            },
        )
