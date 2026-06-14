import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiofiles
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from app.core.health import register_health_endpoints
from loguru import logger

from app.api import api_router
from app.api.export import export_router
from app.api.health import router as health_router
from app.api.ws import ws_router
from app.config import settings
from app.core.audit import ensure_extended_columns_sync
from app.core.audit_middleware import audit_log_middleware
from app.core.auth import cleanup_expired_blacklisted_tokens, get_user_by_id
from app.core.cache_service import cache_service
from app.core.db_performance import (
    init_query_metrics,
    retention_prune_loop,
    setup_sqlite_wal,
    slow_query_logger_setup,
)
from app.core.error_handlers import register_exception_handlers
from app.core.exceptions import AppException
from app.core.metrics import APP_INFO, metrics_endpoint
from app.core.metrics_middleware import PrometheusMiddleware
from app.core.tenant_middleware import TenantMiddleware
from app.core.task_queue import task_queue
from app.db.database import engine as db_engine, init_db
from app.middleware import (
    CSRFMiddleware,
    MetricsState,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
    metrics_state,
    rate_limit_middleware,
    request_id_ctx,
)
from app.service_registry import initialize_services
from app.websocket import manager

logger = logger.patch(
    lambda record: record["extra"].update(request_id=request_id_ctx.get())
)


_audit_log_dir = Path("./logs")
_audit_log_dir.mkdir(parents=True, exist_ok=True)
_audit_logger = logger.bind(name="audit")
_audit_logger.add(
    str(_audit_log_dir / "audit.log"),
    rotation="10 MB",
    retention="30 days",
    compression="gz",
    format="{time:YYYY-MM-DD HH:mm:ss.SSS} | request_id={extra[request_id]} | {message}",
    filter=lambda record: record["extra"].get("name") == "audit",
)
_request_audit_logger = logger.bind(name="audit_request")
_request_audit_logger.add(
    str(_audit_log_dir / "request_audit.log"),
    rotation="10 MB",
    retention="30 days",
    compression="gz",
    format="{time:YYYY-MM-DD HH:mm:ss.SSS} | request_id={extra[request_id]} | {message}",
    filter=lambda record: record["extra"].get("name") == "audit_request",
)

_backup_task_handle: asyncio.Task | None = None
_cleanup_task_handle: asyncio.Task | None = None
_retention_task_handle: asyncio.Task | None = None
_scheduler = None
_shutting_down = False
_inflight_requests = 0
_inflight_lock = asyncio.Lock()
_max_upload_size_bytes: int = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
_allowed_cors_headers: list[str] = [
    "Authorization",
    "Content-Type",
    "X-CSRF-Token",
    "X-Request-ID",
    "X-Tenant-ID",
    "X-API-Key",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
    "X-Total-Count",
]
_cors_exposed_headers: list[str] = [
    "X-Request-ID",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
    "X-Total-Count",
    "Retry-After",
]


async def _shutdown_services(app: FastAPI):
    logger.info("Shutting down services...")
    _stop_service(app, "auto_collector", lambda s: s.stop_auto_collection())
    _stop_async_service(app, "source_scheduler", lambda s: s.stop())
    _stop_service(app, "analysis_scheduler", lambda s: s.stop())

    try:
        await task_queue.stop()
        logger.info("Task queue stopped")
    except Exception as exc:
        logger.warning(f"Failed to stop task queue: {exc}")

    _stop_async_service(app, "cache_service", lambda s: s.close())
    _stop_async_service(app, "realtime_collector", lambda s: s.close())

    for name in ("telegram_collector", "forum_collector", "wechat_collector", "darkweb_collector", "commercial_collector"):
        collector = getattr(app.state, name, None)
        if collector and hasattr(collector, "close"):
            _stop_async_service(app, name, lambda s, c=collector: c.close())

    _stop_async_service(app, "knowledge_graph", lambda s: s.save())
    _stop_async_service(app, "intelligence_organism", lambda s: s.save_to_disk())
    try:
        await _save_provenance_chain(app)
    except Exception as exc:
        logger.warning(f"Failed to save provenance chain: {exc}")
    _stop_async_service(app, "vector_store", lambda s: s.persist())
    _stop_async_service(app, "llm", lambda s: s.close())

    try:
        from app.core.web_search import web_search_service
        await web_search_service.close()
        logger.info("WebSearchService client closed")
    except Exception as exc:
        logger.warning(f"Failed to close WebSearchService: {exc}")

    if hasattr(app.state, "finetune_worker"):
        try:
            for task_id in app.state.finetune_worker.get_active_task_ids():
                app.state.finetune_worker.cancel_training(task_id)
            logger.info("FinetuneWorker tasks cancelled")
        except Exception as exc:
            logger.warning(f"Failed to cancel FinetuneWorker tasks: {exc}")

    logger.info("All services shut down")


def _stop_service(app, name, stop_fn):
    svc = getattr(app.state, name, None)
    if svc:
        try:
            stop_fn(svc)
            logger.info(f"{name} stopped")
        except Exception as exc:
            logger.warning(f"Failed to stop {name}: {exc}")


def _stop_async_service(app, name, stop_fn):
    svc = getattr(app.state, name, None)
    if svc:
        try:
            asyncio.get_running_loop().create_task(_await_stop(name, svc, stop_fn))
        except RuntimeError:
            pass


async def _await_stop(name, svc, stop_fn):
    try:
        await stop_fn(svc)
        logger.info(f"{name} stopped")
    except Exception as exc:
        logger.warning(f"Failed to stop {name}: {exc}")


async def _save_provenance_chain(app):
    chain = getattr(app.state, "provenance_chain", None)
    if not chain:
        return
    try:
        persist_path = Path("./model_data/provenance")
        persist_path.mkdir(parents=True, exist_ok=True)
        data = {
            "chains": {k: [r.to_dict() for r in v] for k, v in chain._chains.items()},
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        tmp = persist_path / "provenance_state.tmp"
        async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
            await f.write(json.dumps(data, ensure_ascii=False, default=str))
        tmp.replace(persist_path / "provenance_state.json")
        logger.info("ProvenanceChain data saved")
    except Exception as exc:
        logger.warning(f"Failed to save ProvenanceChain data: {exc}")


async def _periodic_backup(app: FastAPI):
    import tarfile
    def _do_backup():
        backup_dir = Path("./backups")
        backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive_path = backup_dir / f"backup_{timestamp}.tar.gz"
        dirs_to_backup = ["./chroma_data", "./graph_data", "./model_data", "./economic_data"]
        db_path = Path("./threat_intel.db")
        with tarfile.open(str(archive_path), "w:gz") as tar:
            for dir_path in dirs_to_backup:
                p = Path(dir_path)
                if p.exists():
                    tar.add(str(p), arcname=p.name)
            if db_path.exists():
                tar.add(str(db_path), arcname=db_path.name)
        backups = sorted(backup_dir.glob("backup_*.tar.gz"))
        while len(backups) > settings.BACKUP_RETENTION_COUNT:
            oldest = backups.pop(0)
            oldest.unlink()
        return archive_path

    loop = asyncio.get_running_loop()
    while True:
        await asyncio.sleep(settings.BACKUP_INTERVAL_SECONDS)
        try:
            archive_path = await loop.run_in_executor(None, _do_backup)
            logger.info(f"Backup created: {archive_path}")
        except Exception as exc:
            logger.error(f"Backup task failed: {exc}")


async def _periodic_cleanup(app: FastAPI):
    while True:
        await asyncio.sleep(3600)
        try:
            cleaned = await cleanup_expired_blacklisted_tokens()
            if cleaned > 0:
                logger.info(f"Periodic cleanup: removed {cleaned} expired tokens")
            if hasattr(app.state, "cache_service"):
                cs = app.state.cache_service
                if hasattr(cs._cache, 'cleanup_expired'):
                    await cs._cache.cleanup_expired()
        except Exception as exc:
            logger.warning(f"Periodic cleanup failed: {exc}")


def _init_scheduler(app: FastAPI):
    from app.core.scheduler import TaskScheduler
    scheduler = TaskScheduler()

    async def _retention_sweep():
        retention_manager = getattr(app.state, "retention_manager", None)
        if not retention_manager:
            return
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            result = await retention_manager.run_retention_sweep(db_session=session)
            logger.info(f"Retention sweep: {result}")

    async def _sla_check():
        sla_definition = getattr(app.state, "sla_definition", None)
        if not sla_definition:
            return
        now = datetime.now(timezone.utc)
        start_date = (now - timedelta(hours=1)).strftime("%Y-%m-%d")
        end_date = now.strftime("%Y-%m-%d")
        report = sla_definition.check_sla_compliance(start_date, end_date)
        if report.violations:
            logger.warning(f"SLA violations detected: {report.violations}")

    async def _auto_backup():
        backup_manager = getattr(app.state, "backup_manager", None)
        if not backup_manager:
            return
        now = datetime.now(timezone.utc)
        backup_type = "full" if now.weekday() == 6 else "incremental"
        info = await backup_manager.create_backup(backup_type=backup_type)
        logger.info(f"Auto backup completed: id={info.backup_id}, type={backup_type}, status={info.status}")

    async def _billing_snapshot():
        billing_engine = getattr(app.state, "billing_engine", None)
        if not billing_engine:
            return
        now = datetime.now(timezone.utc)
        period = now.strftime("%Y-%m-%d")
        for tenant_id in billing_engine._tenant_plans:
            try:
                billing_engine.record_usage(
                    tenant_id=tenant_id,
                    resource_type="api_call",
                    amount=0,
                    metadata={"snapshot": True, "timestamp": now.isoformat()},
                )
            except Exception as exc:
                logger.debug(f"Billing snapshot for {tenant_id} failed: {exc}")

    async def _worm_log_rotation():
        worm_logger = getattr(app.state, "worm_logger", None)
        if not worm_logger:
            return
        try:
            current_file = getattr(worm_logger, "_current_file", None)
            if current_file:
                from pathlib import Path as _P
                p = _P(current_file) if isinstance(current_file, str) else current_file
                if p.exists() and p.stat().st_size > 100 * 1024 * 1024:
                    if hasattr(worm_logger, "rotate"):
                        worm_logger.rotate()
                        logger.info("WORM log rotated: file exceeded 100MB")
        except Exception as exc:
            logger.warning(f"WORM log rotation check failed: {exc}")

    async def _source_credibility_update():
        credibility_tracker = getattr(app.state, "credibility_tracker", None)
        if not credibility_tracker:
            return
        try:
            from app.db.database import async_session_factory
            from sqlalchemy import select
            from app.db.tables import RawIntelligenceTable, AnalyzedIntelligenceTable
            async with async_session_factory() as session:
                raw_result = await session.execute(
                    select(RawIntelligenceTable).limit(100)
                )
                raw_items = raw_result.scalars().all()
                for item in raw_items:
                    source = item.source or "unknown"
                    was_accurate = True
                    if item.metadata_json:
                        try:
                            meta = json.loads(item.metadata_json)
                            confidence = meta.get("confidence", 0.8)
                            was_accurate = confidence >= 0.6
                        except (json.JSONDecodeError, TypeError):
                            pass
                    credibility_tracker.update_credibility(source, was_accurate)
            logger.info("Source credibility scores updated from recent intelligence")
        except Exception as exc:
            logger.warning(f"Source credibility update failed: {exc}")

    scheduler.add_task("retention_sweep", "0 2 * * *", _retention_sweep)
    scheduler.add_task("sla_compliance_check", "0 * * * *", _sla_check)
    scheduler.add_task("auto_backup", "0 3 * * *", _auto_backup)
    scheduler.add_task("billing_snapshot", "0 * * * *", _billing_snapshot)
    scheduler.add_task("worm_log_rotation", "0 0 * * *", _worm_log_rotation)
    scheduler.add_task("source_credibility_update", "0 4 * * *", _source_credibility_update)

    return scheduler


async def _drain_inflight_requests(timeout: float = 30.0) -> int:
    global _inflight_requests
    deadline = asyncio.get_event_loop().time() + timeout
    while _inflight_requests > 0 and asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.1)
    return _inflight_requests


async def _shutdown_app(app: FastAPI) -> None:
    global _shutting_down
    _shutting_down = True
    logger.info(f"Graceful shutdown: draining {_inflight_requests} in-flight request(s) (timeout=30s)")
    remaining = await _drain_inflight_requests(timeout=30.0)
    if remaining > 0:
        logger.warning(f"Shutdown timeout reached with {remaining} in-flight request(s) still active")
    else:
        logger.info("All in-flight requests drained")


@asynccontextmanager
async def lifespan(app: FastAPI):
    shutdown_start = time.time()
    logger.info("Starting Threat Intel Agent backend...")
    await init_db()
    ensure_extended_columns_sync()
    setup_sqlite_wal()
    init_query_metrics()
    slow_query_logger_setup()
    logger.info("Database initialized successfully")

    if not settings.is_production and settings.SEED_DATABASE:
        try:
            from app.db.seed import fix_seed_sources, seed_from_real_data
            await fix_seed_sources()
            await asyncio.wait_for(seed_from_real_data(), timeout=15.0)
        except asyncio.TimeoutError:
            logger.warning("Seed from real data timed out (15s), skipping.")
        except Exception as exc:
            logger.warning(f"Seed operations skipped: {exc}")

        try:
            from app.db.seed_new_tables import seed_new_tables
            await asyncio.wait_for(seed_new_tables(), timeout=15.0)
        except asyncio.TimeoutError:
            logger.warning("Database seeding timed out - some seed data may be missing")
        except Exception as exc:
            logger.warning(f"Database seeding failed: {exc} - some seed data may be missing")
    elif settings.is_production:
        logger.info("Production environment detected — skipping seed data injection")
    else:
        logger.info("SEED_DATABASE is not enabled, skipping seed operations")

    try:
        from sqlalchemy import select, func
        from app.db.tables import RawIntelligenceTable
        from app.core.seed_data import load_seed_data
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            count_result = await session.execute(select(func.count(RawIntelligenceTable.id)))
            current_count = count_result.scalar() or 0
            if current_count == 0:
                inserted = await load_seed_data(session)
                logger.info(f"Initial seed of CISA KEV dataset: inserted {inserted} records")
            else:
                logger.info(f"Raw intelligence already populated ({current_count} rows); skipping initial seed")
    except Exception as exc:
        logger.warning(f"Initial seed load skipped: {exc}")

    await initialize_services(app)
    logger.info("All services initialized successfully")

    try:
        await cache_service.warm_critical()
    except Exception as exc:
        logger.warning(f"Cache warm failed: {exc}")

    auto_collector = getattr(app.state, "auto_collector", None)
    if auto_collector is not None and hasattr(auto_collector, "start_flush_worker"):
        try:
            await auto_collector.start_flush_worker()
        except Exception as exc:
            logger.warning(f"AutoCollector flush worker start failed: {exc}")

    from app.core.tracing import setup_tracing
    setup_tracing(app, db_engine)

    APP_INFO.info({
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "python_version": f"{__import__('sys').version_info.major}.{__import__('sys').version_info.minor}",
    })

    global _backup_task_handle, _cleanup_task_handle, _retention_task_handle, _scheduler
    _backup_task_handle = asyncio.create_task(_periodic_backup(app))
    _cleanup_task_handle = asyncio.create_task(_periodic_cleanup(app))
    _retention_task_handle = asyncio.create_task(retention_prune_loop())
    logger.info("Background tasks started: backup (6h), cleanup (1h), retention-prune (24h)")

    _scheduler = _init_scheduler(app)
    _scheduler.start()
    logger.info(f"TaskScheduler started with {len(_scheduler._tasks)} scheduled tasks")

    try:
        yield
    finally:
        await _shutdown_app(app)

        if _scheduler:
            try:
                await asyncio.wait_for(_scheduler.stop(), timeout=10.0)
            except asyncio.TimeoutError:
                logger.warning("TaskScheduler stop timed out")
            logger.info("TaskScheduler stopped")

        for handle in (_backup_task_handle, _cleanup_task_handle, _retention_task_handle):
            if handle:
                handle.cancel()
                try:
                    await handle
                except asyncio.CancelledError:
                    pass
                except Exception as exc:
                    logger.warning(f"Background task error during shutdown: {exc}")
        logger.info("Background tasks cancelled")

        if auto_collector is not None and hasattr(auto_collector, "stop_flush_worker"):
            try:
                await asyncio.wait_for(auto_collector.stop_flush_worker(), timeout=10.0)
            except asyncio.TimeoutError:
                logger.warning("AutoCollector flush worker stop timed out")
            except Exception as exc:
                logger.warning(f"AutoCollector flush worker stop failed: {exc}")

        try:
            await asyncio.wait_for(_shutdown_services(app), timeout=15.0)
        except asyncio.TimeoutError:
            logger.warning("_shutdown_services timed out after 15s")
        except Exception as exc:
            logger.warning(f"Service shutdown error: {exc}")

        try:
            await db_engine.dispose()
            logger.info("Database engine disposed")
        except Exception as exc:
            logger.warning(f"Database engine dispose failed: {exc}")

        shutdown_duration = time.time() - shutdown_start
        logger.info(f"Threat Intel Agent backend shut down cleanly in {shutdown_duration:.2f}s")


app = FastAPI(
    title="黑灰产情报分析Agent",
    description="基于纯算法的威胁情报分析平台",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)

_static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.isdir(_static_dir) and os.path.isdir(os.path.join(_static_dir, "swagger-ui")):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

_frontend_dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend_dist")
if os.path.isdir(_frontend_dist) and os.path.isfile(os.path.join(_frontend_dist, "index.html")):
    app.mount("/assets", StaticFiles(directory=os.path.join(_frontend_dist, "assets")), name="frontend_assets")

    @app.get("/", include_in_schema=False)
    async def spa_index():
        from fastapi.responses import FileResponse
        return FileResponse(os.path.join(_frontend_dist, "index.html"))

    SPA_FALLBACK_DIR = _frontend_dist

    @app.exception_handler(404)
    async def spa_404_handler(request: Request, exc):
        from fastapi.responses import FileResponse
        path = request.url.path
        if path.startswith("/api/") or path.startswith("/docs") or path.startswith("/openapi") or path.startswith("/redoc"):
            return JSONResponse(
                status_code=404,
                content={
                    "success": False,
                    "error_code": "NOT_FOUND",
                    "message": f"Endpoint not found: {request.method} {path}",
                    "path": path,
                    "request_id": getattr(request.state, "request_id", None),
                },
            )
        fp = os.path.join(SPA_FALLBACK_DIR, path.lstrip("/"))
        if os.path.isfile(fp):
            return FileResponse(fp)
        return FileResponse(os.path.join(SPA_FALLBACK_DIR, "index.html"))

app.add_middleware(GZipMiddleware, minimum_size=500)
app.add_middleware(PrometheusMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(CSRFMiddleware)
app.add_middleware(TenantMiddleware)

_cors_origins = settings.cors_origins_list
_cors_wildcard = "*" in _cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=not _cors_wildcard,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=_allowed_cors_headers,
    expose_headers=_cors_exposed_headers,
    max_age=600,
)

register_exception_handlers(app)
register_health_endpoints(app)

app.include_router(api_router, prefix="/api/v1")
app.include_router(ws_router, prefix="/api/v1")
app.include_router(export_router, prefix="/api/v1")
app.include_router(health_router, prefix="/api/v1")


@app.get("/metrics")
async def prometheus_metrics():
    return metrics_endpoint()


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    html = '<!DOCTYPE html><html><head>'
    html += '<link type="text/css" rel="stylesheet" href="/static/swagger-ui/swagger-ui.css">'
    html += '<title>黑灰产情报分析Agent - Swagger UI</title>'
    html += '<style>body{margin:0;padding:0}</style>'
    html += '</head><body><div id="swagger-ui"></div>'
    html += '<script src="/static/swagger-ui/swagger-ui-bundle.js"></script>'
    html += '<script>SwaggerUIBundle({url:"/openapi.json",dom_id:"#swagger-ui",layout:"BaseLayout",deepLinking:true,showExtensions:true,showCommonExtensions:true,presets:[SwaggerUIBundle.presets.apis,SwaggerUIBundle.SwaggerUIStandalonePreset]})</script>'
    html += '</body></html>'
    return HTMLResponse(html)


@app.get("/redoc", include_in_schema=False)
async def custom_redoc_html():
    if settings.is_production:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    html = '<!DOCTYPE html><html><head>'
    html += '<title>黑灰产情报分析Agent - ReDoc</title>'
    html += '<style>body{margin:0;padding:0}</style>'
    html += '</head><body><div id="redoc"></div>'
    html += f'<script src="{settings.REDOC_CDN_URL}"></script>'
    html += '<script>Redoc.init("/openapi.json",{scrollYOffset:50,hideDownloadButton:false},document.getElementById("redoc"))</script>'
    html += '</body></html>'
    return HTMLResponse(html)


@app.middleware("http")
async def body_size_limit_middleware(request: Request, call_next):
    global _inflight_requests
    if _shutting_down:
        return JSONResponse(
            status_code=503,
            content={"success": False, "message": "Server is shutting down", "code": 503},
        )

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError:
            length = -1
        if length > _max_upload_size_bytes:
            logger.warning(
                f"Request rejected: body too large ({length} bytes > "
                f"{_max_upload_size_bytes} bytes) for {request.method} {request.url.path}"
            )
            return JSONResponse(
                status_code=413,
                content={
                    "success": False,
                    "message": f"Request body too large; max {_max_upload_size_bytes // (1024 * 1024)} MB",
                    "code": 413,
                },
            )
        if length > _max_upload_size_bytes * 0.8:
            logger.info(
                f"Large request accepted: {length} bytes ({length / (1024 * 1024):.1f} MB) "
                f"for {request.method} {request.url.path}"
            )

    async with _inflight_lock:
        _inflight_requests += 1
    try:
        return await call_next(request)
    finally:
        async with _inflight_lock:
            _inflight_requests = max(0, _inflight_requests - 1)


@app.middleware("http")
async def request_audit_middleware(request: Request, call_next):
    return await audit_log_middleware(request, call_next)


@app.middleware("http")
async def rate_limit_route_middleware(request: Request, call_next):
    return await rate_limit_middleware(request, call_next)


@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "data": None,
            "message": exc.detail,
            "code": exc.error_code,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    import traceback as tb
    tb_str = tb.format_exc()
    error_id = uuid.uuid4().hex[:12]
    logger.error(f"[{error_id}] Unhandled exception: {exc}\n{tb_str}")
    response_data = {
        "success": False,
        "data": None,
        "message": "服务器内部错误，请稍后重试",
        "code": 500,
        "error_id": error_id,
    }
    if not settings.is_production:
        response_data["detail"] = str(exc)[:200]
    return JSONResponse(status_code=500, content=response_data)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Authentication required")
        return
    try:
        from app.core.auth import decode_access_token, is_token_blacklisted
        from jose import ExpiredSignatureError, JWTError

        # 检查 token 是否已被加入黑名单
        if await is_token_blacklisted(token):
            await websocket.close(code=4001, reason="Token revoked")
            return

        # 解码 token，会自动检查过期时间
        token_data = decode_access_token(token)

        # 获取用户信息
        user = await get_user_by_id(token_data.user_id)
        if user is None or not user.is_active:
            await websocket.close(code=4001, reason="Invalid user")
            return

    except ExpiredSignatureError:
        logger.warning("WebSocket auth failed: token expired")
        await websocket.close(code=4002, reason="Token expired")
        return
    except JWTError as exc:
        logger.warning(f"WebSocket auth failed: invalid JWT - {exc}")
        await websocket.close(code=4003, reason="Invalid token")
        return
    except Exception as exc:
        logger.error(f"WebSocket auth failed with unexpected error: {exc}")
        await websocket.close(code=4001, reason="Authentication failed")
        return

    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                msg_type = msg.get("type", "")
                if msg_type == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
                elif msg_type == "subscribe":
                    await websocket.send_text(
                        json.dumps({"type": "subscribed", "channels": msg.get("channels", [])})
                    )
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"type": "error", "message": "Invalid JSON"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
