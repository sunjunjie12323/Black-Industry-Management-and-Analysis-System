import os

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from loguru import logger
from app.config import settings

USE_ALEMBIC = os.environ.get("USE_ALEMBIC", "").lower() in ("1", "true", "yes")


def _build_engine_kwargs() -> dict:
    url = settings.DATABASE_URL
    kwargs = {"echo": False, "future": True}

    if url.startswith("postgresql+asyncpg://"):
        kwargs["pool_size"] = settings.DB_POOL_SIZE
        kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
        kwargs["pool_timeout"] = settings.DB_POOL_TIMEOUT
        kwargs["pool_recycle"] = settings.DB_POOL_RECYCLE
        kwargs["pool_pre_ping"] = True
        kwargs["pool_use_lifo"] = True
        logger.info(
            f"Using PostgreSQL: pool_size={kwargs['pool_size']} "
            f"max_overflow={kwargs['max_overflow']} pool_timeout={kwargs['pool_timeout']}s"
        )
    elif url.startswith("sqlite"):
        # SQLite并发优化配置
        kwargs["connect_args"] = {
            "check_same_thread": False,
            "timeout": 60,  # 增加到60秒
        }
        kwargs["pool_pre_ping"] = True
        logger.info("Using SQLite (development mode) with WAL and 60s timeout")
    else:
        logger.warning(f"Unknown database type: {url[:30]}...")

    return kwargs


def _setup_pool_logging(sync_engine) -> None:
    if not sync_engine.pool:
        return

    @event.listens_for(sync_engine, "checkout")
    def on_checkout(dbapi_conn, conn_record, conn_proxy):
        if hasattr(sync_engine.pool, "overflow") and sync_engine.pool.overflow() > 0:
            overflow = sync_engine.pool.overflow()
            if overflow > 0 and overflow % 5 == 0:
                logger.warning(f"DB pool overflow reached {overflow} (size={sync_engine.pool.size()})")

    @event.listens_for(sync_engine, "invalidate")
    def on_invalidate(dbapi_conn, conn_record, exception):
        logger.warning(f"DB connection invalidated: {exception}")


engine = create_async_engine(settings.DATABASE_URL, **_build_engine_kwargs())

# SQLite PRAGMA优化：在engine创建后注册事件监听器
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=60000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=-64000")  # 64MB
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.close()

_setup_pool_logging(engine.sync_engine)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    from app.db import tables  # noqa: F401
    from app.db.economic_tables import (  # noqa: F401
        EconomicImpactTable,
        MarketTransactionTable,
        MarketStateTable,
        EconomicAlertTable,
    )
    from app.models.api_key import UserApiKeyTable  # noqa: F401

    if USE_ALEMBIC:
        logger.info("USE_ALEMBIC is enabled, skipping create_all (use Alembic migrations)")
        return

    if settings.is_production and not USE_ALEMBIC:
        logger.error("Running create_all in production without Alembic is not recommended. Set USE_ALEMBIC=true.")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if settings.DATABASE_URL.startswith("sqlite"):
            try:
                result = await conn.execute(text("PRAGMA table_info(analysis_result)"))
                columns = [row[1] for row in result.fetchall()]
                if columns and 'target_id' not in columns:
                    logger.warning("Detected old analysis_result table schema, migrating...")
                    await conn.execute(text("DROP TABLE IF EXISTS analysis_result"))
                    await conn.run_sync(Base.metadata.create_all)
                    logger.info("analysis_result table migrated to new schema")
            except Exception as exc:
                logger.warning(f"Schema migration check failed: {exc}")
        else:
            try:
                result = await conn.execute(text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name='analysis_result' AND column_name='target_id'"
                ))
                if not result.fetchone():
                    logger.info("PostgreSQL: analysis_result table schema is up to date or will be created")
            except Exception as exc:
                logger.debug(f"PostgreSQL schema check skipped: {exc}")
    logger.info("Database tables created/verified")

    await _create_indexes()


async def _create_indexes():
    async with async_session_factory() as session:
        indexes = [
            "CREATE INDEX IF NOT EXISTS ix_intelligence_status ON intelligence(status)",
            "CREATE INDEX IF NOT EXISTS ix_intelligence_source ON intelligence(source)",
            "CREATE INDEX IF NOT EXISTS ix_intelligence_threat_level ON intelligence(threat_level)",
            "CREATE INDEX IF NOT EXISTS ix_intelligence_created_at ON intelligence(created_at)",
            "CREATE INDEX IF NOT EXISTS ix_alerts_severity ON alerts(severity)",
            "CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status)",
            "CREATE INDEX IF NOT EXISTS ix_entities_type ON entities(entity_type)",
        ]
        for idx_sql in indexes:
            try:
                await session.execute(text(idx_sql))
            except Exception:
                pass
        await session.commit()


async def check_db_connection() -> bool:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error(f"Database connection check failed: {exc}")
        return False


async def close_db() -> None:
    await engine.dispose()
    logger.info("Database engine disposed")
