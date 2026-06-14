import asyncio
import uuid
from datetime import datetime, timedelta, timezone
import random

from loguru import logger

from app.db.database import engine, Base, async_session_factory
from app.db.tables import (
    RawIntelligenceTable,
    CleanedIntelligenceTable,
    AnalyzedIntelligenceTable,
    PIRTable,
    PIRTaskTable,
    ReportTable,
)
from app.core.knowledge_graph import KnowledgeGraph
from app.core.blacktalk_engine import BlackTalkEngine, BlackTalkTerm
from app.models.entity import Entity, Relation, EntityType, RelationType
from app.models.pir import PIR, PIRStatus, PIRPriority

from app.config import settings
if not settings.SEED_DATABASE:
    import sys
    print("WARNING: seed.py is designed for development/demo only. Set SEED_DATABASE=true in .env to enable.", file=sys.stderr)


PIRS_DATA = [
    {
        "title": "新型信贷欺诈手法监测",
        "description": "监测近期出现的信贷欺诈新型手法，包括套路贷、房贷背债等变种",
        "priority": "high",
        "keywords": ["信贷", "欺诈", "套路贷", "背债"],
        "target_sources": ["telegram", "forum", "wechat"],
    },
    {
        "title": "暗网数据泄露追踪",
        "description": "追踪暗网市场上出售的中国公民个人数据泄露事件",
        "priority": "critical",
        "keywords": ["数据泄露", "脱库", "个人信息", "fullz"],
        "target_sources": ["darkweb", "forum"],
    },
    {
        "title": "AI赋能黑产趋势分析",
        "description": "分析黑产利用AI技术（换脸、语音克隆、自动化攻击）的趋势和案例",
        "priority": "medium",
        "keywords": ["AI", "换脸", "语音克隆", "自动化"],
        "target_sources": ["telegram", "wechat", "darkweb"],
    },
]


async def seed_database():
    if settings.is_production:
        logger.error("Seed scripts cannot run in production")
        return
    logger.info("Starting database seeding...")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    kg = KnowledgeGraph()

    async with async_session_factory() as session:
        for pir_data in PIRS_DATA:
            pir = PIRTable(
                id=str(uuid.uuid4()),
                title=pir_data["title"],
                description=pir_data["description"],
                priority=pir_data["priority"],
                status="active",
                keywords_json=str(pir_data["keywords"]),
                target_sources_json=str(pir_data["target_sources"]),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(pir)

        await session.commit()

    logger.info(f"Database seeded: {len(PIRS_DATA)} PIRs. "
                "Intelligence data will be collected from real APIs on first query.")


async def seed_from_real_data():
    if settings.is_production:
        logger.error("Seed scripts cannot run in production")
        return
    logger.info("Seeding database from real threat intelligence APIs...")

    from app.collectors.darkweb_collector import DarkWebCollector
    from app.collectors.forum_collector import ForumCollector

    items: list = []

    try:
        darkweb = DarkWebCollector()
        darkweb_items = await darkweb.collect(keywords=["malware", "phishing", "fraud"], max_results=20)
        items.extend(darkweb_items)
        await darkweb.close()
    except Exception as exc:
        logger.warning(f"DarkWeb seeding failed: {exc}")

    try:
        forum = ForumCollector()
        forum_items = await forum.collect(keywords=["fraud", "malware", "data breach"], max_results=20)
        items.extend(forum_items)
        await forum.close()
    except Exception as exc:
        logger.warning(f"Forum seeding failed: {exc}")

    if not items:
        logger.warning("No real data available from APIs, skipping intelligence seeding")
        return

    async with async_session_factory() as session:
        for item in items[:30]:
            raw_id = str(uuid.uuid4())
            raw = RawIntelligenceTable(
                id=raw_id,
                source=item.get("metadata", {}).get("source", "unknown"),
                source_url=item.get("source_url", ""),
                content=item.get("content", ""),
                raw_content=item.get("content", ""),
                collected_at=datetime.now(timezone.utc),
                status="raw",
                metadata_json=str(item.get("metadata", {})),
            )
            session.add(raw)

        await session.commit()

    logger.info(f"Seeded {min(len(items), 30)} real intelligence items from APIs")


async def fix_seed_sources():
    if settings.is_production:
        logger.error("Seed scripts cannot run in production")
        return
    from sqlalchemy import text
    async with async_session_factory() as session:
        result = await session.execute(
            text("UPDATE raw_intelligence SET source = 'seed' WHERE source IN ('telegram', 'forum', 'wechat', 'darkweb') AND metadata_json LIKE '%seed%'")
        )
        if result.rowcount > 0:
            logger.info(f"Fixed {result.rowcount} seed records with correct source label")
        await session.commit()


if __name__ == "__main__":
    if not settings.SEED_DATABASE:
        import sys
        print("WARNING: seed.py is designed for development/demo only. Set SEED_DATABASE=true in .env to enable.", file=sys.stderr)
        sys.exit(1)
    asyncio.run(seed_database())
