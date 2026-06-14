import asyncio
import json
import uuid
import re
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from loguru import logger

from app.core.tracing import get_tracer

from app.core.data_governance import DataClassification, DataMinimizer, ClassificationLevel
from app.core.data_masking import PIIDetector
from app.core.message_queue import TOPIC_INTELLIGENCE_COLLECTED

from app.db.tables import RawIntelligenceTable, PIRTable
from app.core.knowledge_graph import KnowledgeGraph
from app.models.entity import Entity, EntityType, Relation, RelationType


_DEFAULT_RSS_SOURCES: List[Dict[str, Any]] = []
_FALLBACK_RSS_FEEDS: List[Dict[str, Any]] = [
    {
        "name": "FreeBuf",
        "url": "https://www.freebuf.com/feed",
        "type": "rss",
        "source_tag": "web",
        "language": "zh",
        "poll_interval_minutes": 60,
    },
    {
        "name": "嘶吼",
        "url": "https://www.4hou.com/feed",
        "type": "rss",
        "source_tag": "web",
        "language": "zh",
        "poll_interval_minutes": 60,
    },
    {
        "name": "SecWiki",
        "url": "https://www.sec-wiki.com/news/rss",
        "type": "rss",
        "source_tag": "web",
        "language": "zh",
        "poll_interval_minutes": 60,
    },
    {
        "name": "先知社区",
        "url": "https://xz.aliyun.com/feed",
        "type": "rss",
        "source_tag": "web",
        "language": "zh",
        "poll_interval_minutes": 60,
    },
]

_THREAT_LEVELS = ["critical", "high", "medium", "low", "info"]

_SOURCE_TYPES = ["darkweb", "telegram", "forum", "wechat", "web"]


class DataSourceConfig:
    def __init__(self, name: str, url: str, source_type: str, source_tag: str,
                 parser: str = "generic", poll_interval_minutes: int = 30,
                 headers: Dict = None, post_data: Dict = None,
                 enabled: bool = True):
        self.name = name
        self.url = url
        self.source_type = source_type
        self.source_tag = source_tag
        self.parser = parser
        self.poll_interval_minutes = poll_interval_minutes
        self.headers = headers or {}
        self.post_data = post_data
        self.enabled = enabled
        self.last_fetched: Optional[datetime] = None
        self.fetch_count = 0
        self.error_count = 0
        self.last_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "url": self.url,
            "source_type": self.source_type,
            "source_tag": self.source_tag,
            "parser": self.parser,
            "poll_interval_minutes": self.poll_interval_minutes,
            "enabled": self.enabled,
            "last_fetched": self.last_fetched.isoformat() if self.last_fetched else None,
            "fetch_count": self.fetch_count,
            "error_count": self.error_count,
        }


class AutoCollector:
    def __init__(self, kg: KnowledgeGraph, blacktalk_engine=None, llm_service=None,
                 data_classification=None, data_minimizer=None, pii_detector=None,
                 provenance_chain=None, message_queue=None, worker_pool=None):
        self.kg = kg
        self.blacktalk_engine = blacktalk_engine
        self._llm = llm_service
        self.data_classification = data_classification
        self.data_minimizer = data_minimizer
        self.pii_detector = pii_detector
        self.provenance_chain = provenance_chain
        self.message_queue = message_queue
        self.worker_pool = worker_pool
        self._stop_event = threading.Event()
        self._interval_minutes = 30
        self._collection_count = 0
        self._last_collection_at: Optional[datetime] = None
        self._lock = threading.Lock()
        self._http_session = None
        self._sources: List[DataSourceConfig] = []
        self._buffer: List[Dict[str, Any]] = []
        self._buffer_lock = threading.Lock()
        self._buffer_max_size = 100
        self._flush_batch_size = 50
        self._flush_interval_seconds = 5.0
        self._batch_stats = {
            "items_buffered": 0,
            "items_inserted": 0,
            "items_failed": 0,
            "flushes": 0,
            "last_flush_at": None,
        }
        self._init_default_sources()
        self._flush_task: Optional[asyncio.Task] = None
        self._flush_running = False

    def _init_default_sources(self):
        config_sources: List[Dict[str, Any]] = []
        config_apis: List[Dict[str, Any]] = []
        try:
            from app.core.seed_data import load_data_sources_config
            ds_config = load_data_sources_config()
            config_sources = ds_config.get("rss_feeds", []) or []
            config_apis = ds_config.get("api_sources", []) or []
        except Exception as exc:
            logger.warning(f"Failed to load data_sources.json: {exc}")

        for src in config_apis:
            if not src.get("enabled", True):
                api_key_env = src.get("api_key_env", "")
                if api_key_env:
                    import os
                    if not os.environ.get(api_key_env) and not getattr(self, "_explicit_api_keys", {}).get(api_key_env):
                        continue
            self._sources.append(DataSourceConfig(
                name=src["name"],
                url=src["url"],
                source_type=src["type"],
                source_tag=src.get("source_tag", "web"),
                parser=src.get("parser", "generic"),
                poll_interval_minutes=src.get("poll_interval_minutes", 60),
                post_data=src.get("post_data"),
            ))

        feed_list = config_sources if config_sources else _FALLBACK_RSS_FEEDS
        for src in feed_list:
            self._sources.append(DataSourceConfig(
                name=src["name"],
                url=src["url"],
                source_type=src["type"],
                source_tag=src.get("source_tag", "web"),
                poll_interval_minutes=src.get("poll_interval_minutes", 60),
            ))

        if not config_sources and not config_apis:
            for src in _DEFAULT_RSS_SOURCES:
                self._sources.append(DataSourceConfig(
                    name=src["name"],
                    url=src["url"],
                    source_type=src["type"],
                    source_tag=src.get("source_tag", "web"),
                    parser=src.get("parser", "generic"),
                    poll_interval_minutes=src.get("poll_interval_minutes", 60),
                    post_data=src.get("post_data"),
                ))

    def add_source(self, source: DataSourceConfig):
        with self._lock:
            self._sources.append(source)
        logger.info(f"Added data source: {source.name} ({source.url})")

    def _enqueue_items(self, items: List[Dict[str, Any]]) -> int:
        if not items:
            return 0
        accepted = 0
        with self._buffer_lock:
            for item in items:
                if len(self._buffer) >= self._buffer_max_size:
                    logger.warning("AutoCollector buffer is full, dropping item")
                    continue
                self._buffer.append(item)
                self._batch_stats["items_buffered"] += 1
                accepted += 1
        return accepted

    async def _flush_buffer(self, force: bool = False) -> Dict[str, int]:
        with self._buffer_lock:
            if not self._buffer:
                return {"inserted": 0, "failed": 0, "flushed": 0}
            if not force and len(self._buffer) < self._flush_batch_size:
                return {"inserted": 0, "failed": 0, "flushed": 0}
            batch = self._buffer[: self._flush_batch_size]
            self._buffer = self._buffer[self._flush_batch_size:]
        return await self._persist_batch(batch)

    async def _flush_all(self) -> Dict[str, int]:
        total = {"inserted": 0, "failed": 0, "flushed": 0}
        while True:
            with self._buffer_lock:
                if not self._buffer:
                    return total
                batch = self._buffer[: self._flush_batch_size]
                self._buffer = self._buffer[self._flush_batch_size:]
            result = await self._persist_batch(batch)
            total["inserted"] += result["inserted"]
            total["failed"] += result["failed"]
            total["flushed"] += result["flushed"]
        return total

    async def _persist_batch(self, batch: List[Dict[str, Any]]) -> Dict[str, int]:
        inserted = 0
        failed = 0
        if not batch:
            return {"inserted": 0, "failed": 0, "flushed": 0}

        max_retries = 3
        retry_delay = 0.5  # 秒

        for attempt in range(max_retries):
            try:
                from app.db.database import async_session_factory
                from sqlalchemy import insert as sql_insert
                async with async_session_factory() as session:
                    try:
                        mappings = []
                        for item in batch:
                            try:
                                mappings.append({
                                    "id": item["id"],
                                    "source": item.get("source"),
                                    "source_url": item.get("source_url"),
                                    "content": item.get("content"),
                                    "raw_content": item.get("raw_content"),
                                    "collected_at": item.get("collected_at", datetime.now(timezone.utc)),
                                    "status": item.get("status", "raw"),
                                    "metadata_json": item.get("metadata_json"),
                                    "classification_level": item.get("classification_level"),
                                })
                            except Exception as e:
                                logger.debug(f"AutoCollector batch item skipped: {e}")
                                failed += 1
                        if mappings:
                            await session.execute(sql_insert(RawIntelligenceTable), mappings)
                            await session.commit()
                            inserted = len(mappings)
                    except Exception as exc:
                        logger.warning(f"AutoCollector bulk insert failed, falling back to per-row: {exc}")
                        await session.rollback()
                        for item in batch:
                            try:
                                session.add(RawIntelligenceTable(**item))
                                await session.commit()
                                inserted += 1
                            except Exception as e:
                                failed += 1
                                try:
                                    await session.rollback()
                                except Exception:
                                    pass
                                logger.debug(f"AutoCollector single insert failed: {e}")
                # 成功执行，跳出重试循环
                break
            except Exception as exc:
                error_str = str(exc).lower()
                if "database is locked" in error_str or "database is busy" in error_str:
                    if attempt < max_retries - 1:
                        wait_time = retry_delay * (2 ** attempt)
                        logger.warning(f"AutoCollector 数据库锁定，{wait_time:.1f}秒后重试 ({attempt + 1}/{max_retries})")
                        await asyncio.sleep(wait_time)
                        inserted = 0  # 重置计数
                        failed = 0
                        continue
                    else:
                        logger.error(f"AutoCollector 数据库锁定，已达最大重试次数: {exc}")
                        failed += len(batch)
                else:
                    logger.error(f"AutoCollector persist batch failed: {exc}")
                    failed += len(batch)
                break

        with self._buffer_lock:
            self._batch_stats["items_inserted"] += inserted
            self._batch_stats["items_failed"] += failed
            self._batch_stats["flushes"] += 1
            self._batch_stats["last_flush_at"] = datetime.now(timezone.utc).isoformat()
        return {"inserted": inserted, "failed": failed, "flushed": len(batch)}

    async def start_flush_worker(self):
        if self._flush_running:
            return
        self._flush_running = True
        loop = asyncio.get_running_loop()

        async def _loop():
            while self._flush_running:
                try:
                    await self._flush_buffer(force=False)
                except Exception as exc:
                    logger.warning(f"AutoCollector flush worker error: {exc}")
                await asyncio.sleep(self._flush_interval_seconds)

        self._flush_task = loop.create_task(_loop())
        logger.info("AutoCollector batch flush worker started")

    async def stop_flush_worker(self):
        self._flush_running = False
        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except (asyncio.CancelledError, Exception):
                pass
            self._flush_task = None
        await self._flush_all()
        logger.info("AutoCollector batch flush worker stopped")

    def get_batch_stats(self) -> Dict[str, Any]:
        with self._buffer_lock:
            return {
                "buffer_size": len(self._buffer),
                "buffer_max_size": self._buffer_max_size,
                "flush_batch_size": self._flush_batch_size,
                "flush_interval_seconds": self._flush_interval_seconds,
                "flush_running": self._flush_running,
                **self._batch_stats,
            }

    def remove_source(self, name: str) -> bool:
        with self._lock:
            before = len(self._sources)
            self._sources = [s for s in self._sources if s.name != name]
            return len(self._sources) < before

    def list_sources(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._sources]

    def _get_http_session(self):
        if self._http_session is None or self._http_session.closed:
            try:
                import aiohttp
                self._http_session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=30),
                    headers={"User-Agent": "ThreatIntelBot/1.0"},
                )
            except ImportError:
                logger.warning("aiohttp not installed, HTTP fetching disabled")
                return None
        return self._http_session

    def _get_llm(self):
        if self._llm is None:
            try:
                from app.core.llm import LLMService
                self._llm = LLMService()
            except Exception as e:
                logger.warning(f"LLM service not available: {e}")
        return self._llm

    async def collect_once(self) -> dict:
        stats = {
            "intelligence": 0,
            "entities": 0,
            "relations": 0,
            "blacktalk": 0,
            "pir": 0,
            "errors": [],
            "sources_fetched": 0,
            "sources_failed": 0,
        }

        tracer = get_tracer("auto_collector")
        with tracer.start_as_current_span("auto_collector.collect_once") as span:
            fetch_stats = await self._fetch_from_sources()
            stats["intelligence"] += fetch_stats["collected"]
            stats["sources_fetched"] = fetch_stats["fetched"]
            stats["sources_failed"] = fetch_stats["failed"]
            stats["errors"].extend(fetch_stats.get("errors", []))

            if fetch_stats["collected"] > 0:
                await self._apply_data_governance(fetch_stats.get("items", []))
            else:
                eligible_count = sum(
                    1 for s in self._sources
                    if s.enabled and (
                        not s.last_fetched
                        or (datetime.now(timezone.utc) - s.last_fetched).total_seconds() / 60 >= s.poll_interval_minutes
                    )
                )
                if eligible_count == 0:
                    logger.warning(
                        "No real data collected: no eligible sources available. "
                        "All sources are either disabled or within their poll interval."
                    )
                elif fetch_stats["failed"] > 0:
                    logger.warning(
                        f"No real data collected: all {fetch_stats['failed']} source(s) failed to fetch. "
                        "Check source connectivity and parser configuration."
                    )
                else:
                    logger.warning(
                        "No real data collected: no data sources are configured. "
                        "Add real data sources via add_source() or configure _DEFAULT_RSS_SOURCES."
                    )

            entity_data = await self._extract_entities_from_recent_intel()
            if entity_data:
                for item in entity_data:
                    try:
                        entity = Entity(
                            id=item["id"],
                            type=item["entity_type"],
                            value=item["value"],
                            context=item.get("context"),
                            source_ids=item.get("source_ids", []),
                            confidence=item.get("confidence", 0.8),
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc),
                        )
                        await self.kg.add_entity(entity)
                        stats["entities"] += 1
                    except Exception as e:
                        logger.debug(f"Entity add failed: {e}")

                try:
                    relation_data = await self._extract_relations_from_intel(
                        fetch_stats.get("items", [])
                    )
                    for item in relation_data:
                        relation = Relation(
                            id=item["id"],
                            source_entity_id=item["source_id"],
                            target_entity_id=item["target_id"],
                            type=item["relation_type"],
                            confidence=item.get("confidence", 0.7),
                            evidence=item.get("evidence"),
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc),
                        )
                        await self.kg.add_relation(relation)
                        stats["relations"] += 1
                except Exception as e:
                    logger.debug(f"Relation extraction failed: {e}")

                try:
                    await self.kg.save()
                except Exception as e:
                    stats["errors"].append(f"kg_save: {str(e)[:100]}")

            with self._lock:
                self._collection_count += 1
                self._last_collection_at = datetime.now(timezone.utc)

            span.set_attribute("intelligence_count", stats["intelligence"])
            span.set_attribute("entities_count", stats["entities"])
            span.set_attribute("relations_count", stats["relations"])
            span.set_attribute("sources_fetched", stats["sources_fetched"])
            span.set_attribute("sources_failed", stats["sources_failed"])

        logger.info(
            f"AutoCollection completed: intel={stats['intelligence']}, "
            f"entities={stats['entities']}, relations={stats['relations']}, "
            f"sources_fetched={stats['sources_fetched']}, sources_failed={stats['sources_failed']}"
        )
        return stats

    async def _apply_data_governance(self, items: list):
        for item in items:
            content = item.get("content", "")
            if self.data_classification:
                try:
                    cls_result = self.data_classification.classify(content, item.get("metadata"))
                    item["classification_level"] = cls_result.level.value
                except Exception as exc:
                    logger.warning(f"AutoCollector data classification failed: {exc}")
            if self.pii_detector:
                try:
                    pii_matches = self.pii_detector.detect_pii(content)
                    if pii_matches:
                        item["pii_detected"] = True
                        item["pii_types"] = list({m.pii_type.value for m in pii_matches})
                        if self.data_minimizer and item.get("classification_level") == ClassificationLevel.RESTRICTED.value:
                            item["content"] = self.data_minimizer.minimize_pii(
                                content, ClassificationLevel.RESTRICTED
                            )
                except Exception as exc:
                    logger.warning(f"AutoCollector PII detection failed: {exc}")
            if self.provenance_chain:
                try:
                    await self.provenance_chain.record_provenance(
                        intelligence_id=item.get("id", uuid.uuid4().hex),
                        stage="collected",
                        input_data={"source": item.get("source", "unknown"), "source_url": item.get("source_url", "")},
                        output_data={"content": (item.get("content", "") or "")[:500]},
                    )
                except Exception as exc:
                    logger.warning(f"AutoCollector provenance chain record failed: {exc}")
        if self.message_queue and items:
            try:
                await self.message_queue.publish(
                    TOPIC_INTELLIGENCE_COLLECTED,
                    {"items": items, "count": len(items)},
                )
            except Exception as exc:
                logger.warning(f"AutoCollector message queue publish failed: {exc}")

    async def _fetch_from_sources(self) -> dict:
        stats = {"collected": 0, "fetched": 0, "failed": 0, "errors": [], "items": []}
        session = self._get_http_session()
        if session is None:
            logger.warning("No HTTP session available; cannot fetch from real sources")
            return stats

        eligible_sources = []
        with self._lock:
            for source in self._sources:
                if not source.enabled:
                    continue
                if source.last_fetched:
                    elapsed = (datetime.now(timezone.utc) - source.last_fetched).total_seconds() / 60
                    if elapsed < source.poll_interval_minutes:
                        continue
                eligible_sources.append(source)

        if not eligible_sources:
            logger.debug("No eligible sources to fetch in this cycle")
            return stats

        if self.worker_pool and eligible_sources:
            stats = await self._fetch_with_worker_pool(session, eligible_sources, stats)
        else:
            stats = await self._fetch_serial(session, eligible_sources, stats)

        return stats

    async def _fetch_serial(self, session, sources: list, stats: dict, db_session=None) -> dict:
        for source in sources:
            try:
                items = await self._fetch_source(session, source)
                if items:
                    accepted = self._enqueue_items(items)
                    if accepted > 0:
                        await self._flush_buffer(force=True)
                    for item in items:
                        stats["collected"] += 1
                        stats["items"].append(item)
                    if db_session is not None:
                        try:
                            for item in items:
                                db_session.add(RawIntelligenceTable(**item))
                            await db_session.commit()
                        except Exception as e:
                            logger.debug(f"Failed to store items externally from {source.name}: {e}")
                source.last_fetched = datetime.now(timezone.utc)
                source.fetch_count += 1
                stats["fetched"] += 1
                logger.info(f"Fetched {len(items)} items from {source.name}")
            except Exception as e:
                source.error_count += 1
                source.last_error = str(e)[:200]
                stats["failed"] += 1
                stats["errors"].append(f"{source.name}: {str(e)[:100]}")
                logger.warning(f"Failed to fetch from {source.name}: {e}")
        return stats

    async def _fetch_with_worker_pool(self, session, sources: list, stats: dict) -> dict:
        from app.core.worker_pool import CollectionWorkerPool

        pool = self.worker_pool
        if not isinstance(pool, CollectionWorkerPool):
            return await self._fetch_serial(session, sources, stats)

        if not pool._running:
            await pool.start()

        futures = []
        for source in sources:
            future = await pool.submit_collection(
                self._fetch_and_store_source, source.name, session, source
            )
            futures.append((source, future))

        for source, future in futures:
            try:
                result = await future
                if result:
                    stats["collected"] += result.get("collected", 0)
                    stats["fetched"] += result.get("fetched", 0)
                    stats["failed"] += result.get("failed", 0)
                    stats["errors"].extend(result.get("errors", []))
                    stats["items"].extend(result.get("items", []))
            except Exception as e:
                source.error_count += 1
                source.last_error = str(e)[:200]
                stats["failed"] += 1
                stats["errors"].append(f"{source.name}: {str(e)[:100]}")
                logger.warning(f"Worker pool fetch failed for {source.name}: {e}")

        return stats

    async def _fetch_and_store_source(self, session, source: DataSourceConfig, db_session=None) -> dict:
        result = {"collected": 0, "fetched": 0, "failed": 0, "errors": [], "items": []}
        try:
            items = await self._fetch_source(session, source)
            if items:
                accepted = self._enqueue_items(items)
                if accepted > 0:
                    await self._flush_buffer(force=True)
                for item in items:
                    result["collected"] += 1
                    result["items"].append(item)
                if db_session is not None:
                    try:
                        for item in items:
                            db_session.add(RawIntelligenceTable(**item))
                        await db_session.commit()
                    except Exception as e:
                        logger.debug(f"Failed to store items externally from {source.name}: {e}")
                if self.message_queue:
                    try:
                        from app.core.message_queue import TOPIC_INTELLIGENCE_COLLECTED
                        await self.message_queue.publish(TOPIC_INTELLIGENCE_COLLECTED, {
                            "collector": source.name,
                            "count": len(items),
                            "source_tag": source.source_tag,
                        })
                    except Exception as exc:
                        logger.error(f"Failed to publish collection result for {source.name}: {exc}")

            source.last_fetched = datetime.now(timezone.utc)
            source.fetch_count += 1
            result["fetched"] = 1
            logger.info(f"Fetched {len(items)} items from {source.name}")
        except Exception as e:
            source.error_count += 1
            source.last_error = str(e)[:200]
            result["failed"] = 1
            result["errors"].append(f"{source.name}: {str(e)[:100]}")
            logger.warning(f"Failed to fetch from {source.name}: {e}")
        return result

    async def _fetch_source(self, session, source: DataSourceConfig) -> list[dict]:
        items = []

        if source.source_type == "json_api":
            async with session.get(source.url, headers=source.headers) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                data = await resp.json(content_type=None)
                items = self._parse_json_api(data, source)

        elif source.source_type == "json_api_post":
            async with session.post(source.url, data=source.post_data, headers=source.headers) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                data = await resp.json(content_type=None)
                items = self._parse_json_api(data, source)

        elif source.source_type == "rss":
            async with session.get(source.url, headers=source.headers) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                text = await resp.text()
                items = self._parse_rss(text, source)

        elif source.source_type == "html":
            async with session.get(source.url, headers=source.headers) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                text = await resp.text()
                items = self._parse_html(text, source)

        return items

    def _parse_json_api(self, data: dict, source: DataSourceConfig) -> list[dict]:
        results = []
        now = datetime.now(timezone.utc)

        if source.parser == "cisa_kev":
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities[:20]:
                cve_id = vuln.get("cveID", "")
                product = vuln.get("product", "")
                description = vuln.get("shortDescription", "")
                content = f"CISA KEV: {cve_id} - {product}. {description}"
                metadata = {
                    "threat_level": "high",
                    "category": "vulnerability",
                    "language": "en",
                    "confidence": 0.95,
                    "source_name": source.name,
                    "cve_id": cve_id,
                }
                results.append({
                    "id": uuid.uuid4().hex,
                    "source": source.source_tag,
                    "source_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "content": content,
                    "raw_content": json.dumps(vuln, ensure_ascii=False)[:500],
                    "collected_at": now,
                    "status": "raw",
                    "metadata_json": json.dumps(metadata, ensure_ascii=False),
                })

        elif source.parser == "urlhaus":
            urls = data.get("urls", [])
            for entry in urls[:20]:
                url_value = entry.get("url", "")
                threat = entry.get("threat", "")
                tags = ", ".join(entry.get("tags", []))
                content = f"URLhaus恶意URL: {url_value} 威胁类型: {threat} 标签: {tags}"
                metadata = {
                    "threat_level": "high",
                    "category": "malicious_url",
                    "language": "en",
                    "confidence": 0.9,
                    "source_name": source.name,
                    "urlhaus_threat": threat,
                }
                results.append({
                    "id": uuid.uuid4().hex,
                    "source": source.source_tag,
                    "source_url": url_value,
                    "content": content,
                    "raw_content": json.dumps(entry, ensure_ascii=False)[:500],
                    "collected_at": now,
                    "status": "raw",
                    "metadata_json": json.dumps(metadata, ensure_ascii=False),
                })

        elif source.parser == "malware_bazaar":
            samples = data.get("data", [])
            for sample in samples[:20]:
                sha256 = sample.get("sha256_hash", "")
                malware_name = sample.get("signature", "")
                file_type = sample.get("file_type", "")
                content = f"MalwareBazaar样本: {malware_name} SHA256: {sha256} 类型: {file_type}"
                metadata = {
                    "threat_level": "high",
                    "category": "malware_sample",
                    "language": "en",
                    "confidence": 0.9,
                    "source_name": source.name,
                    "sha256": sha256,
                    "malware_family": malware_name,
                }
                results.append({
                    "id": uuid.uuid4().hex,
                    "source": source.source_tag,
                    "source_url": f"https://bazaar.abuse.ch/sample/{sha256}/",
                    "content": content,
                    "raw_content": json.dumps(sample, ensure_ascii=False)[:500],
                    "collected_at": now,
                    "status": "raw",
                    "metadata_json": json.dumps(metadata, ensure_ascii=False),
                })

        else:
            if isinstance(data, list):
                for item in data[:20]:
                    content = json.dumps(item, ensure_ascii=False)[:500]
                    metadata = {
                        "threat_level": "medium",
                        "category": "generic",
                        "confidence": 0.5,
                        "source_name": source.name,
                    }
                    results.append({
                        "id": uuid.uuid4().hex,
                        "source": source.source_tag,
                        "source_url": source.url,
                        "content": content,
                        "raw_content": content[:200],
                        "collected_at": now,
                        "status": "raw",
                        "metadata_json": json.dumps(metadata, ensure_ascii=False),
                    })

        return results

    def _parse_rss(self, text: str, source: DataSourceConfig) -> list[dict]:
        results = []
        now = datetime.now(timezone.utc)

        def _detect_language(sample: str, default: str = "en") -> str:
            if not sample:
                return default
            if re.search(r'[\u4e00-\u9fff]', sample):
                return "zh"
            return default

        try:
            import xml.etree.ElementTree as ET
            
            # 预处理XML文本，移除可能导致解析失败的内容
            # 1. 移除XML声明（如果有编码问题）
            text = re.sub(r'<\?xml[^>]+\?>', '', text, count=1)
            # 2. 移除BOM字符
            text = text.lstrip('\ufeff')
            # 3. 尝试修复常见的XML问题
            text = re.sub(r'&(?!amp;|lt;|gt;|apos;|quot;|#)', '&amp;', text)
            
            try:
                root = ET.fromstring(text)
            except ET.ParseError:
                # 如果还是失败，尝试用lxml（如果可用）
                try:
                    from lxml import etree
                    root = etree.fromstring(text.encode('utf-8'))
                    # 转换为ElementTree兼容格式
                    channel = root.find("channel")
                    if channel is None:
                        return results
                    
                    for item in channel.findall("item")[:15]:
                        title = item.findtext("title", "")
                        link = item.findtext("link", "")
                        description = item.findtext("description", "")
                        pub_date = item.findtext("pubDate", "")
                        
                        content = f"{title}"
                        if description:
                            clean_desc = re.sub(r'<[^>]+>', '', description)
                            content += f"\n{clean_desc[:500]}"
                        
                        if not content.strip():
                            continue
                        
                        language = _detect_language(content, default="en")
                        
                        metadata = {
                            "threat_level": "medium",
                            "category": "security_news",
                            "language": language,
                            "confidence": 0.7,
                            "source_name": source.name,
                            "original_link": link,
                            "pub_date": pub_date,
                        }
                        results.append({
                            "id": uuid.uuid4().hex,
                            "source": source.source_tag,
                            "source_url": link or source.url,
                            "content": content[:1000],
                            "raw_content": content[:200],
                            "collected_at": now,
                            "status": "raw",
                            "metadata_json": json.dumps(metadata, ensure_ascii=False),
                        })
                    return results
                except ImportError:
                    logger.warning(f"RSS parse failed for {source.name}: XML parse error and lxml not available")
                    return results
            
            channel = root.find("channel")
            if channel is None:
                # 尝试解析 Atom 格式（先知社区等使用 Atom）
                # Atom 命名空间
                atom_ns = {"atom": "http://www.w3.org/2005/Atom"}
                entries = root.findall("atom:entry", atom_ns) or root.findall("entry")
                
                if entries:
                    # Atom 格式
                    for entry in entries[:15]:
                        title = entry.findtext("atom:title", "", atom_ns) or entry.findtext("title", "")
                        link_el = entry.find("atom:link", atom_ns) or entry.find("link")
                        link = link_el.get("href", "") if link_el is not None else ""
                        summary = entry.findtext("atom:summary", "", atom_ns) or entry.findtext("summary", "")
                        content_el = entry.findtext("atom:content", "", atom_ns) or entry.findtext("content", "")
                        updated = entry.findtext("atom:updated", "", atom_ns) or entry.findtext("updated", "")
                        published = entry.findtext("atom:published", "", atom_ns) or entry.findtext("published", "")
                        pub_date = published or updated
                        
                        content = f"{title}"
                        if summary:
                            clean_summary = re.sub(r'<[^>]+>', '', summary)
                            content += f"\n{clean_summary[:500]}"
                        elif content_el:
                            clean_content = re.sub(r'<[^>]+>', '', content_el)
                            content += f"\n{clean_content[:500]}"
                        
                        if not content.strip():
                            continue
                        
                        language = _detect_language(content, default="zh")
                        
                        metadata = {
                            "threat_level": "medium",
                            "category": "security_news",
                            "language": language,
                            "confidence": 0.7,
                            "source_name": source.name,
                            "original_link": link,
                            "pub_date": pub_date,
                        }
                        results.append({
                            "id": uuid.uuid4().hex,
                            "source": source.source_tag,
                            "source_url": link or source.url,
                            "content": content[:1000],
                            "raw_content": content[:200],
                            "collected_at": now,
                            "status": "raw",
                            "metadata_json": json.dumps(metadata, ensure_ascii=False),
                        })
                return results

            for item in channel.findall("item")[:15]:
                title = item.findtext("title", "")
                link = item.findtext("link", "")
                description = item.findtext("description", "")
                pub_date = item.findtext("pubDate", "")

                content = f"{title}"
                if description:
                    clean_desc = re.sub(r'<[^>]+>', '', description)
                    content += f"\n{clean_desc[:500]}"

                if not content.strip():
                    continue

                language = _detect_language(content, default="en")

                metadata = {
                    "threat_level": "medium",
                    "category": "security_news",
                    "language": language,
                    "confidence": 0.7,
                    "source_name": source.name,
                    "original_link": link,
                    "pub_date": pub_date,
                }
                results.append({
                    "id": uuid.uuid4().hex,
                    "source": source.source_tag,
                    "source_url": link or source.url,
                    "content": content[:1000],
                    "raw_content": content[:200],
                    "collected_at": now,
                    "status": "raw",
                    "metadata_json": json.dumps(metadata, ensure_ascii=False),
                })
        except Exception as e:
            logger.warning(f"RSS parse failed for {source.name}: {e}")

        return results

    def _parse_html(self, text: str, source: DataSourceConfig) -> list[dict]:
        results = []
        now = datetime.now(timezone.utc)

        clean = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
        clean = re.sub(r'<style[^>]*>.*?</style>', '', clean, flags=re.DOTALL)
        clean = re.sub(r'<[^>]+>', ' ', clean)
        clean = re.sub(r'\s+', ' ', clean).strip()

        paragraphs = re.split(r'[。！？\.\!\?]', clean)
        for para in paragraphs[:10]:
            para = para.strip()
            if len(para) < 20:
                continue
            metadata = {
                "threat_level": "medium",
                "category": "web_scrape",
                "confidence": 0.4,
                "source_name": source.name,
            }
            results.append({
                "id": uuid.uuid4().hex,
                "source": source.source_tag,
                "source_url": source.url,
                "content": para[:500],
                "raw_content": para[:200],
                "collected_at": now,
                "status": "raw",
                "metadata_json": json.dumps(metadata, ensure_ascii=False),
            })

        return results

    async def _extract_entities_from_recent_intel(self, db_session=None) -> list[dict]:
        results = []
        try:
            from app.core.rule_based_extractor import rule_extractor

            if db_session is not None:
                from sqlalchemy import select
                from app.db.tables import RawIntelligenceTable

                stmt = select(RawIntelligenceTable).order_by(
                    RawIntelligenceTable.collected_at.desc()
                ).limit(20)
                db_result = await db_session.execute(stmt)
                rows = db_result.scalars().all()
            else:
                from app.db.database import async_session_factory
                async with async_session_factory() as session:
                    from sqlalchemy import select
                    from app.db.tables import RawIntelligenceTable

                    stmt = select(RawIntelligenceTable).order_by(
                        RawIntelligenceTable.collected_at.desc()
                    ).limit(20)
                    db_result = await session.execute(stmt)
                    rows = db_result.scalars().all()

            seen_values = set()
            for entity in self.kg._entities.values():
                seen_values.add(entity.value)

            for row in rows:
                if not row.content:
                    continue
                extracted = rule_extractor.extract(row.content)
                for ent in extracted[:5]:
                    val = ent.get("value", "")
                    if val and val not in seen_values and len(val) > 2:
                        results.append({
                            "id": uuid.uuid4().hex,
                            "entity_type": ent.get("type", "unknown"),
                            "value": val,
                            "context": ent.get("context", f"从情报{row.id[:8]}中提取"),
                            "source_ids": [row.id],
                            "confidence": ent.get("confidence", 0.7),
                        })
                        seen_values.add(val)
                        if len(results) >= 10:
                            break
                if len(results) >= 10:
                    break
        except Exception as e:
            logger.debug(f"Entity extraction from recent intel failed: {e}")

        return results

    async def _extract_relations_from_intel(self, intel_items: list[dict]) -> list[dict]:
        results = []
        if not intel_items:
            return results

        entity_ids = list(self.kg._entities.keys())
        if len(entity_ids) < 2:
            return results

        entity_by_value = {}
        for eid, entity in self.kg._entities.items():
            entity_by_value[entity.value] = eid

        llm = self._get_llm()
        if llm is None:
            logger.debug(
                "LLM service unavailable; skipping relation extraction. "
                "Configure LLM service to enable automatic relation extraction from intelligence."
            )
            return results

        for item in intel_items[:5]:
            content = item.get("content", "")
            if not content or len(content) < 20:
                continue

            try:
                prompt = (
                    "从以下威胁情报内容中提取实体之间的关系。"
                    "只提取有明确证据支持的关系，不要推测。\n\n"
                    f"情报内容：{content[:800]}\n\n"
                    "已知实体："
                    + ", ".join(list(entity_by_value.keys())[:20])
                    + "\n\n"
                    '请以JSON数组格式返回，每项包含：source(源实体值), target(目标实体值), '
                    'relation_type(关系类型，可选：USES/BELONGS_TO/COMMUNICATES_WITH/OPERATES/SELLS/BUYS/'
                    'ASSOCIATED_WITH/CONTROLS/DERIVED_FROM), evidence(证据文本)\n'
                    "如果没有明确的关系，返回空数组[]"
                )

                response = await llm.generate(prompt)
                if not response:
                    continue

                text = response.strip()
                if text.startswith("```"):
                    text = re.sub(r'^```\w*\n?', '', text)
                    text = re.sub(r'\n?```$', '', text)

                relations_raw = json.loads(text)
                if not isinstance(relations_raw, list):
                    continue

                for rel in relations_raw[:3]:
                    source_val = rel.get("source", "")
                    target_val = rel.get("target", "")
                    rel_type_str = rel.get("relation_type", "")
                    evidence = rel.get("evidence", "")

                    source_id = entity_by_value.get(source_val)
                    target_id = entity_by_value.get(target_val)

                    if not source_id or not target_id or source_id == target_id:
                        continue
                    if self.kg.graph.has_edge(source_id, target_id):
                        continue

                    try:
                        rel_type = RelationType(rel_type_str)
                    except ValueError:
                        rel_type = RelationType.ASSOCIATED_WITH

                    results.append({
                        "id": uuid.uuid4().hex,
                        "source_id": source_id,
                        "target_id": target_id,
                        "relation_type": rel_type,
                        "evidence": evidence or f"从情报中提取：{source_val}与{target_val}的关系",
                        "confidence": 0.7,
                    })

                    if len(results) >= 10:
                        break

            except json.JSONDecodeError:
                logger.debug(f"LLM relation extraction returned non-JSON for item {item.get('id', 'unknown')[:8]}")
            except Exception as e:
                logger.debug(f"LLM relation extraction failed for item: {e}")

            if len(results) >= 10:
                break

        return results

    def start_auto_collection(self, interval_minutes: int = 30):
        if not self._stop_event.is_set() and hasattr(self, '_timer') and self._timer and self._timer.is_alive():
            logger.warning("Auto collection is already running")
            return
        self._stop_event.clear()
        self._interval_minutes = interval_minutes
        logger.info(f"Starting auto collection with interval {interval_minutes} minutes")

        def _run_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                while not self._stop_event.is_set():
                    try:
                        loop.run_until_complete(self.collect_once())
                    except Exception as e:
                        logger.error(f"Auto collection cycle failed: {e}")
                    if self._stop_event.is_set():
                        break
                    self._stop_event.wait(timeout=self._interval_minutes * 60)
            finally:
                if self._http_session and not self._http_session.closed:
                    try:
                        loop.run_until_complete(self._http_session.close())
                    except Exception:
                        pass
                    self._http_session = None
                loop.close()
                logger.info("Auto collection loop exited")

        self._timer = threading.Thread(target=_run_loop, daemon=True, name="auto_collector")
        self._timer.start()

    def stop_auto_collection(self):
        if self._stop_event.is_set():
            logger.warning("Auto collection is not running")
            return
        self._stop_event.set()
        if hasattr(self, '_timer') and self._timer and self._timer.is_alive():
            self._timer.join(timeout=10)
        self._timer = None
        if self._http_session and not self._http_session.closed:
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self._http_session.close())
                loop.close()
            except Exception:
                pass
            self._http_session = None
        logger.info("Auto collection stopped")

    async def close(self):
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
            self._http_session = None

    @property
    def is_running(self) -> bool:
        return not self._stop_event.is_set() and hasattr(self, '_timer') and self._timer is not None and self._timer.is_alive()

    @property
    def status(self) -> dict:
        return {
            "running": self.is_running,
            "interval_minutes": self._interval_minutes,
            "collection_count": self._collection_count,
            "last_collection_at": self._last_collection_at.isoformat() if self._last_collection_at else None,
            "sources": [s.to_dict() for s in self._sources],
        }
