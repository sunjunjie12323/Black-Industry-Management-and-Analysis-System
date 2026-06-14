import asyncio
import json
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from loguru import logger


class SourceStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    DISABLED = "disabled"


class SourcePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SourceConfig:
    source_id: str
    name: str
    source_type: str
    priority: SourcePriority = SourcePriority.MEDIUM
    status: SourceStatus = SourceStatus.ACTIVE
    interval_minutes: int = 30
    max_results_per_cycle: int = 50
    keywords: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    last_collected_at: Optional[datetime] = None
    last_error: str = ""
    total_collected: int = 0
    total_errors: int = 0
    consecutive_errors: int = 0
    rate_limit_until: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "source_id": self.source_id,
            "name": self.name,
            "source_type": self.source_type,
            "priority": self.priority.value,
            "status": self.status.value,
            "interval_minutes": self.interval_minutes,
            "max_results_per_cycle": self.max_results_per_cycle,
            "keywords": self.keywords,
            "config": self.config,
            "last_collected_at": self.last_collected_at.isoformat() if self.last_collected_at else None,
            "last_error": self.last_error,
            "total_collected": self.total_collected,
            "total_errors": self.total_errors,
            "consecutive_errors": self.consecutive_errors,
            "rate_limit_until": self.rate_limit_until.isoformat() if self.rate_limit_until else None,
        }


DEFAULT_SOURCES = [
    SourceConfig(
        source_id="threatbook_feed",
        name="微步在线威胁情报",
        source_type="commercial",
        priority=SourcePriority.CRITICAL,
        interval_minutes=15,
        max_results_per_cycle=100,
        keywords=["黑产", "木马", "钓鱼", "APT", "勒索", "0day"],
        config={"api_type": "threatbook"},
    ),
    SourceConfig(
        source_id="alienvault_otx",
        name="AlienVault OTX",
        source_type="forum",
        priority=SourcePriority.HIGH,
        interval_minutes=30,
        max_results_per_cycle=50,
        keywords=["malware", "phishing", "ransomware", "APT", "exploit"],
        config={"api_type": "otx"},
    ),
    SourceConfig(
        source_id="cisa_kev",
        name="CISA已知被利用漏洞",
        source_type="forum",
        priority=SourcePriority.HIGH,
        interval_minutes=60,
        max_results_per_cycle=50,
        keywords=[],
        config={"api_type": "cisa_kev"},
    ),
    SourceConfig(
        source_id="sogou_wechat",
        name="搜狗微信公众号",
        source_type="wechat",
        priority=SourcePriority.MEDIUM,
        interval_minutes=30,
        max_results_per_cycle=30,
        keywords=["黑灰产", "反诈", "网络犯罪", "洗钱", "诈骗"],
        config={"api_type": "sogou"},
    ),
    SourceConfig(
        source_id="abuseipdb",
        name="AbuseIPDB",
        source_type="commercial",
        priority=SourcePriority.MEDIUM,
        interval_minutes=60,
        max_results_per_cycle=50,
        keywords=[],
        config={"api_type": "abuseipdb"},
    ),
    SourceConfig(
        source_id="circl_cve",
        name="CIRCL CVE",
        source_type="forum",
        priority=SourcePriority.LOW,
        interval_minutes=120,
        max_results_per_cycle=30,
        keywords=[],
        config={"api_type": "circl"},
    ),
    SourceConfig(
        source_id="manual_import",
        name="手动导入",
        source_type="manual",
        priority=SourcePriority.CRITICAL,
        interval_minutes=0,
        max_results_per_cycle=0,
        keywords=[],
        config={},
    ),
]


@dataclass
class CollectionCycleResult:
    cycle_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    sources_collected: int = 0
    total_items: int = 0
    errors: int = 0
    source_results: Dict[str, Dict] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "cycle_id": self.cycle_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "sources_collected": self.sources_collected,
            "total_items": self.total_items,
            "errors": self.errors,
            "source_results": self.source_results,
        }


class SourceScheduler:
    def __init__(self, pipeline=None, persist_dir: str = "./model_data/scheduler"):
        self._pipeline = pipeline
        self._sources: Dict[str, SourceConfig] = {}
        self._collectors: Dict[str, Callable] = {}
        self._running = False
        self._scheduler_task: Optional[asyncio.Task] = None
        self._cycle_history: List[CollectionCycleResult] = []
        self._persist_dir = Path(persist_dir)
        self._persist_dir.mkdir(parents=True, exist_ok=True)
        self._total_cycles = 0
        self._total_items_collected = 0

        for source in DEFAULT_SOURCES:
            self._sources[source.source_id] = source

        self._load_state()

    def register_collector(self, source_type: str, collector_fn: Callable):
        self._collectors[source_type] = collector_fn
        logger.info(f"Registered collector for source type: {source_type}")

    def add_source(self, config: SourceConfig):
        if config.source_id in self._sources:
            logger.warning(f"Source already exists: {config.source_id}, updating instead")
        self._sources[config.source_id] = config
        logger.info(f"Added source: {config.source_id} ({config.name})")
        self._save_state()

    def remove_source(self, source_id: str) -> bool:
        if source_id in self._sources:
            del self._sources[source_id]
            logger.info(f"Removed source: {source_id}")
            self._save_state()
            return True
        return False

    def update_source(self, source_id: str, updates: Dict) -> bool:
        source = self._sources.get(source_id)
        if not source:
            return False

        for key, value in updates.items():
            if hasattr(source, key):
                if key == "priority" and isinstance(value, str):
                    value = SourcePriority(value)
                elif key == "status" and isinstance(value, str):
                    value = SourceStatus(value)
                setattr(source, key, value)

        logger.info(f"Updated source {source_id}: {list(updates.keys())}")
        self._save_state()
        return True

    def get_source(self, source_id: str) -> Optional[Dict]:
        source = self._sources.get(source_id)
        return source.to_dict() if source else None

    def list_sources(self, status: Optional[str] = None) -> List[Dict]:
        sources = list(self._sources.values())
        if status:
            sources = [s for s in sources if s.status.value == status]
        return [s.to_dict() for s in sources]

    def get_due_sources(self) -> List[SourceConfig]:
        now = datetime.now(timezone.utc)
        due = []

        for source in self._sources.values():
            if source.status != SourceStatus.ACTIVE:
                continue

            if source.rate_limit_until and now < source.rate_limit_until:
                continue

            if source.interval_minutes <= 0:
                continue

            if source.last_collected_at is None:
                due.append(source)
                continue

            elapsed = (now - source.last_collected_at).total_seconds() / 60
            if elapsed >= source.interval_minutes:
                due.append(source)

        priority_order = {
            SourcePriority.CRITICAL: 0,
            SourcePriority.HIGH: 1,
            SourcePriority.MEDIUM: 2,
            SourcePriority.LOW: 3,
        }
        due.sort(key=lambda s: priority_order.get(s.priority, 3))

        return due

    async def collect_from_source(self, source_id: str) -> Dict:
        source = self._sources.get(source_id)
        if not source:
            return {"status": "error", "error": f"Source {source_id} not found"}

        collector_fn = self._collectors.get(source.source_type)
        if not collector_fn:
            return {"status": "error", "error": f"No collector registered for type: {source.source_type}"}

        try:
            items = await collector_fn(
                keywords=source.keywords,
                max_results=source.max_results_per_cycle,
            )

            if not isinstance(items, list):
                items = []

            source.last_collected_at = datetime.now(timezone.utc)
            source.total_collected += len(items)
            source.consecutive_errors = 0
            source.last_error = ""

            for item in items:
                item["source"] = source.source_id
                item["source_name"] = source.name

            self._total_items_collected += len(items)
            self._save_state()

            logger.info(f"Collected {len(items)} items from {source.name} ({source_id})")

            return {
                "status": "success",
                "source_id": source_id,
                "items_count": len(items),
                "items": items,
            }

        except Exception as exc:
            source.consecutive_errors += 1
            source.total_errors += 1
            source.last_error = "数据源操作失败"

            if source.consecutive_errors >= 5:
                source.status = SourceStatus.ERROR
                logger.error(f"Source {source_id} disabled after {source.consecutive_errors} consecutive errors")
            elif source.consecutive_errors >= 3:
                source.rate_limit_until = datetime.now(timezone.utc) + timedelta(minutes=30)
                logger.warning(f"Source {source_id} rate-limited for 30min after {source.consecutive_errors} errors")

            self._save_state()

            return {
                "status": "error",
                "source_id": source_id,
                "error": "数据源操作失败",
                "consecutive_errors": source.consecutive_errors,
            }

    async def run_collection_cycle(self) -> CollectionCycleResult:
        cycle_id = uuid.uuid4().hex[:12]
        result = CollectionCycleResult(
            cycle_id=cycle_id,
            started_at=datetime.now(timezone.utc),
        )

        due_sources = self.get_due_sources()
        logger.info(f"Collection cycle [{cycle_id}]: {len(due_sources)} sources due")

        all_items = []

        for source in due_sources:
            collect_result = await self.collect_from_source(source.source_id)

            result.source_results[source.source_id] = {
                "status": collect_result.get("status", "unknown"),
                "items_count": collect_result.get("items_count", 0),
                "error": collect_result.get("error", ""),
            }

            if collect_result.get("status") == "success":
                result.sources_collected += 1
                items = collect_result.get("items", [])
                all_items.extend(items)
                result.total_items += len(items)
            else:
                result.errors += 1

        if all_items and self._pipeline:
            try:
                pipeline_result = await self._pipeline.process_batch(all_items, use_llm=True, max_concurrent=5)
                result.source_results["_pipeline"] = {
                    "status": "completed",
                    "total_input": pipeline_result.total_input,
                    "total_processed": pipeline_result.total_processed,
                    "total_duplicates": pipeline_result.total_duplicates,
                    "total_high_risk": pipeline_result.total_high_risk,
                }

                stored = await self._pipeline.store_results(pipeline_result.item_results)
                result.source_results["_pipeline"]["stored"] = stored

            except Exception as exc:
                logger.error(f"Pipeline processing failed in cycle [{cycle_id}]: {exc}")
                result.source_results["_pipeline"] = {"status": "error", "error": "数据源操作失败"}

        result.completed_at = datetime.now(timezone.utc)
        self._total_cycles += 1
        self._cycle_history.append(result)

        if len(self._cycle_history) > 100:
            self._cycle_history = self._cycle_history[-100:]

        self._save_state()

        logger.info(
            f"Collection cycle [{cycle_id}] completed: "
            f"sources={result.sources_collected}, items={result.total_items}, "
            f"errors={result.errors}"
        )

        return result

    async def start(self, base_interval_minutes: int = 10):
        if self._running:
            logger.warning("SourceScheduler already running")
            return

        self._running = True
        logger.info(f"SourceScheduler starting (base interval: {base_interval_minutes}min)")

        self._scheduler_task = asyncio.create_task(
            self._scheduler_loop(base_interval_minutes)
        )

    async def stop(self):
        self._running = False
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
            self._scheduler_task = None
        logger.info("SourceScheduler stopped")

    async def _scheduler_loop(self, interval_minutes: int):
        while self._running:
            try:
                await self.run_collection_cycle()
            except Exception as exc:
                logger.error(f"Scheduler cycle failed: {exc}")

            await asyncio.sleep(interval_minutes * 60)

    async def trigger_source(self, source_id: str) -> Dict:
        return await self.collect_from_source(source_id)

    async def trigger_all(self) -> CollectionCycleResult:
        for source in self._sources.values():
            if source.status == SourceStatus.ACTIVE:
                source.last_collected_at = None

        return await self.run_collection_cycle()

    async def import_items(self, items: List[Dict], source_name: str = "manual_import") -> Dict:
        if not items:
            return {"status": "error", "error": "No items to import"}

        for item in items:
            item.setdefault("source", "manual")
            item.setdefault("source_name", source_name)

        if self._pipeline:
            pipeline_result = await self._pipeline.process_batch(items, use_llm=True, max_concurrent=5)
            stored = await self._pipeline.store_results(pipeline_result.item_results)
            return {
                "status": "success",
                "total_input": pipeline_result.total_input,
                "total_processed": pipeline_result.total_processed,
                "total_duplicates": pipeline_result.total_duplicates,
                "total_high_risk": pipeline_result.total_high_risk,
                "stored": stored,
            }

        return {"status": "success", "total_input": len(items), "note": "No pipeline configured, items not processed"}

    def get_stats(self) -> Dict:
        active_sources = sum(1 for s in self._sources.values() if s.status == SourceStatus.ACTIVE)
        error_sources = sum(1 for s in self._sources.values() if s.status == SourceStatus.ERROR)

        return {
            "is_running": self._running,
            "total_sources": len(self._sources),
            "active_sources": active_sources,
            "error_sources": error_sources,
            "total_cycles": self._total_cycles,
            "total_items_collected": self._total_items_collected,
            "registered_collectors": list(self._collectors.keys()),
            "last_cycle": self._cycle_history[-1].to_dict() if self._cycle_history else None,
        }

    def get_cycle_history(self, limit: int = 20) -> List[Dict]:
        return [c.to_dict() for c in self._cycle_history[-limit:]]

    def _save_state(self):
        try:
            state = {
                "sources": {sid: s.to_dict() for sid, s in self._sources.items()},
                "total_cycles": self._total_cycles,
                "total_items_collected": self._total_items_collected,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            tmp_path = self._persist_dir / "scheduler_state.tmp"
            final_path = self._persist_dir / "scheduler_state.json"

            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False, indent=2, default=str)

            tmp_path.replace(final_path)
        except Exception as exc:
            logger.warning(f"Failed to save scheduler state: {exc}")

    def _load_state(self):
        state_path = self._persist_dir / "scheduler_state.json"
        if not state_path.exists():
            return

        try:
            with open(state_path, "r", encoding="utf-8") as f:
                state = json.load(f)

            for sid, sdata in state.get("sources", {}).items():
                if sid in self._sources:
                    source = self._sources[sid]
                    source.total_collected = sdata.get("total_collected", 0)
                    source.total_errors = sdata.get("total_errors", 0)
                    source.consecutive_errors = sdata.get("consecutive_errors", 0)
                    source.last_error = sdata.get("last_error", "")
                    if sdata.get("last_collected_at"):
                        try:
                            source.last_collected_at = datetime.fromisoformat(sdata["last_collected_at"])
                        except (ValueError, TypeError):
                            pass
                    if sdata.get("rate_limit_until"):
                        try:
                            source.rate_limit_until = datetime.fromisoformat(sdata["rate_limit_until"])
                        except (ValueError, TypeError):
                            pass
                    if sdata.get("status"):
                        try:
                            source.status = SourceStatus(sdata["status"])
                        except ValueError:
                            pass
                    if sdata.get("keywords"):
                        source.keywords = sdata["keywords"]
                    if sdata.get("interval_minutes"):
                        source.interval_minutes = sdata["interval_minutes"]

            self._total_cycles = state.get("total_cycles", 0)
            self._total_items_collected = state.get("total_items_collected", 0)

            logger.info(f"Loaded scheduler state: {len(self._sources)} sources, {self._total_cycles} cycles")

        except Exception as exc:
            logger.warning(f"Failed to load scheduler state: {exc}")
