import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional
from uuid import uuid4

import httpx
from loguru import logger

from app.config import settings
from app.agents.base import BaseAgent
from app.core.knowledge_graph import KnowledgeGraph
from app.core.llm import LLMService
from app.core.vector_store import VectorStore
from app.models.intelligence import IntelligenceSource, RawIntelligence


def _sanitize_input(text: str, max_length: int = 10000) -> str:
    if not text:
        return ""
    sanitized = text[:max_length]
    sanitized = sanitized.replace("```", " ")
    sanitized = sanitized.replace("<|im_end|>", " ")
    sanitized = sanitized.replace("<|im_start|>", " ")
    return sanitized.strip()


CollectorFn = Callable[..., Coroutine[Any, Any, List[Dict]]]


async def _collect_cisa_kev(
    keywords: List[str], max_results: int = 100, **kwargs
) -> List[Dict]:
    items = []
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                for v in vulns[:max_results]:
                    cve_id = v.get("cveID", "")
                    product = v.get("product", "")
                    desc = v.get("shortDescription", "")
                    date_added = v.get("dateAdded", "")
                    items.append({
                        "content": f"[CISA KEV] {cve_id}: {desc} (产品: {product}, 添加日期: {date_added})",
                        "source_url": f"https://www.cve.org/CVERecord?id={cve_id}",
                        "metadata": {
                            "cve_id": cve_id,
                            "product": product,
                            "date_added": date_added,
                            "source": "cisa_kev",
                        },
                    })
    except Exception as exc:
        logger.warning(f"CISA KEV collection failed: {exc}")
    return items


async def _collect_urlhaus(
    keywords: List[str], max_results: int = 100, **kwargs
) -> List[Dict]:
    items = []
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get("https://urlhaus-api.abuse.ch/v1/recent/")
            if r.status_code == 200:
                data = r.json()
                urls = data.get("urls", [])
                for u in urls[:max_results]:
                    url_val = u.get("url", "")
                    threat = u.get("threat", "")
                    tags = u.get("tags", [])
                    host = u.get("host", "")
                    date_added = u.get("date_added", "")
                    items.append({
                        "content": f"[URLhaus] 恶意URL: {url_val} (威胁: {threat}, 标签: {','.join(tags)}, 主机: {host})",
                        "source_url": f"https://urlhaus.abuse.ch/url/{u.get('id', '')}/",
                        "metadata": {
                            "url": url_val,
                            "threat": threat,
                            "tags": tags,
                            "host": host,
                            "date_added": date_added,
                            "source": "urlhaus",
                        },
                    })
    except Exception as exc:
        logger.warning(f"URLhaus collection failed: {exc}")
    return items


async def _collect_malware_bazaar(
    keywords: List[str], max_results: int = 100, **kwargs
) -> List[Dict]:
    items = []
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_recent", "selector": "time"},
            )
            if r.status_code == 200:
                data = r.json()
                samples = data.get("data", [])
                for s in samples[:max_results]:
                    sha256 = s.get("sha256_hash", "")
                    malware = s.get("malware", "")
                    family = s.get("family", "")
                    tags = s.get("tags", [])
                    date_added = s.get("first_seen_utc", "")
                    items.append({
                        "content": f"[MalwareBazaar] 恶意软件样本: {malware} (SHA256: {sha256[:16]}..., 家族: {family}, 标签: {','.join(tags or [])})",
                        "source_url": f"https://bazaar.abuse.ch/sample/{sha256}/",
                        "metadata": {
                            "sha256": sha256,
                            "malware": malware,
                            "family": family,
                            "tags": tags,
                            "date_added": date_added,
                            "source": "malware_bazaar",
                        },
                    })
    except Exception as exc:
        logger.warning(f"MalwareBazaar collection failed: {exc}")
    return items


class CollectorAgent(BaseAgent):
    def __init__(
        self,
        llm: LLMService,
        vector_store: VectorStore,
        knowledge_graph: KnowledgeGraph,
    ):
        super().__init__("collector", llm, vector_store)
        self.knowledge_graph = knowledge_graph
        self.collectors: Dict[str, CollectorFn] = {}
        self._monitor_tasks: Dict[str, Dict] = {}

        self.register_collector("cisa_kev", _collect_cisa_kev)
        self.register_collector("urlhaus", _collect_urlhaus)
        self.register_collector("malware_bazaar", _collect_malware_bazaar)

    def register_collector(self, source_type: str, collector: CollectorFn):
        self.collectors[source_type] = collector
        self.logger.info(f"Registered collector for source: {source_type}")

    async def execute(self, task: Dict) -> Dict:
        task_type = task.get("type", "collect")
        try:
            if task_type == "collect":
                source = task.get("source", "all")
                keywords = task.get("keywords", [])
                max_results = task.get("max_results", 100)
                time_range = task.get("time_range")

                collected = await self.collect_from_source(
                    source=source,
                    keywords=keywords,
                    max_results=max_results,
                )

                try:
                    deduped = await asyncio.wait_for(
                        self.deduplicate(collected), timeout=30.0
                    )
                except asyncio.TimeoutError:
                    self.logger.warning("Deduplication timed out (30s), returning all collected items")
                    deduped = collected

                result = self._create_task_result(
                    status="success",
                    data={
                        "collected_count": len(collected),
                        "deduplicated_count": len(deduped),
                        "items": deduped,
                        "source": source,
                        "keywords": keywords,
                    },
                )

            elif task_type == "search":
                query = task.get("query", "")
                n_results = task.get("n_results", 10)
                if not query:
                    return self._create_task_result(
                        status="failed",
                        data={},
                        errors=["Search query is required"],
                    )
                results = await self.search_existing(query, n_results)
                result = self._create_task_result(
                    status="success",
                    data={
                        "query": query,
                        "results_count": len(results),
                        "results": results,
                    },
                )

            elif task_type == "monitor":
                source = task.get("source", "all")
                keywords = task.get("keywords", [])
                interval = task.get("interval_seconds", 300)
                monitor_id = uuid4().hex
                self._monitor_tasks[monitor_id] = {
                    "source": source,
                    "keywords": keywords,
                    "interval_seconds": interval,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "status": "active",
                    "last_run": None,
                    "total_collected": 0,
                }
                result = self._create_task_result(
                    status="success",
                    data={
                        "monitor_id": monitor_id,
                        "source": source,
                        "keywords": keywords,
                        "interval_seconds": interval,
                        "message": f"Monitoring task created with ID {monitor_id}",
                    },
                )

            else:
                result = self._create_task_result(
                    status="failed",
                    data={},
                    errors=[f"Unknown task type: {task_type}"],
                )

        except Exception as exc:
            self.logger.error(f"Collector task failed: {exc}")
            result = self._create_task_result(
                status="failed",
                data={},
                errors=[str(exc)],
            )

        await self._log_execution(task, result)
        return result

    async def collect_from_source(
        self,
        source: str,
        keywords: List[str],
        max_results: int = 100,
        time_range: Optional[Dict] = None,
    ) -> List[Dict]:
        all_items: List[Dict] = []

        if source == "all":
            sources_to_query = list(self.collectors.keys())
            if not sources_to_query:
                sources_to_query = [s.value for s in IntelligenceSource]
        else:
            sources_to_query = [source]

        for src in sources_to_query:
            try:
                collector_fn = self.collectors.get(src)
                if collector_fn:
                    items = await collector_fn(
                        keywords=keywords,
                        max_results=max_results,
                        time_range=time_range,
                    )
                else:
                    self.logger.warning(f"No real collector for source '{src}', skipping to avoid fake data")
                    items = []

                for item in items:
                    raw_intel = self._normalize_raw_intelligence(item, src)
                    all_items.append(raw_intel)

                self.logger.info(
                    f"Collected {len(items)} items from {src}"
                )

            except Exception as exc:
                self.logger.error(
                    f"Failed to collect from {src}: {exc}"
                )
                continue

        for item in all_items:
            try:
                await self._store_raw_intelligence(item)
            except Exception as exc:
                self.logger.warning(
                    f"Failed to store collected item: {exc}"
                )

        self.logger.info(
            f"Total collected: {len(all_items)} items from {len(sources_to_query)} sources"
        )
        return all_items

    async def search_existing(
        self, query: str, n_results: int = 10
    ) -> List[Dict]:
        try:
            results = await self.vector_store.search_intelligence(
                query=query,
                n_results=n_results,
            )
            return results
        except Exception as exc:
            self.logger.error(f"Search existing intelligence failed: {exc}")
            return []

    async def deduplicate(self, items: List[Dict]) -> List[Dict]:
        if not items:
            return []

        unique_items: List[Dict] = []
        seen_ids: set = set()

        for item in items:
            item_id = item.get("id", "")
            if item_id and item_id in seen_ids:
                continue
            if item_id:
                seen_ids.add(item_id)

            content = item.get("content", "") or item.get("raw_content", "")
            if not content:
                unique_items.append(item)
                continue

            try:
                similar = await self.vector_store.search_intelligence(
                    query=content,
                    n_results=3,
                )
                is_duplicate = False
                for result in similar:
                    distance = result.get("distance")
                    if distance is not None and distance < 0.05:
                        existing_id = result.get("id", "")
                        if existing_id != item_id and existing_id in seen_ids:
                            is_duplicate = True
                            break

                if not is_duplicate:
                    unique_items.append(item)
                else:
                    self.logger.debug(
                        f"Deduplicated item: {item_id}"
                    )

            except Exception as exc:
                self.logger.warning(
                    f"Dedup check failed for item {item_id}: {exc}"
                )
                unique_items.append(item)

        self.logger.info(
            f"Deduplication: {len(items)} -> {len(unique_items)} items"
        )
        return unique_items

    async def _simulate_collect(
        self,
        source: str,
        keywords: List[str],
        max_results: int,
    ) -> List[Dict]:
        system_prompt = (
            "你是一个黑灰产情报模拟采集专家。根据给定的来源和关键词，"
            "模拟从该来源可能采集到的情报数据。\n\n"
            "返回JSON数组，每个元素包含：\n"
            "- content: 情报内容（包含黑话、暗语等真实特征）\n"
            "- source_url: 来源URL（模拟）\n"
            "- metadata: 元数据对象，包含author、timestamp等字段\n\n"
            "生成2-5条模拟情报。只返回JSON数组，不要其他内容。"
        )
        keyword_str = "、".join(keywords) if keywords else "黑灰产"
        prompt = (
            f"来源：{_sanitize_input(source)}\n"
            f"关键词：{_sanitize_input(keyword_str)}\n"
            f"最多条数：{min(max_results, 5)}\n\n"
            f"请模拟从该来源采集到的情报数据。"
        )

        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
            )
            if isinstance(result, list):
                return result[:max_results]
            if isinstance(result, dict):
                return [result]
        except Exception as exc:
            self.logger.warning(
                f"Simulated collection failed for {source}: {exc}"
            )
        return []

    def _normalize_raw_intelligence(
        self, item: Dict, source: str
    ) -> Dict:
        try:
            source_enum = IntelligenceSource(source)
        except ValueError:
            source_enum = IntelligenceSource.OTHER

        content = item.get("content", "")
        raw_content = item.get("raw_content", content)
        metadata = item.get("metadata", {})

        raw_intel = RawIntelligence(
            source=source_enum,
            source_url=item.get("source_url"),
            content=content,
            raw_content=raw_content,
            metadata=metadata,
        )

        return raw_intel.model_dump()

    async def _store_raw_intelligence(self, item: Dict):
        intel_id = item.get("id", uuid4().hex)
        content = item.get("content", "")
        if not content:
            return

        source = item.get("source", "other")
        metadata = {
            "source": source,
            "collected_at": item.get(
                "collected_at", datetime.now(timezone.utc).isoformat()
            ),
            "status": "raw",
        }
        extra_meta = item.get("metadata", {})
        if isinstance(extra_meta, dict):
            metadata.update(extra_meta)

        await self.vector_store.add_intelligence(
            intel_id=intel_id,
            content=content,
            metadata=metadata,
        )

    async def run_monitor(self, monitor_id: str) -> Dict:
        monitor = self._monitor_tasks.get(monitor_id)
        if not monitor:
            return {"error": f"Monitor task {monitor_id} not found"}

        if monitor["status"] != "active":
            return {"error": f"Monitor task {monitor_id} is not active"}

        try:
            collected = await self.collect_from_source(
                source=monitor["source"],
                keywords=monitor["keywords"],
                max_results=50,
            )
            try:
                deduped = await asyncio.wait_for(
                    self.deduplicate(collected), timeout=30.0
                )
            except asyncio.TimeoutError:
                self.logger.warning(f"Deduplication timed out (30s) for monitor {monitor_id}, returning all items")
                deduped = collected

            monitor["last_run"] = datetime.now(timezone.utc).isoformat()
            monitor["total_collected"] += len(deduped)

            return {
                "monitor_id": monitor_id,
                "new_items": len(deduped),
                "total_collected": monitor["total_collected"],
                "items": deduped,
            }
        except Exception as exc:
            self.logger.error(
                f"Monitor run failed for {monitor_id}: {exc}"
            )
            return {"error": str(exc)}

    def get_monitor_status(self, monitor_id: str) -> Optional[Dict]:
        return self._monitor_tasks.get(monitor_id)

    def list_monitors(self) -> List[Dict]:
        return [
            {"monitor_id": mid, **info}
            for mid, info in self._monitor_tasks.items()
        ]

    def stop_monitor(self, monitor_id: str) -> bool:
        monitor = self._monitor_tasks.get(monitor_id)
        if not monitor:
            return False
        monitor["status"] = "stopped"
        return True
