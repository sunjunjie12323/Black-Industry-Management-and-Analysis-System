import asyncio
import aiohttp
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from loguru import logger


class RealTimeCollector:
    URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    ALIENVAULT_OTX = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    CISA_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_DIR = "./cache/realtime"
    CACHE_TTL_SECONDS = 3600

    def __init__(self):
        self.logger = logger.bind(collector="realtime")
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=20)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": "ThreatIntelAgent/1.0"},
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def collect(
        self,
        keywords: List[str],
        max_results: int = 50,
        time_range: Optional[Dict] = None,
        **kwargs: Any,
    ) -> List[Dict]:
        self.logger.info(f"RealTimeCollector: keywords={keywords}, max_results={max_results}")
        items: List[Dict] = []

        try:
            urlhaus_items = await self._collect_urlhaus(max_results)
            items.extend(urlhaus_items)
        except Exception as exc:
            self.logger.warning(f"URLhaus collection failed: {exc}")

        if len(items) < max_results:
            try:
                otx_items = await self._collect_alienvault_otx(max_results - len(items))
                items.extend(otx_items)
            except Exception as exc:
                self.logger.warning(f"AlienVault OTX collection failed: {exc}")

        if len(items) < max_results:
            try:
                cisa_items = await self._collect_cisa_kev(max_results - len(items))
                items.extend(cisa_items)
            except Exception as exc:
                self.logger.warning(f"CISA KEV collection failed: {exc}")

        if not items:
            cached = self._load_cache()
            if cached:
                self.logger.info(f"Using cached data: {len(cached)} items")
                items = cached

        if not items:
            self.logger.error(
                "All real-time sources failed and no cache available. "
                "URLhaus, AlienVault OTX, and CISA KEV are free APIs. "
                "Check network connectivity."
            )

        if items:
            self._save_cache(items)

        self.logger.info(f"RealTimeCollector: collected {len(items)} items total")
        return items[:max_results]

    def _load_cache(self) -> List[Dict]:
        cache_path = Path(self.CACHE_DIR) / "latest.json"
        if not cache_path.exists():
            return []
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_at = data.get("cached_at", "")
            if cached_at:
                cached_time = datetime.fromisoformat(cached_at)
                age = (datetime.now(timezone.utc) - cached_time).total_seconds()
                if age > self.CACHE_TTL_SECONDS:
                    self.logger.info(f"Cache expired ({age:.0f}s old)")
                    return []
            return data.get("items", [])
        except Exception as exc:
            self.logger.warning(f"Failed to load cache: {exc}")
            return []

    def _save_cache(self, items: List[Dict]):
        cache_path = Path(self.CACHE_DIR) / "latest.json"
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "count": len(items),
                "items": items,
            }
            tmp_path = cache_path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
            tmp_path.replace(cache_path)
            self.logger.debug(f"Cached {len(items)} items")
        except Exception as exc:
            self.logger.warning(f"Failed to save cache: {exc}")

    async def _collect_urlhaus(self, max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []

        try:
            async with session.post(self.URLHAUS_RECENT) as resp:
                if resp.status != 200:
                    self.logger.warning(f"URLhaus API returned {resp.status}")
                    return items
                data = await resp.json(content_type=None)
                urls = data.get("urls", [])

                for entry in urls[:max_results]:
                    threat_type = entry.get("threat", "unknown")
                    url = entry.get("url", "")
                    host = entry.get("host", "")
                    tags = entry.get("tags", [])

                    content = f"[URLhaus] 恶意URL: {url}"
                    if threat_type:
                        content += f" | 威胁类型: {threat_type}"
                    if host:
                        content += f" | 主机: {host}"
                    if tags:
                        content += f" | 标签: {','.join(str(t) for t in tags)}"

                    items.append({
                        "content": content,
                        "source_url": entry.get("urlhaus_reference", ""),
                        "metadata": {
                            "source": "urlhaus",
                            "threat_type": threat_type,
                            "url": url,
                            "host": host,
                            "tags": tags,
                            "reporter": entry.get("reporter", ""),
                            "first_seen": entry.get("date_added", ""),
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })
        except Exception as exc:
            self.logger.warning(f"URLhaus request failed: {exc}")

        return items

    async def _collect_alienvault_otx(self, max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []

        try:
            async with session.get(self.ALIENVAULT_OTX) as resp:
                if resp.status != 200:
                    self.logger.warning(f"AlienVault OTX returned {resp.status}")
                    return items
                data = await resp.json(content_type=None)
                pulses = data.get("results", [])

                for pulse in pulses[:max_results]:
                    name = pulse.get("name", "")
                    description = pulse.get("description", "")[:200] if pulse.get("description") else ""
                    author = pulse.get("author", {}).get("username", "")
                    tags = pulse.get("tags", [])
                    indicators = pulse.get("indicators", [])

                    content = f"[OTX] 威胁情报: {name}"
                    if description:
                        content += f" | {description[:100]}"
                    if tags:
                        content += f" | 标签: {','.join(str(t) for t in tags[:5])}"

                    ioc_count = len(indicators)
                    ioc_types = list(set(ind.get("type", "") for ind in indicators[:20]))

                    items.append({
                        "content": content,
                        "source_url": pulse.get("url", ""),
                        "metadata": {
                            "source": "alienvault_otx",
                            "pulse_name": name,
                            "author": author,
                            "tags": tags[:10],
                            "ioc_count": ioc_count,
                            "ioc_types": ioc_types,
                            "modified": pulse.get("modified", ""),
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })
        except Exception as exc:
            self.logger.warning(f"AlienVault OTX request failed: {exc}")

        return items

    async def _collect_cisa_kev(self, max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []

        try:
            async with session.get(self.CISA_FEED) as resp:
                if resp.status != 200:
                    self.logger.warning(f"CISA KEV returned {resp.status}")
                    return items
                data = await resp.json(content_type=None)
                vulns = data.get("vulnerabilities", [])

                for vuln in vulns[:max_results]:
                    cve_id = vuln.get("cveID", "")
                    product = vuln.get("product", "")
                    vuln_type = vuln.get("vulnerabilityName", "")
                    date_added = vuln.get("dateAdded", "")

                    content = f"[CISA KEV] 已知被利用漏洞: {cve_id}"
                    if vuln_type:
                        content += f" | {vuln_type}"
                    if product:
                        content += f" | 产品: {product}"

                    items.append({
                        "content": content,
                        "source_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                        "metadata": {
                            "source": "cisa_kev",
                            "cve_id": cve_id,
                            "product": product,
                            "vulnerability_name": vuln_type,
                            "date_added": date_added,
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })
        except Exception as exc:
            self.logger.warning(f"CISA KEV request failed: {exc}")

        return items
