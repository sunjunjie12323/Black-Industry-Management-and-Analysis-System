import aiohttp
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from loguru import logger

from app.config import settings


class CommercialCollector:
    VT_API_BASE = "https://www.virustotal.com/api/v3"
    THREATBOOK_API = "https://api.threatbook.cn/v3/threat_intelligence"
    QIANXIN_API = "https://ti.qianxin.com/api/v1/threat"

    def __init__(self):
        self.logger = logger.bind(collector="commercial")
        self._session: Optional[aiohttp.ClientSession] = None
        self._vt_key = settings.VIRUSTOTAL_API_KEY
        self._threatbook_key = settings.THREATBOOK_API_KEY
        self._qianxin_key = settings.QIANXIN_API_KEY

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
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
        **kwargs: Any,
    ) -> List[Dict]:
        self.logger.info(f"Collecting from commercial sources: keywords={keywords}")
        items: List[Dict] = []

        if self._vt_key:
            try:
                vt_items = await self._collect_virustotal(keywords, max_results)
                items.extend(vt_items)
            except Exception as exc:
                self.logger.warning(f"VirusTotal failed: {exc}")
        else:
            self.logger.info("VirusTotal API key not configured, skipping")

        if self._threatbook_key and len(items) < max_results:
            try:
                tb_items = await self._collect_threatbook(keywords, max_results - len(items))
                items.extend(tb_items)
            except Exception as exc:
                self.logger.warning(f"ThreatBook failed: {exc}")
        else:
            if not self._threatbook_key:
                self.logger.info("ThreatBook API key not configured, skipping")

        if self._qianxin_key and len(items) < max_results:
            try:
                qx_items = await self._collect_qianxin(keywords, max_results - len(items))
                items.extend(qx_items)
            except Exception as exc:
                self.logger.warning(f"Qianxin TI failed: {exc}")
        else:
            if not self._qianxin_key:
                self.logger.info("Qianxin TI API key not configured, skipping")

        if items:
            self.logger.info(f"Collected {len(items)} items from commercial sources")
        else:
            configured = sum(1 for k in [self._vt_key, self._threatbook_key, self._qianxin_key] if k)
            if configured == 0:
                self.logger.error(
                    "No commercial API keys configured. "
                    "Set VIRUSTOTAL_API_KEY, THREATBOOK_API_KEY, or QIANXIN_API_KEY in .env"
                )
            else:
                self.logger.warning(f"{configured} commercial source(s) configured but returned no results")

        return items[:max_results]

    async def _collect_virustotal(self, keywords: List[str], max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []
        headers = {"x-apikey": self._vt_key}

        for kw in keywords[:3]:
            try:
                async with session.get(
                    f"{self.VT_API_BASE}/search",
                    params={"query": kw, "limit": min(max_results, 20)},
                    headers=headers,
                ) as resp:
                    if resp.status != 200:
                        self.logger.warning(f"VirusTotal returned {resp.status} for '{kw}'")
                        continue
                    data = await resp.json(content_type=None)

                    for item in data.get("data", [])[:max_results]:
                        item_type = item.get("type", "unknown")
                        attrs = item.get("attributes", {})
                        item_id = item.get("id", "")

                        content = f"[VirusTotal] {item_type}: {item_id}"
                        if item_type == "file":
                            names = attrs.get("names", [])
                            threat_label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "")
                            if threat_label:
                                content += f" | 威胁: {threat_label}"
                            if names:
                                content += f" | 名称: {names[0]}"
                        elif item_type == "domain":
                            reputation = attrs.get("reputation", 0)
                            content += f" | 信誉: {reputation}"
                        elif item_type == "ip_address":
                            continent = attrs.get("continent", "")
                            country = attrs.get("country", "")
                            content += f" | 位置: {country}/{continent}"
                        elif item_type == "url":
                            last_analysis_stats = attrs.get("last_analysis_stats", {})
                            malicious = last_analysis_stats.get("malicious", 0)
                            content += f" | 恶意检测: {malicious}个引擎"

                        items.append({
                            "content": content,
                            "source_url": f"https://www.virustotal.com/gui/{item_type}/{item_id}",
                            "metadata": {
                                "source": "virustotal",
                                "vt_type": item_type,
                                "vt_id": item_id,
                                "collected_at": datetime.now(timezone.utc).isoformat(),
                            },
                        })
            except Exception as exc:
                self.logger.warning(f"VirusTotal search failed for '{kw}': {exc}")

        return items

    async def _collect_threatbook(self, keywords: List[str], max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []

        for kw in keywords[:3]:
            try:
                async with session.get(
                    self.THREATBOOK_API,
                    params={"apikey": self._threatbook_key, "query": kw, "limit": min(max_results, 20)},
                ) as resp:
                    if resp.status != 200:
                        self.logger.warning(f"ThreatBook returned {resp.status} for '{kw}'")
                        continue
                    data = await resp.json(content_type=None)

                    for threat in data.get("data", {}).get("threats", [])[:max_results]:
                        threat_id = threat.get("id", "")
                        threat_type = threat.get("type", "")
                        severity = threat.get("severity", "")
                        description = threat.get("description", "")[:200]
                        tags = threat.get("tags", [])

                        content = f"[微步在线] {threat_type}: {threat_id}"
                        if severity:
                            content += f" | 严重度: {severity}"
                        if description:
                            content += f" | {description[:100]}"
                        if tags:
                            content += f" | 标签: {','.join(str(t) for t in tags[:5])}"

                        items.append({
                            "content": content,
                            "source_url": threat.get("url", f"https://x.threatbook.com/node/{threat_id}"),
                            "metadata": {
                                "source": "threatbook",
                                "threat_id": threat_id,
                                "threat_type": threat_type,
                                "severity": severity,
                                "tags": tags[:10],
                                "collected_at": datetime.now(timezone.utc).isoformat(),
                            },
                        })
            except Exception as exc:
                self.logger.warning(f"ThreatBook search failed for '{kw}': {exc}")

        return items

    async def _collect_qianxin(self, keywords: List[str], max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []

        for kw in keywords[:3]:
            try:
                async with session.get(
                    self.QIANXIN_API,
                    params={"apikey": self._qianxin_key, "query": kw, "limit": min(max_results, 20)},
                ) as resp:
                    if resp.status != 200:
                        self.logger.warning(f"Qianxin TI returned {resp.status} for '{kw}'")
                        continue
                    data = await resp.json(content_type=None)

                    for threat in data.get("data", [])[:max_results]:
                        threat_id = threat.get("id", "")
                        threat_name = threat.get("name", "")
                        threat_type = threat.get("type", "")
                        severity = threat.get("severity", "")
                        description = threat.get("description", "")[:200]

                        content = f"[奇安信TI] {threat_type}: {threat_name}"
                        if severity:
                            content += f" | 严重度: {severity}"
                        if description:
                            content += f" | {description[:100]}"

                        items.append({
                            "content": content,
                            "source_url": threat.get("url", f"https://ti.qianxin.com/threat/{threat_id}"),
                            "metadata": {
                                "source": "qianxin",
                                "threat_id": threat_id,
                                "threat_name": threat_name,
                                "threat_type": threat_type,
                                "severity": severity,
                                "collected_at": datetime.now(timezone.utc).isoformat(),
                            },
                        })
            except Exception as exc:
                self.logger.warning(f"Qianxin TI search failed for '{kw}': {exc}")

        return items

    def get_status(self) -> Dict:
        return {
            "virustotal": {"configured": bool(self._vt_key), "source": "virustotal"},
            "threatbook": {"configured": bool(self._threatbook_key), "source": "threatbook"},
            "qianxin": {"configured": bool(self._qianxin_key), "source": "qianxin"},
        }
