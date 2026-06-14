import aiohttp
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from loguru import logger

from app.config import settings

DIRECT_ACCESS_LEGAL_WARNING = (
    "⚠️ 法律风险警告：直接访问暗网可能违反当地法律法规。"
    "建议使用 IndirectModeCollector 通过合法API间接获取威胁情报数据。"
    "直接访问暗网存在以下风险：1) 可能违反《网络安全法》等法律；"
    "2) 可能涉及非法数据获取；3) 可能面临刑事责任。"
    "请确保您有合法授权并遵守所有适用法律。"
)


class DarkWebCollector:
    URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    URLHAUS_RECENT_LIMIT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"
    ABUSE_CH_MALWARE_BAZAAR = "https://mb-api.abuse.ch/api/v1/"
    THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
    URLHAUS_TEXT_FEED = "https://urlhaus.abuse.ch/downloads/text/"
    URLHAUS_CSV_FEED = "https://urlhaus.abuse.ch/downloads/csv/"
    MALWAREBAZAAR_CSV_FEED = "https://bazaar.abuse.ch/downloads/csv/"

    def __init__(self):
        self.logger = logger.bind(collector="darkweb")
        self._session: Optional[aiohttp.ClientSession] = None
        self._auth_key = settings.ABUSE_CH_AUTH_KEY

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=20)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json, text/html, text/csv, */*",
            }
            if self._auth_key:
                headers["Auth-Key"] = self._auth_key
            self._session = aiohttp.ClientSession(timeout=timeout, headers=headers)
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
        self.logger.warning(DIRECT_ACCESS_LEGAL_WARNING)
        self.logger.info(f"Collecting from DarkWeb/ThreatFeeds: keywords={keywords}, max_results={max_results}")

        items: List[Dict] = []

        try:
            urlhaus_items = await self._collect_urlhaus(max_results)
            items.extend(urlhaus_items)
        except Exception as exc:
            self.logger.warning(f"URLhaus failed: {exc}")

        if len(items) < max_results:
            try:
                malware_items = await self._collect_malware_bazaar(max_results - len(items))
                items.extend(malware_items)
            except Exception as exc:
                self.logger.warning(f"MalwareBazaar failed: {exc}")

        if len(items) < max_results:
            try:
                tf_items = await self._collect_threatfox(max_results - len(items))
                items.extend(tf_items)
            except Exception as exc:
                self.logger.warning(f"ThreatFox failed: {exc}")

        if items:
            self.logger.info(f"Collected {len(items)} real items from dark web/threat feeds")
        else:
            self.logger.warning("All dark web/threat feed sources failed. Trying fallback sources...")
            try:
                fallback_items = await self._collect_fallback_iocs(max_results)
                items.extend(fallback_items)
            except Exception as exc:
                self.logger.warning(f"Fallback IOC collection failed: {exc}")

        return items[:max_results]

    async def _collect_urlhaus(self, max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []

        if self._auth_key:
            try:
                url = self.URLHAUS_RECENT_LIMIT_URL.format(limit=min(max_results, 100))
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data.get("urls", [])[:max_results]:
                            threat = entry.get("threat", "unknown")
                            url_val = entry.get("url", "")
                            host = entry.get("host", "")
                            tags = entry.get("tags", [])

                            content = f"[URLhaus] 恶意URL: {url_val}"
                            if threat:
                                content += f" | 威胁: {threat}"
                            if host:
                                content += f" | 主机: {host}"
                            if tags:
                                content += f" | 标签: {','.join(str(t) for t in tags)}"

                            items.append({
                                "content": content,
                                "source_url": entry.get("urlhaus_reference", ""),
                                "metadata": {
                                    "source": "urlhaus",
                                    "threat_type": threat,
                                    "url": url_val,
                                    "host": host,
                                    "tags": tags,
                                    "reporter": entry.get("reporter", ""),
                                    "collected_at": datetime.now(timezone.utc).isoformat(),
                                },
                            })
                        if items:
                            return items
                    else:
                        self.logger.warning(f"URLhaus API returned {resp.status}, falling back to text feed")
            except Exception as exc:
                self.logger.warning(f"URLhaus API failed: {exc}, falling back to text feed")

        try:
            async with session.get(self.URLHAUS_TEXT_FEED) as resp:
                if resp.status != 200:
                    self.logger.warning(f"URLhaus text feed returned {resp.status}")
                    return items
                text = await resp.text()
                count = 0
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    content = f"[URLhaus] 恶意URL: {line}"
                    items.append({
                        "content": content,
                        "source_url": f"https://urlhaus.abuse.ch/url/{line}/",
                        "metadata": {
                            "source": "urlhaus_feed",
                            "url": line,
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })
                    count += 1
                    if count >= max_results:
                        break
        except Exception as exc:
            self.logger.warning(f"URLhaus text feed failed: {exc}")

        return items

    async def _collect_malware_bazaar(self, max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []

        if self._auth_key:
            try:
                payload = {"query": "get_recent", "selector": "time"}
                async with session.post(self.ABUSE_CH_MALWARE_BAZAAR, data=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data.get("data", [])[:max_results]:
                            sha256 = entry.get("sha256_hash", "")
                            malware_name = entry.get("malware", "")
                            family = entry.get("family", "")
                            tags = entry.get("tags", [])
                            delivery_method = entry.get("delivery_method", "")

                            content = f"[MalwareBazaar] 恶意软件样本: {malware_name}"
                            if family:
                                content += f" | 家族: {family}"
                            if delivery_method:
                                content += f" | 传播方式: {delivery_method}"
                            if tags:
                                content += f" | 标签: {','.join(str(t) for t in tags[:5])}"

                            items.append({
                                "content": content,
                                "source_url": f"https://bazaar.abuse.ch/sample/{sha256}/" if sha256 else "",
                                "metadata": {
                                    "source": "malware_bazaar",
                                    "sha256": sha256,
                                    "malware_name": malware_name,
                                    "family": family,
                                    "delivery_method": delivery_method,
                                    "tags": tags[:10] if tags else [],
                                    "collected_at": datetime.now(timezone.utc).isoformat(),
                                },
                            })
                        if items:
                            return items
                    else:
                        self.logger.warning(f"MalwareBazaar API returned {resp.status}, falling back to recent_detections")
            except Exception as exc:
                self.logger.warning(f"MalwareBazaar API failed: {exc}, falling back")

        try:
            payload = {"query": "recent_detections", "hours": 48}
            async with session.post(self.ABUSE_CH_MALWARE_BAZAAR, data=payload) as resp:
                if resp.status != 200:
                    self.logger.warning(f"MalwareBazaar recent_detections returned {resp.status}")
                    return items
                data = await resp.json(content_type=None)
                for entry in data.get("data", [])[:max_results]:
                    sha256 = entry.get("sha256_hash", "")
                    malware_name = entry.get("signature", "") or entry.get("file_name", "unknown")
                    first_seen = entry.get("first_seen", "")

                    content = f"[MalwareBazaar] 检测: {malware_name}"
                    if sha256:
                        content += f" | SHA256: {sha256[:16]}..."
                    if first_seen:
                        content += f" | 首次发现: {first_seen}"

                    items.append({
                        "content": content,
                        "source_url": f"https://bazaar.abuse.ch/sample/{sha256}/" if sha256 else "",
                        "metadata": {
                            "source": "malware_bazaar_detections",
                            "sha256": sha256,
                            "malware_name": malware_name,
                            "first_seen": first_seen,
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })
        except Exception as exc:
            self.logger.warning(f"MalwareBazaar recent_detections failed: {exc}")

        return items

    async def _collect_threatfox(self, max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []

        try:
            payload = {"query": "search_ioc", "search_term": "malware", "limit": max_results}
            async with session.post(self.THREATFOX_API, json=payload) as resp:
                if resp.status != 200:
                    self.logger.warning(f"ThreatFox returned {resp.status}")
                    return items
                data = await resp.json(content_type=None)
                for entry in data.get("data", [])[:max_results]:
                    ioc = entry.get("ioc", "")
                    ioc_type = entry.get("ioc_type", "")
                    malware = entry.get("malware_malbazaar", "") or entry.get("malware", "")
                    confidence = entry.get("confidence_level", 0)
                    tags = entry.get("tags", [])

                    content = f"[ThreatFox] IOC: {ioc}"
                    if ioc_type:
                        content += f" | 类型: {ioc_type}"
                    if malware:
                        content += f" | 恶意软件: {malware}"
                    if confidence:
                        content += f" | 置信度: {confidence}"

                    items.append({
                        "content": content,
                        "source_url": entry.get("link", ""),
                        "metadata": {
                            "source": "threatfox",
                            "ioc": ioc,
                            "ioc_type": ioc_type,
                            "malware": malware,
                            "confidence": confidence,
                            "tags": tags[:10] if tags else [],
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })
        except Exception as exc:
            self.logger.warning(f"ThreatFox collection failed: {exc}")

        return items

    async def _collect_fallback_iocs(self, max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []

        try:
            url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return items
                text = await resp.text()
                count = 0
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        domain = parts[-1]
                        if domain in ("localhost", "localhost.localdomain", "broadcasthost"):
                            continue
                        content = f"[StevenBlack Hosts] 恶意域名: {domain}"
                        items.append({
                            "content": content,
                            "source_url": "https://github.com/StevenBlack/hosts",
                            "metadata": {
                                "source": "stevenblack_hosts",
                                "domain": domain,
                                "collected_at": datetime.now(timezone.utc).isoformat(),
                            },
                        })
                        count += 1
                        if count >= max_results:
                            break
        except Exception as exc:
            self.logger.warning(f"StevenBlack hosts fallback failed: {exc}")

        return items


class IndirectModeCollector:
    URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
    CISA_KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    OTX_API_BASE = "https://otx.alienvault.com/api/v1"
    ABUSE_CH_THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self):
        self.logger = logger.bind(collector="indirect_mode")
        self._session: Optional[aiohttp.ClientSession] = None
        self._auth_key = settings.ABUSE_CH_AUTH_KEY
        self._otx_key = settings.ALIENVAULT_OTX_KEY

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=20)
            headers = {
                "User-Agent": "ThreatIntelAgent/IndirectMode/1.0",
                "Accept": "application/json",
            }
            if self._auth_key:
                headers["Auth-Key"] = self._auth_key
            if self._otx_key:
                headers["X-OTX-API-KEY"] = self._otx_key
            self._session = aiohttp.ClientSession(timeout=timeout, headers=headers)
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
        self.logger.info(f"IndirectMode collecting: keywords={keywords}, max_results={max_results}")
        items: List[Dict] = []

        try:
            urlhaus_items = await self._collect_urlhaus(max_results)
            items.extend(urlhaus_items)
        except Exception as exc:
            self.logger.warning(f"URLhaus indirect failed: {exc}")

        if len(items) < max_results:
            try:
                mb_items = await self._collect_malware_bazaar(max_results - len(items))
                items.extend(mb_items)
            except Exception as exc:
                self.logger.warning(f"MalwareBazaar indirect failed: {exc}")

        if len(items) < max_results:
            try:
                cisa_items = await self._collect_cisa_kev(max_results - len(items))
                items.extend(cisa_items)
            except Exception as exc:
                self.logger.warning(f"CISA KEV indirect failed: {exc}")

        if len(items) < max_results:
            try:
                otx_items = await self._collect_otx(max_results - len(items), keywords)
                items.extend(otx_items)
            except Exception as exc:
                self.logger.warning(f"AlienVault OTX indirect failed: {exc}")

        if len(items) < max_results:
            try:
                tf_items = await self._collect_threatfox(max_results - len(items))
                items.extend(tf_items)
            except Exception as exc:
                self.logger.warning(f"ThreatFox indirect failed: {exc}")

        for item in items:
            item["metadata"]["acquisition_mode"] = "indirect_api"

        self.logger.info(f"IndirectMode collected {len(items)} items from legal APIs")
        return items[:max_results]

    async def _collect_urlhaus(self, max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []
        try:
            url = f"{self.URLHAUS_API}?limit={min(max_results, 100)}"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return items
                data = await resp.json(content_type=None)
                for entry in data.get("urls", [])[:max_results]:
                    threat = entry.get("threat", "unknown")
                    url_val = entry.get("url", "")
                    host = entry.get("host", "")
                    content = f"[URLhaus-API] 恶意URL: {url_val}"
                    if threat:
                        content += f" | 威胁: {threat}"
                    if host:
                        content += f" | 主机: {host}"
                    items.append({
                        "content": content,
                        "source_url": entry.get("urlhaus_reference", ""),
                        "metadata": {
                            "source": "urlhaus_api",
                            "threat_type": threat,
                            "url": url_val,
                            "host": host,
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })
        except Exception as exc:
            self.logger.warning(f"URLhaus API indirect failed: {exc}")
        return items

    async def _collect_malware_bazaar(self, max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []
        try:
            payload = {"query": "get_recent", "selector": "time"}
            async with session.post(self.MALWAREBAZAAR_API, data=payload) as resp:
                if resp.status != 200:
                    return items
                data = await resp.json(content_type=None)
                for entry in data.get("data", [])[:max_results]:
                    sha256 = entry.get("sha256_hash", "")
                    malware_name = entry.get("malware", "")
                    family = entry.get("family", "")
                    content = f"[MalwareBazaar-API] 恶意软件: {malware_name}"
                    if family:
                        content += f" | 家族: {family}"
                    items.append({
                        "content": content,
                        "source_url": f"https://bazaar.abuse.ch/sample/{sha256}/" if sha256 else "",
                        "metadata": {
                            "source": "malware_bazaar_api",
                            "sha256": sha256,
                            "malware_name": malware_name,
                            "family": family,
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })
        except Exception as exc:
            self.logger.warning(f"MalwareBazaar API indirect failed: {exc}")
        return items

    async def _collect_cisa_kev(self, max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []
        try:
            async with session.get(self.CISA_KEV_API) as resp:
                if resp.status != 200:
                    return items
                data = await resp.json(content_type=None)
                vulnerabilities = data.get("vulnerabilities", [])[:max_results]
                for vuln in vulnerabilities:
                    cve_id = vuln.get("cveID", "")
                    product = vuln.get("product", "")
                    vuln_type = vuln.get("vulnerabilityName", "")
                    content = f"[CISA-KEV] 已知被利用漏洞: {cve_id}"
                    if vuln_type:
                        content += f" | {vuln_type}"
                    if product:
                        content += f" | 产品: {product}"
                    items.append({
                        "content": content,
                        "source_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog" if cve_id else "",
                        "metadata": {
                            "source": "cisa_kev",
                            "cve_id": cve_id,
                            "product": product,
                            "vulnerability_name": vuln_type,
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })
        except Exception as exc:
            self.logger.warning(f"CISA KEV indirect failed: {exc}")
        return items

    async def _collect_otx(self, max_results: int, keywords: List[str]) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []
        if not self._otx_key:
            self.logger.debug("AlienVault OTX API key not configured, skipping")
            return items
        try:
            url = f"{self.OTX_API_BASE}/pulse/subscribed?limit={min(max_results, 50)}"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return items
                data = await resp.json(content_type=None)
                for pulse in data.get("results", [])[:max_results]:
                    name = pulse.get("name", "")
                    description = pulse.get("description", "")[:200] if pulse.get("description") else ""
                    content = f"[OTX] 威胁情报: {name}"
                    if description:
                        content += f" | {description}"
                    items.append({
                        "content": content,
                        "source_url": pulse.get("url", ""),
                        "metadata": {
                            "source": "alienvault_otx",
                            "pulse_name": name,
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })
        except Exception as exc:
            self.logger.warning(f"AlienVault OTX indirect failed: {exc}")
        return items

    async def _collect_threatfox(self, max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []
        try:
            payload = {"query": "search_ioc", "search_term": "malware", "limit": max_results}
            async with session.post(self.ABUSE_CH_THREATFOX, json=payload) as resp:
                if resp.status != 200:
                    return items
                data = await resp.json(content_type=None)
                for entry in data.get("data", [])[:max_results]:
                    ioc = entry.get("ioc", "")
                    ioc_type = entry.get("ioc_type", "")
                    malware = entry.get("malware", "")
                    content = f"[ThreatFox-API] IOC: {ioc}"
                    if ioc_type:
                        content += f" | 类型: {ioc_type}"
                    if malware:
                        content += f" | 恶意软件: {malware}"
                    items.append({
                        "content": content,
                        "source_url": entry.get("link", ""),
                        "metadata": {
                            "source": "threatfox_api",
                            "ioc": ioc,
                            "ioc_type": ioc_type,
                            "malware": malware,
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })
        except Exception as exc:
            self.logger.warning(f"ThreatFox API indirect failed: {exc}")
        return items
