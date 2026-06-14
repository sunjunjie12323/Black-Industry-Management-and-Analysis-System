"""
Real Data Provider — 从公开API获取真实威胁情报统计数据
为经济系统提供有据可查的损失估算和市场规模数据
数据来源：
  - CISA KEV: 已知被利用漏洞目录
  - URLhaus: 恶意URL实时数据
  - MalwareBazaar: 恶意软件样本统计
  - AlienVault OTX: 威胁情报脉冲统计
  - Chainalysis/慢雾: 链上安全事件（公开报告数据）
"""
import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from loguru import logger

import httpx


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
MALWAREBAZAAR_RECENT_URL = "https://mb-api.abuse.ch/api/v1/"
OTX_PULSE_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

SECTOR_KEYWORD_MAP = {
    "fraud": ["fraud", "scam", "phishing", "诈骗", "钓鱼", "杀猪盘", "套路贷"],
    "gambling": ["gambling", "赌", "博彩", "彩票"],
    "phishing": ["phishing", "钓鱼", "credential", "仿冒"],
    "money_laundering": ["laundering", "洗钱", "mixer", "tornado"],
    "account_trading": ["account", "账号", "stealer", "窃取", "data breach"],
    "tool_sales": ["malware", "tool", "exploit", "工具", "木马", "rat"],
    "data_broker": ["data breach", "leak", "泄露", "脱库", "database"],
    "ransomware": ["ransomware", "勒索", "encrypt", "lockbit"],
    "ddos_service": ["ddos", "dos", "拒绝服务", "booter"],
    "phishing_kit": ["phishing kit", "钓鱼工具", "template"],
}

PUBLISHED_LOSS_DATA = {
    "fraud": {
        "source": "中国公安部2024年度报告/国家反诈中心",
        "annual_loss_cny": 3537e8,
        "annual_cases": 464e4,
        "avg_loss_per_case": 7623,
        "year": 2024,
    },
    "ransomware": {
        "source": "Chainalysis 2024 Crypto Crime Report",
        "annual_loss_usd": 11e8,
        "annual_cases": None,
        "avg_ransom_usd": 1500000,
        "year": 2024,
    },
    "money_laundering": {
        "source": "联合国毒品和犯罪问题办公室(UNODC)估算",
        "annual_loss_usd": 800e8,
        "pct_gdp": 0.02,
        "year": 2023,
    },
    "phishing": {
        "source": "APWG Phishing Activity Trends Report 2024",
        "annual_attacks": 48e6,
        "avg_loss_per_attack_usd": 136,
        "year": 2024,
    },
    "data_broker": {
        "source": "IBM Cost of a Data Breach Report 2024",
        "avg_cost_per_breach_usd": 488e4,
        "annual_breaches_global": 3200,
        "year": 2024,
    },
    "gambling": {
        "source": "中国公安部打击跨境赌博专项行动2024",
        "annual_loss_cny": 5000e8,
        "year": 2024,
    },
    "account_trading": {
        "source": "SpyCloud Annual Identity Exposure Report 2024",
        "exposed_credentials": 225e8,
        "avg_account_value_usd": 15,
        "year": 2024,
    },
    "tool_sales": {
        "source": "Kaspersky/Group-IB地下市场监测",
        "market_size_usd": 5e8,
        "year": 2024,
    },
    "ddos_service": {
        "source": "Cloudflare DDoS Threat Report 2024",
        "annual_attacks": 143e4,
        "avg_cost_per_hour_usd": 10000,
        "year": 2024,
    },
    "phishing_kit": {
        "source": "Group-IB Hi-Tech Crime Trends 2024",
        "market_size_usd": 2e8,
        "year": 2024,
    },
}

CACHE_DIR = Path("./economic_data/real_data_cache")
CACHE_TTL_SECONDS = 3600


@dataclass
class RealDataPoint:
    sector: str
    metric_name: str
    value: float
    unit: str
    source: str
    source_url: str
    collected_at: str
    confidence: float

    def to_dict(self):
        return asdict(self)


class RealDataProvider:
    def __init__(self, cache_dir: str = None):
        self.cache_dir = Path(cache_dir) if cache_dir else CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, dict] = {}
        self._load_cache()

    def _load_cache(self):
        cache_file = self.cache_dir / "api_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

    def _save_cache(self):
        cache_file = self.cache_dir / "api_cache.json"
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, ensure_ascii=False, default=str)
        except Exception:
            pass

    def _is_cache_valid(self, key: str) -> bool:
        if key not in self._cache:
            return False
        entry = self._cache[key]
        cached_at = entry.get("cached_at", "")
        if not cached_at:
            return False
        try:
            cached_time = datetime.fromisoformat(cached_at)
            age = (datetime.now(timezone.utc) - cached_time).total_seconds()
            return age < CACHE_TTL_SECONDS
        except Exception:
            return False

    async def _fetch_json(self, url: str, method: str = "GET", data: dict = None, timeout: float = 15.0) -> Optional[dict]:
        cache_key = hashlib.md5(f"{method}:{url}:{data}".encode()).hexdigest()
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key].get("data")

        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                if method == "GET":
                    resp = await client.get(url)
                else:
                    resp = await client.post(url, data=data)
                resp.raise_for_status()
                result = resp.json()

            self._cache[cache_key] = {
                "data": result,
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "url": url,
            }
            self._save_cache()
            return result
        except Exception as exc:
            logger.warning(f"Failed to fetch {url}: {exc}")
            return None

    async def fetch_cisa_kev_stats(self) -> List[RealDataPoint]:
        data = await self._fetch_json(CISA_KEV_URL)
        points = []
        if data and "vulnerabilities" in data:
            vulns = data["vulnerabilities"]
            total = len(vulns)
            points.append(RealDataPoint(
                sector="tool_sales",
                metric_name="known_exploited_vulnerabilities",
                value=float(total),
                unit="count",
                source="CISA KEV",
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                collected_at=datetime.now(timezone.utc).isoformat(),
                confidence=0.95,
            ))
            recent_count = 0
            cutoff = datetime.now(timezone.utc) - timedelta(days=30)
            for v in vulns:
                date_str = v.get("dateAdded", "")
                if date_str:
                    try:
                        added = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                        if added > cutoff:
                            recent_count += 1
                    except Exception:
                        pass
            points.append(RealDataPoint(
                sector="tool_sales",
                metric_name="new_exploited_vulns_30d",
                value=float(recent_count),
                unit="count",
                source="CISA KEV",
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                collected_at=datetime.now(timezone.utc).isoformat(),
                confidence=0.95,
            ))
        return points

    async def fetch_urlhaus_stats(self) -> List[RealDataPoint]:
        data = await self._fetch_json(URLHAUS_RECENT_URL)
        points = []
        if data and "urls" in data:
            urls = data["urls"]
            total = len(urls)
            points.append(RealDataPoint(
                sector="phishing",
                metric_name="recent_malicious_urls",
                value=float(total),
                unit="count",
                source="URLhaus",
                source_url="https://urlhaus.abuse.ch/",
                collected_at=datetime.now(timezone.utc).isoformat(),
                confidence=0.90,
            ))
            threat_counts: Dict[str, int] = defaultdict(int)
            for entry in urls:
                threat = entry.get("threat", "unknown").lower()
                for sector, keywords in SECTOR_KEYWORD_MAP.items():
                    if any(kw in threat for kw in keywords):
                        threat_counts[sector] += 1
                        break
                else:
                    threat_counts["phishing"] += 1
            for sector, count in threat_counts.items():
                points.append(RealDataPoint(
                    sector=sector,
                    metric_name="urlhaus_threat_count",
                    value=float(count),
                    unit="count",
                    source="URLhaus",
                    source_url="https://urlhaus.abuse.ch/",
                    collected_at=datetime.now(timezone.utc).isoformat(),
                    confidence=0.85,
                ))
        return points

    async def fetch_malwarebazaar_stats(self) -> List[RealDataPoint]:
        data = await self._fetch_json(
            MALWAREBAZAAR_RECENT_URL,
            method="POST",
            data={"query": "get_recent", "selector": "24h"},
        )
        points = []
        if data and "data" in data:
            samples = data["data"]
            total = len(samples) if isinstance(samples, list) else 0
            points.append(RealDataPoint(
                sector="tool_sales",
                metric_name="malware_samples_24h",
                value=float(total),
                unit="count",
                source="MalwareBazaar",
                source_url="https://bazaar.abuse.ch/",
                collected_at=datetime.now(timezone.utc).isoformat(),
                confidence=0.90,
            ))
        return points

    def get_published_loss_data(self, sector: str) -> Optional[Dict]:
        return PUBLISHED_LOSS_DATA.get(sector)

    def get_all_published_sources(self) -> Dict[str, Dict]:
        return PUBLISHED_LOSS_DATA

    async def collect_all(self) -> List[RealDataPoint]:
        all_points = []
        tasks = [
            self.fetch_cisa_kev_stats(),
            self.fetch_urlhaus_stats(),
            self.fetch_malwarebazaar_stats(),
        ]
        for task in tasks:
            try:
                points = await task
                all_points.extend(points)
            except Exception as exc:
                logger.warning(f"Data collection task failed: {exc}")
        logger.info(f"RealDataProvider collected {len(all_points)} real data points")
        return all_points

    def compute_loss_estimate(self, sector: str, threat_level: str) -> Tuple[float, str]:
        published = self.get_published_loss_data(sector)
        if not published:
            return 0.0, "无公开数据"

        multipliers = {"critical": 1.0, "high": 0.3, "medium": 0.1, "low": 0.03, "info": 0.005}
        mult = multipliers.get(threat_level, 0.01)

        if "annual_loss_cny" in published:
            daily_loss = published["annual_loss_cny"] / 365
            estimate = daily_loss * mult * 30
            return estimate, f"基于{published['source']}({published['year']}年)年损失{published['annual_loss_cny']/1e8:.0f}亿元，按{threat_level}级别{mult*100:.0f}%比例×30天估算"
        elif "annual_loss_usd" in published:
            daily_loss = published["annual_loss_usd"] / 365
            estimate = daily_loss * mult * 30
            return estimate, f"基于{published['source']}({published['year']}年)年损失${published['annual_loss_usd']/1e8:.1f}B，按{threat_level}级别{mult*100:.0f}%比例×30天估算"
        elif "market_size_usd" in published:
            estimate = published["market_size_usd"] * mult * 0.1
            return estimate, f"基于{published['source']}({published['year']}年)市场规模${published['market_size_usd']/1e6:.0f}M，按{threat_level}级别影响估算"
        elif "avg_cost_per_breach_usd" in published:
            estimate = published["avg_cost_per_breach_usd"] * mult * 10
            return estimate, f"基于{published['source']}({published['year']}年)单次泄露成本${published['avg_cost_per_breach_usd']/1e4:.0f}万"
        else:
            return 0.0, "数据格式不支持估算"
