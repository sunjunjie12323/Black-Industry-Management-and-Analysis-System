import aiohttp
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from loguru import logger

from app.config import settings


class WeChatCollector:
    SOGOU_WECHAT_SEARCH = "https://weixin.sogou.com/weixin"

    def __init__(self):
        self.logger = logger.bind(collector="wechat")
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                },
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
        self.logger.info(f"Collecting from WeChat: keywords={keywords}, max_results={max_results}")

        items = await self._collect_sogou(keywords, max_results)

        if items:
            self.logger.info(f"Collected {len(items)} real items from Sogou WeChat")
        else:
            self.logger.error(
                "Sogou WeChat search returned no results. "
                "This may be due to: 1) No matching articles found for keywords; "
                "2) Sogou anti-crawl blocking (try again later or use a proxy); "
                "3) Network connectivity issues."
            )

        return items

    async def _collect_sogou(self, keywords: List[str], max_results: int) -> List[Dict]:
        session = await self._get_session()
        items: List[Dict] = []

        try:
            search_kw = " ".join(keywords) if keywords else "黑灰产 反诈"
            async with session.get(
                self.SOGOU_WECHAT_SEARCH,
                params={"type": "2", "query": search_kw, "s_from": "input"},
            ) as resp:
                if resp.status != 200:
                    self.logger.error(f"Sogou WeChat returned {resp.status}")
                    return items

                text = await resp.text()

                title_pattern = re.compile(
                    r'<a[^>]*href="(https?://mp\.weixin\.qq\.com/[^"]*)"[^>]*>([^<]+)</a>',
                    re.IGNORECASE,
                )
                matches = title_pattern.findall(text)

                for href, title in matches[:max_results]:
                    title = title.strip()
                    if not title or len(title) < 4:
                        continue

                    clean_title = re.sub(r'<[^>]+>', '', title)
                    if any(skip in clean_title for skip in ['登录', '注册', '搜狗', '微信安全']):
                        continue

                    items.append({
                        "content": f"[微信公众号] {clean_title}",
                        "source_url": href,
                        "metadata": {
                            "source": "sogou_wechat",
                            "title": clean_title,
                            "search_keyword": search_kw,
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        },
                    })

                if not matches:
                    account_pattern = re.compile(
                        r'<a[^>]*href="([^"]*)"[^>]*class="[^"]*txt-box[^"]*"[^>]*>[\s\S]*?<h3[^>]*>([^<]+)</h3>',
                        re.IGNORECASE,
                    )
                    account_matches = account_pattern.findall(text)
                    for href, title in account_matches[:max_results]:
                        title = title.strip()
                        if not title or len(title) < 4:
                            continue
                        items.append({
                            "content": f"[微信公众号] {title}",
                            "source_url": href if href.startswith("http") else f"https://weixin.sogou.com{href}",
                            "metadata": {
                                "source": "sogou_wechat",
                                "title": title,
                                "search_keyword": search_kw,
                                "collected_at": datetime.now(timezone.utc).isoformat(),
                            },
                        })

        except Exception as exc:
            self.logger.error(f"Sogou WeChat collection failed: {exc}")

        return items
