import re
from typing import Dict, List, Optional

import httpx
from loguru import logger


class WebSearchService:
    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(15.0, connect=5.0),
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                },
                follow_redirects=True,
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def search(self, query: str, max_results: int = 5) -> List[Dict]:
        results = []
        try:
            ddg_results = await self._search_duckduckgo(query, max_results)
            results.extend(ddg_results)
        except Exception as exc:
            logger.warning(f"DuckDuckGo search failed: {exc}")

        if len(results) < max_results:
            try:
                bing_results = await self._search_bing(query, max_results - len(results))
                results.extend(bing_results)
            except Exception as exc:
                logger.warning(f"Bing search failed: {exc}")

        return results[:max_results]

    async def _search_duckduckgo(self, query: str, max_results: int = 5) -> List[Dict]:
        client = await self._get_client()
        results = []

        try:
            resp = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query, "kl": "cn-zh"},
            )
            resp.raise_for_status()
            html = resp.text

            title_pattern = re.compile(
                r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>',
                re.DOTALL,
            )
            snippet_pattern = re.compile(
                r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
                re.DOTALL,
            )

            titles = title_pattern.findall(html)
            snippets = snippet_pattern.findall(html)

            for i, (url, title) in enumerate(titles[:max_results]):
                clean_title = re.sub(r"<[^>]+>", "", title).strip()
                snippet = ""
                if i < len(snippets):
                    snippet = re.sub(r"<[^>]+>", "", snippets[i]).strip()
                results.append({
                    "title": clean_title,
                    "url": url,
                    "snippet": snippet,
                    "source": "DuckDuckGo",
                })
        except Exception as exc:
            logger.warning(f"DuckDuckGo HTML search error: {exc}")

        if not results:
            try:
                resp = await client.get(
                    "https://api.duckduckgo.com/",
                    params={"q": query, "format": "json", "no_html": 1, "skip_disambig": 1},
                )
                resp.raise_for_status()
                data = resp.json()

                abstract = data.get("Abstract", "")
                abstract_url = data.get("AbstractURL", "")
                abstract_title = data.get("Heading", "")
                if abstract:
                    results.append({
                        "title": abstract_title,
                        "url": abstract_url,
                        "snippet": abstract,
                        "source": "DuckDuckGo",
                    })

                for topic in data.get("RelatedTopics", [])[:max_results - len(results)]:
                    if isinstance(topic, dict) and "Text" in topic:
                        results.append({
                            "title": topic.get("Text", "")[:80],
                            "url": topic.get("FirstURL", ""),
                            "snippet": topic.get("Text", ""),
                            "source": "DuckDuckGo",
                        })
            except Exception as exc:
                logger.warning(f"DuckDuckGo API search error: {exc}")

        return results[:max_results]

    async def _search_bing(self, query: str, max_results: int = 5) -> List[Dict]:
        client = await self._get_client()
        results = []

        try:
            resp = await client.get(
                "https://www.bing.com/search",
                params={"q": query, "count": max_results, "setlang": "zh-Hans"},
            )
            resp.raise_for_status()
            html = resp.text

            li_pattern = re.compile(
                r'<li class="b_algo">(.*?)</li>',
                re.DOTALL,
            )
            href_pattern = re.compile(r'<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>', re.DOTALL)
            p_pattern = re.compile(r'<p[^>]*>(.*?)</p>', re.DOTALL)

            for match in li_pattern.findall(html)[:max_results]:
                block = match
                href_match = href_pattern.search(block)
                if not href_match:
                    continue
                url = href_match.group(1)
                title = re.sub(r"<[^>]+>", "", href_match.group(2)).strip()
                snippet = ""
                p_match = p_pattern.search(block)
                if p_match:
                    snippet = re.sub(r"<[^>]+>", "", p_match.group(1)).strip()
                if title and url.startswith("http"):
                    results.append({
                        "title": title,
                        "url": url,
                        "snippet": snippet,
                        "source": "Bing",
                    })
        except Exception as exc:
            logger.warning(f"Bing search error: {exc}")

        return results[:max_results]

    def format_results_for_context(self, results: List[Dict]) -> str:
        if not results:
            return ""
        lines = ["【网络搜索结果】"]
        for i, r in enumerate(results, 1):
            lines.append(f"{i}. {r['title']}")
            if r.get("snippet"):
                lines.append(f"   摘要: {r['snippet'][:200]}")
            if r.get("url"):
                lines.append(f"   来源: {r['url']}")
        return "\n".join(lines)


web_search_service = WebSearchService()
