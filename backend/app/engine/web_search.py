from typing import Dict, List, Optional
from dataclasses import dataclass, field

import httpx
from loguru import logger

from app.config import settings


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str
    source: str
    relevance_score: float = 0.0


class WebSearchService:
    def __init__(self):
        self._otx_key = settings.ALIENVAULT_OTX_KEY
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0), headers={"User-Agent": "ThreatIntelAgent/2.3"})
        return self._client

    async def search(self, query: str, keywords: Optional[List[str]] = None) -> List[SearchResult]:
        results = []
        try:
            otx_results = await self._search_otx(query)
            results.extend(otx_results)
        except Exception as exc:
            logger.warning(f"OTX search failed: {exc}")
        if keywords:
            for kw in keywords[:3]:
                try:
                    otx_results = await self._search_otx(kw)
                    results.extend(otx_results)
                except Exception:
                    pass
        return results[:20]

    async def _search_otx(self, query: str) -> List[SearchResult]:
        if not self._otx_key:
            return []
        client = await self._get_client()
        response = await client.get(
            "https://otx.alienvault.com/api/v1/search/pulses",
            params={"q": query, "limit": 10},
            headers={"X-OTX-API-KEY": self._otx_key},
        )
        response.raise_for_status()
        return self._parse_otx_response(response.json())

    def _parse_otx_response(self, data: Dict) -> List[SearchResult]:
        results = []
        for pulse in data.get("results", []):
            results.append(SearchResult(
                title=pulse.get("name", ""),
                url=pulse.get("id", ""),
                snippet=pulse.get("description", "")[:200],
                source="alienvault_otx",
                relevance_score=0.7,
            ))
        return results

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None


web_search_service = WebSearchService()
