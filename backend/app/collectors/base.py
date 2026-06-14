from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional

from loguru import logger

from app.models.intelligence import IntelligenceSource


class BaseCollector(ABC):
    def __init__(self, source_type: IntelligenceSource, config: dict = None):
        self.source_type = source_type
        self.config = config or {}
        self.logger = logger.bind(collector=source_type.value)

    @abstractmethod
    async def collect(
        self,
        keywords: List[str],
        max_results: int = 100,
        time_range: Dict = None,
    ) -> List[Dict]:
        pass

    @abstractmethod
    async def test_connection(self) -> bool:
        pass

    def _normalize_item(self, raw_data: Dict) -> Dict:
        return {
            "source": self.source_type.value,
            "source_url": raw_data.get("url", ""),
            "content": raw_data.get("content", ""),
            "raw_content": raw_data.get("raw_content", raw_data.get("content", "")),
            "collected_at": datetime.now().isoformat(),
            "metadata": {
                "collector": self.source_type.value,
                "title": raw_data.get("title", ""),
                "author": raw_data.get("author", ""),
                "timestamp": raw_data.get("timestamp", ""),
                **raw_data.get("extra_metadata", {}),
            },
        }
