from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List

from loguru import logger

from app.core.llm import LLMService
from app.core.vector_store import VectorStore


class BaseAgent(ABC):
    def __init__(self, name: str, llm: LLMService, vector_store: VectorStore):
        self.name = name
        self.llm = llm
        self.vector_store = vector_store
        self.logger = logger.bind(agent=name)

    @abstractmethod
    async def execute(self, task: Dict) -> Dict:
        pass

    async def _log_execution(self, task: Dict, result: Dict):
        task_type = task.get("type", "unknown")
        status = result.get("status", "unknown")
        self.logger.info(
            f"Task executed: type={task_type}, status={status}"
        )
        if status == "failed":
            errors = result.get("errors", [])
            self.logger.error(f"Task errors: {errors}")

    def _create_task_result(
        self, status: str, data: Dict, errors: List[str] = None
    ) -> Dict:
        return {
            "agent": self.name,
            "status": status,
            "data": data,
            "errors": errors or [],
            "timestamp": datetime.now().isoformat(),
        }
