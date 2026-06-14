import asyncio
import json
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from loguru import logger
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from app.config import settings
from app.core.llm import LLMService
from app.db.analysis_crud import AnalysisResultCRUD


class BaseAnalyzer(ABC):
    analysis_type: str = "base"

    def __init__(self, llm_client: LLMService, db_session_factory: async_sessionmaker):
        self.llm_client = llm_client
        self.db_session_factory = db_session_factory

    async def analyze(self, target_id: str, target_type: str = "intelligence", context: Optional[Dict] = None) -> Optional[Dict]:
        try:
            target_data = await self._fetch_target_data(target_id, target_type)
            if not target_data:
                logger.warning(f"[{self.analysis_type}] Target not found: {target_id}")
                return None
            rule_result = await self._rule_based_analyze(target_data)
            final_result = rule_result.copy()
            if self._should_enhance_with_llm(rule_result):
                try:
                    prompt = self._build_prompt(target_data, rule_result)
                    llm_result = await self._call_llm(prompt)
                    final_result = self._merge_results(rule_result, llm_result)
                except Exception as exc:
                    logger.warning(f"[{self.analysis_type}] LLM enhancement failed for {target_id}: {exc}")
            await self._save_result(target_id, target_type, final_result)
            return final_result
        except Exception as exc:
            logger.error(f"[{self.analysis_type}] Analysis failed for {target_id}: {exc}")
            try:
                async with self.db_session_factory() as session:
                    await AnalysisResultCRUD.create(session, {
                        "analysis_type": self.analysis_type,
                        "target_id": target_id,
                        "target_type": target_type,
                        "result_summary": f"分析失败: {str(exc)[:200]}",
                        "confidence_score": 0.0,
                        "status": "failed",
                        "error_message": str(exc)[:500],
                    })
            except Exception:
                pass
            return None

    async def _fetch_target_data(self, target_id: str, target_type: str) -> Optional[Dict]:
        from app.db.tables import RawIntelligenceTable, CleanedIntelligenceTable, EntityTable
        from sqlalchemy import select
        async with self.db_session_factory() as session:
            if target_type == "intelligence":
                result = await session.execute(select(RawIntelligenceTable).where(RawIntelligenceTable.id == target_id))
                row = result.scalars().first()
                if row:
                    return {"id": row.id, "content": row.content or "", "source": row.source, "collected_at": str(row.collected_at), "status": row.status}
                result = await session.execute(select(CleanedIntelligenceTable).where(CleanedIntelligenceTable.id == target_id))
                row = result.scalars().first()
                if row:
                    return {"id": row.id, "content": row.content or "", "threat_level": row.threat_level, "cleaned_at": str(row.cleaned_at)}
            elif target_type == "entity":
                result = await session.execute(select(EntityTable).where(EntityTable.id == target_id))
                row = result.scalars().first()
                if row:
                    return {"id": row.id, "type": row.type, "value": row.value, "context": row.context or "", "confidence": row.confidence}
        return None

    @abstractmethod
    async def _rule_based_analyze(self, target_data: Dict) -> Dict:
        pass

    @abstractmethod
    def _should_enhance_with_llm(self, rule_result: Dict) -> bool:
        pass

    @abstractmethod
    def _build_prompt(self, target_data: Dict, rule_result: Dict) -> str:
        pass

    async def _call_llm(self, prompt: str) -> Dict:
        system_prompt = getattr(self, '_system_prompt', '你是威胁情报分析专家。请用纯JSON格式回复。')
        result = await self.llm_client.generate_json(prompt=prompt, system_prompt=system_prompt, temperature=settings.LLM_TEMPERATURE_CREATIVE)
        return result

    @abstractmethod
    def _merge_results(self, rule_result: Dict, llm_result: Dict) -> Dict:
        pass

    async def _save_result(self, target_id: str, target_type: str, final_result: Dict):
        async with self.db_session_factory() as session:
            await AnalysisResultCRUD.create(session, {
                "analysis_type": self.analysis_type,
                "target_id": target_id,
                "target_type": target_type,
                "result_summary": final_result.get("result_summary", ""),
                "findings": final_result.get("findings", []),
                "iocs": final_result.get("iocs", []),
                "recommendations": final_result.get("recommendations", []),
                "result_data": final_result.get("result_data", {}),
                "confidence_score": final_result.get("confidence_score", 0.0),
                "status": final_result.get("status", "completed"),
                "error_message": final_result.get("error_message"),
                "llm_tokens_used": final_result.get("llm_tokens_used", 0),
                "model_name": self.llm_client.model_name,
                "input_content": final_result.get("input_content", "")[:2000],
            })
