import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from loguru import logger
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.llm import LLMService
from app.core.zero_day_detector import ZeroDayDetector
from app.core.entity_attribution import EntityAttribution
from app.core.provenance_chain import ProvenanceChain
from app.core.temporal_decay import TemporalDecay
from app.core.attack_chain_predictor import AttackChainPredictor
from app.core.knowledge_graph import KnowledgeGraph
from app.db.analysis_crud import AnalysisResultCRUD
from app.engine.analyzers.base import BaseAnalyzer
from app.engine.analyzers.zero_day import ZeroDayAnalyzer
from app.engine.analyzers.attribution import AttributionAnalyzer
from app.engine.analyzers.provenance import ProvenanceAnalyzer
from app.engine.analyzers.decay import DecayAnalyzer
from app.engine.analyzers.attack_prediction import AttackPredictionAnalyzer
from app.engine.report_generator import ReportGenerator


class AnalysisEngine:
    def __init__(
        self,
        llm_client: LLMService,
        db_session_factory: async_sessionmaker,
        zero_day_detector: ZeroDayDetector,
        entity_attribution: EntityAttribution,
        provenance_chain: ProvenanceChain,
        temporal_decay: TemporalDecay,
        attack_predictor: AttackChainPredictor,
        knowledge_graph: KnowledgeGraph,
        max_concurrent: int = 5,
    ):
        self.llm_client = llm_client
        self.db_session_factory = db_session_factory
        self.knowledge_graph = knowledge_graph
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._analyzers: Dict[str, BaseAnalyzer] = {
            "zero_day": ZeroDayAnalyzer(llm_client, db_session_factory, zero_day_detector),
            "attribution": AttributionAnalyzer(llm_client, db_session_factory, entity_attribution),
            "provenance": ProvenanceAnalyzer(llm_client, db_session_factory, provenance_chain),
            "decay": DecayAnalyzer(llm_client, db_session_factory, temporal_decay),
            "attack_prediction": AttackPredictionAnalyzer(llm_client, db_session_factory, attack_predictor),
        }
        self._report_generator = ReportGenerator(llm_client, db_session_factory)
        self._running = False

    async def run_analysis_cycle(self, enabled_types: Optional[List[str]] = None) -> Dict[str, Any]:
        if self._running:
            logger.warning("Analysis cycle already running, skipping")
            return {"status": "skipped", "message": "已有分析周期在运行"}
        self._running = True
        start_time = datetime.now(timezone.utc)
        all_results = []
        processed = 0
        errors = 0
        try:
            since = await self._get_last_analyzed_time()
            targets = await self._get_pending_targets(since)
            logger.info(f"Analysis cycle: {len(targets)} targets to analyze (since: {since})")
            for target in targets:
                try:
                    result = await self._analyze_target(target, enabled_types)
                    if result:
                        all_results.extend(result)
                    processed += 1
                except Exception as exc:
                    logger.error(f"Target analysis failed: {exc}")
                    errors += 1
            if all_results:
                try:
                    report_ids = await self._report_generator.generate_from_results(all_results)
                    logger.info(f"Generated {len(report_ids)} reports from analysis results")
                except Exception as exc:
                    logger.error(f"Report generation failed: {exc}")
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.info(f"Analysis cycle completed: {processed} targets, {len(all_results)} results, {errors} errors, {duration:.1f}s")
            return {"status": "completed", "targets_processed": processed, "results_count": len(all_results), "errors": errors, "duration_seconds": duration}
        finally:
            self._running = False

    async def run_single_analysis(self, target_id: str, target_type: str, analysis_type: str) -> Optional[Dict]:
        analyzer = self._analyzers.get(analysis_type)
        if not analyzer:
            logger.error(f"Unknown analysis type: {analysis_type}")
            return None
        async with self._semaphore:
            return await analyzer.analyze(target_id, target_type)

    async def _get_last_analyzed_time(self) -> Optional[datetime]:
        try:
            async with self.db_session_factory() as session:
                return await AnalysisResultCRUD.get_last_analyzed_time(session)
        except Exception:
            return None

    async def _get_pending_targets(self, since: Optional[datetime] = None) -> List[Dict]:
        from app.db.tables import RawIntelligenceTable, EntityTable
        from sqlalchemy import select
        targets = []
        try:
            async with self.db_session_factory() as session:
                q = select(RawIntelligenceTable).where(RawIntelligenceTable.content != "").order_by(RawIntelligenceTable.collected_at.desc())
                if since:
                    q = q.where(RawIntelligenceTable.collected_at > since)
                q = q.limit(100)
                result = await session.execute(q)
                for row in result.scalars().all():
                    targets.append({"id": row.id, "type": "intelligence"})
                eq = select(EntityTable).order_by(EntityTable.last_seen.desc()).limit(50)
                entity_result = await session.execute(eq)
                for row in entity_result.scalars().all():
                    targets.append({"id": row.id, "type": "entity"})
        except Exception as exc:
            logger.error(f"Failed to get pending targets: {exc}")
        return targets

    async def _analyze_target(self, target: Dict, enabled_types: Optional[List[str]] = None) -> List[Dict]:
        target_id = target["id"]
        target_type = target["type"]
        types_to_run = enabled_types or list(self._analyzers.keys())
        results = []
        for atype in types_to_run:
            analyzer = self._analyzers.get(atype)
            if not analyzer:
                continue
            async with self._semaphore:
                try:
                    result = await self._with_retry(analyzer.analyze(target_id, target_type))
                    if result:
                        results.append({"analysis_type": atype, "target_id": target_id, **result})
                except Exception as exc:
                    logger.error(f"Analysis {atype} failed for {target_id}: {exc}")
        return results

    async def _with_retry(self, coro, max_retries: int = 3):
        delays = [5, 15, 45]
        last_exc = None
        for attempt in range(max_retries + 1):
            try:
                return await coro
            except Exception as exc:
                last_exc = exc
                if attempt < max_retries:
                    delay = delays[attempt] if attempt < len(delays) else 45
                    logger.warning(f"Retry {attempt+1}/{max_retries} after {delay}s: {exc}")
                    await asyncio.sleep(delay)
                else:
                    raise
