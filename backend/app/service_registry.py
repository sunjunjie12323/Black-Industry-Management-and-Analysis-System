import asyncio
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from loguru import logger

from app.config import settings
from app.core.threat_keywords import get_threat_keywords


async def initialize_services(app) -> None:
    logger.info("Initializing core services...")

    llm = _init_llm(app)
    embedding_engine, vector_store = _init_vector_store(app)
    knowledge_graph = _init_knowledge_graph(app)
    blacktalk_engine = _init_blacktalk(app, llm, vector_store)
    evidence_chain = _init_evidence_chain(app, llm, vector_store)
    pir_engine = _init_pir(app, llm, vector_store)
    _init_ner_engine(app, llm)
    message_queue = _init_message_queue(app)
    orchestrator = _init_orchestrator(app, llm, vector_store, blacktalk_engine, knowledge_graph, evidence_chain, pir_engine)
    collectors = _init_collectors(app, orchestrator)
    _init_task_queue(app)
    innovation_engines = _init_innovation_engines(app, vector_store, blacktalk_engine, knowledge_graph, llm)
    await _init_default_admin()
    _init_cache(app)
    _init_threat_intel_service(app, llm)
    _init_prompt_engine(app, llm)
    _init_pipeline_engine(app, llm)
    _init_finetune_worker(app, llm)
    _init_qa_engine(app, vector_store, llm, embedding_engine)
    _init_translation_engine(app, llm)
    _init_content_engine(app, llm)
    _init_analytics_engine(app, llm)
    _init_dfx(app)
    _init_notification_and_alert(app)
    _init_deployment_managers(app)
    _init_intel_pipeline(app, llm, vector_store, knowledge_graph, collectors)
    _init_csrf(app)
    _init_domain_finetune(app, llm)
    _init_billing(app)
    _init_backup(app)
    _init_tenant_and_case(app)
    _init_retention(app)
    worker_pool = _init_worker_pool(app, message_queue)

    _init_new_analysis_engines(app)

    from app.websocket import manager
    app.state.connection_manager = manager
    logger.info("All services initialized and stored in app.state")

    await _post_init_services(app, innovation_engines, knowledge_graph, vector_store)


def _init_new_analysis_engines(app):
    """初始化5个商用级核心分析引擎"""
    logger.info("[18/20] Initializing 5 new commercial-grade analysis engines...")
    
    try:
        from app.core.intelligence_quality import intelligence_quality_engine
        app.state.intelligence_quality_engine = intelligence_quality_engine
        logger.info("IntelligenceQualityEngine initialized (Bayesian credibility + exponential timeliness + Jaccard consistency)")
    except Exception as exc:
        logger.warning(f"IntelligenceQualityEngine initialization failed: {exc}")
    
    try:
        from app.core.event_correlation import event_correlation_engine
        app.state.event_correlation_engine = event_correlation_engine
        logger.info("EventCorrelationEngine initialized (TF-IDF cosine + temporal decay + causal inference)")
    except Exception as exc:
        logger.warning(f"EventCorrelationEngine initialization failed: {exc}")
    
    try:
        from app.core.threat_behavior import threat_behavior_profiler
        app.state.threat_behavior_profiler = threat_behavior_profiler
        logger.info("ThreatBehaviorProfiler initialized (TTP fingerprint + hierarchical clustering + Apriori)")
    except Exception as exc:
        logger.warning(f"ThreatBehaviorProfiler initialization failed: {exc}")
    
    try:
        from app.core.risk_scoring import dynamic_risk_scorer
        app.state.dynamic_risk_scorer = dynamic_risk_scorer
        logger.info("DynamicRiskScorer initialized (CVSS v3.1 + exponential decay + cascade risk + industry matrix)")
    except Exception as exc:
        logger.warning(f"DynamicRiskScorer initialization failed: {exc}")
    
    try:
        from app.core.intelligence_fusion import intelligence_fusion_engine
        app.state.intelligence_fusion_engine = intelligence_fusion_engine
        logger.info("IntelligenceFusionEngine initialized (TF-IDF dedup + Dempster-Shafer evidence fusion + provenance graph)")
    except Exception as exc:
        logger.warning(f"IntelligenceFusionEngine initialization failed: {exc}")


def _init_llm(app):
    logger.info("[1/17] Creating LLMService...")
    from app.core.llm import LLMService
    llm = LLMService()
    app.state.llm = llm
    logger.info("LLMService created")
    return llm


def _init_vector_store(app):
    logger.info("[2/17] Creating VectorStore with local embedding engine...")
    from app.core.local_embedding import LocalEmbeddingEngine
    from app.core.vector_store import VectorStore
    embedding_engine = LocalEmbeddingEngine(dim=256)
    vector_store = VectorStore(
        persist_dir=settings.CHROMA_PERSIST_DIR,
        embedding_engine=embedding_engine,
    )
    app.state.vector_store = vector_store
    app.state.embedding_engine = embedding_engine
    logger.info(f"VectorStore created (local TF-IDF+SVD embedding, dim={embedding_engine.dim})")
    return embedding_engine, vector_store


def _init_knowledge_graph(app):
    logger.info("[3/17] Creating KnowledgeGraph...")
    from app.core.knowledge_graph import KnowledgeGraph
    knowledge_graph = KnowledgeGraph(persist_dir="./graph_data")
    app.state.knowledge_graph = knowledge_graph
    logger.info("KnowledgeGraph created")
    return knowledge_graph


def _init_blacktalk(app, llm, vector_store):
    logger.info("[4/17] Creating BlackTalkEngine...")
    from app.core.blacktalk_engine import BlackTalkEngine
    blacktalk_engine = BlackTalkEngine(llm=llm, vector_store=vector_store)
    app.state.blacktalk_engine = blacktalk_engine
    logger.info(f"BlackTalkEngine created with {len(blacktalk_engine._dictionary)} seed terms")
    return blacktalk_engine


async def _init_blacktalk_vectors(blacktalk_engine):
    logger.info("[5/17] Initializing BlackTalkEngine vectors...")
    try:
        await asyncio.wait_for(blacktalk_engine.initialize_vectors(), timeout=30.0)
        logger.info("BlackTalkEngine vectors initialized")
    except asyncio.TimeoutError:
        logger.warning("BlackTalkEngine vector initialization timed out (30s), skipping. Vectors will be built on-demand.")
    except Exception as exc:
        logger.warning(f"BlackTalkEngine vector initialization failed: {exc}. Vectors will be built on-demand.")


def _init_evidence_chain(app, llm, vector_store):
    logger.info("[6/17] Creating EvidenceChain...")
    from app.core.evidence_chain import EvidenceChain, CrossValidator, SourceCredibilityTracker, HallucinationDetector
    evidence_chain = EvidenceChain(llm=llm, vector_store=vector_store)
    app.state.evidence_chain = evidence_chain
    app.state.cross_validator = evidence_chain.cross_validator
    app.state.credibility_tracker = evidence_chain.credibility_tracker
    app.state.hallucination_detector = evidence_chain.hallucination_detector
    logger.info("EvidenceChain created (CrossValidator + SourceCredibilityTracker + HallucinationDetector)")
    return evidence_chain


def _init_pir(app, llm, vector_store):
    logger.info("[7/17] Creating PIREngine...")
    from app.db.database import async_session_factory as _pir_session_factory
    from app.core.pir_engine import PIREngine
    pir_engine = PIREngine(llm=llm, vector_store=vector_store, session_factory=_pir_session_factory)
    app.state.pir_engine = pir_engine
    logger.info("PIREngine created")
    return pir_engine


def _init_orchestrator(app, llm, vector_store, blacktalk_engine, knowledge_graph, evidence_chain, pir_engine):
    logger.info("[8/17] Creating OrchestratorAgent with all sub-agents...")
    from app.agents.orchestrator import OrchestratorAgent
    from app.core.data_governance import DataClassification, DataMinimizer
    from app.core.data_masking import PIIDetector

    data_classification = DataClassification()
    data_minimizer = DataMinimizer()
    pii_detector = PIIDetector()
    provenance_chain = getattr(app.state, "provenance_chain", None)
    cross_validator = getattr(app.state, "cross_validator", None)
    hallucination_detector = getattr(app.state, "hallucination_detector", None)
    ner_engine = getattr(app.state, "ner_engine", None)
    message_queue = getattr(app.state, "message_queue", None)

    orchestrator = OrchestratorAgent(
        llm=llm,
        vector_store=vector_store,
        blacktalk_engine=blacktalk_engine,
        knowledge_graph=knowledge_graph,
        evidence_chain=evidence_chain,
        pir_engine=pir_engine,
        data_classification=data_classification,
        data_minimizer=data_minimizer,
        pii_detector=pii_detector,
        provenance_chain=provenance_chain,
        cross_validator=cross_validator,
        hallucination_detector=hallucination_detector,
        ner_engine=ner_engine,
        message_queue=message_queue,
    )
    app.state.orchestrator = orchestrator
    app.state.data_classification = data_classification
    app.state.data_minimizer = data_minimizer
    app.state.pii_detector = pii_detector
    logger.info("OrchestratorAgent created with all sub-agents and data governance pipeline")
    return orchestrator


def _init_collectors(app, orchestrator):
    logger.info("[9/17] Creating collectors...")
    from app.collectors.telegram_collector import TelegramCollector
    from app.collectors.forum_collector import ForumCollector
    from app.collectors.wechat_collector import WeChatCollector
    from app.collectors.darkweb_collector import DarkWebCollector
    from app.collectors.realtime_collector import RealTimeCollector
    from app.collectors.commercial_collector import CommercialCollector

    collectors = {
        "telegram": TelegramCollector(),
        "forum": ForumCollector(),
        "wechat": WeChatCollector(),
        "darkweb": DarkWebCollector(),
        "realtime": RealTimeCollector(),
        "commercial": CommercialCollector(),
    }

    for name, collector in collectors.items():
        setattr(app.state, f"{name}_collector", collector)

    logger.info("[10/17] Registering collectors with CollectorAgent...")
    for name, collector in collectors.items():
        orchestrator.collector.register_collector(name, collector.collect)
    logger.info("All collectors registered")
    return collectors


async def _init_task_queue(app):
    logger.info("[11/17] Registering task queue handlers and starting workers...")
    from app.api.agent import register_agent_handlers
    from app.core.task_queue import task_queue
    register_agent_handlers(app)
    await task_queue.start()
    logger.info(f"Task queue started with {settings.MAX_CONCURRENT_TASKS} workers")


def _init_innovation_engines(app, vector_store, blacktalk_engine, knowledge_graph, llm=None):
    logger.info("[12/17] Creating innovation engines (real ML algorithms)...")
    from app.core.zero_day_detector import ZeroDayDetector
    from app.core.attack_chain_predictor import AttackChainPredictor
    from app.core.provenance_chain import ProvenanceChain
    from app.core.entity_attribution import EntityAttribution
    from app.core.temporal_decay import TemporalDecay
    from app.core.intelligence_organism import IntelligenceOrganismEngine

    zero_day_detector = ZeroDayDetector(vector_store=vector_store, blacktalk_engine=blacktalk_engine, llm_service=llm)
    app.state.zero_day_detector = zero_day_detector
    logger.info("ZeroDayDetector created (Skip-gram + KL divergence + LLM)")

    attack_chain_predictor = AttackChainPredictor(vector_store=vector_store, knowledge_graph=knowledge_graph, llm_service=llm)
    app.state.attack_chain_predictor = attack_chain_predictor
    logger.info("AttackChainPredictor created (MITRE ATT&CK + Markov chain + Dynamic Bayesian + LLM)")

    provenance_chain = ProvenanceChain(vector_store=vector_store)
    app.state.provenance_chain = provenance_chain
    app.state.worm_logger = provenance_chain.worm_logger
    logger.info("ProvenanceChain created (SHA-256 hash chain + WORM logger + Merkle integrity proof)")

    entity_attribution = EntityAttribution(vector_store=vector_store, knowledge_graph=knowledge_graph)
    app.state.entity_attribution = entity_attribution
    logger.info("EntityAttribution created (TransE knowledge graph embedding)")

    temporal_decay = TemporalDecay(vector_store=vector_store)
    app.state.temporal_decay = temporal_decay
    logger.info("TemporalDecay created (MLE half-life estimation)")

    intelligence_organism = IntelligenceOrganismEngine(vector_store=vector_store, knowledge_graph=knowledge_graph, llm_service=llm)
    app.state.intelligence_organism = intelligence_organism
    logger.info("IntelligenceOrganismEngine created (adaptive half-life + semantic change detection + LLM-enhanced evolution)")

    return {
        "zero_day_detector": zero_day_detector,
        "attack_chain_predictor": attack_chain_predictor,
        "provenance_chain": provenance_chain,
        "entity_attribution": entity_attribution,
        "temporal_decay": temporal_decay,
        "intelligence_organism": intelligence_organism,
    }


async def _init_default_admin():
    logger.info("[14/17] Creating default admin user...")
    from app.core.auth import create_default_admin
    await create_default_admin()


async def _init_cache(app):
    logger.info("[15/17] Initializing CacheService...")
    from app.core.cache_service import cache_service
    await cache_service.initialize()
    app.state.cache_service = cache_service
    logger.info(f"CacheService initialized (mode: {'Redis' if cache_service.is_redis else 'Memory'})")

    if cache_service.is_redis:
        try:
            from app.core.rate_limiter import rate_limiter
            redis_client = cache_service._cache._redis
            if redis_client:
                rate_limiter.set_redis(redis_client)
                logger.info("RateLimiter: Redis backend connected via CacheService")
        except Exception as exc:
            logger.warning(f"RateLimiter Redis integration failed: {exc}")


def _init_threat_intel_service(app, llm):
    logger.info("[14.1/17] Initializing ThreatIntelService...")
    from app.core.threat_intel_service import ThreatIntelService
    threat_intel_service = ThreatIntelService(llm_service=llm)
    app.state.threat_intel_service = threat_intel_service
    logger.info("ThreatIntelService created (ThreatClassifier + EntityExtractor + CrimePatternAnalyzer + TechChainAnalyzer)")


def _init_prompt_engine(app, llm):
    logger.info("[15.1/17] Initializing Prompt Execution Engine...")
    from app.core.prompt_engine_service import PromptExecutionEngine, ABTestAnalyzer, PromptOptimizer
    prompt_execution_engine = PromptExecutionEngine(llm_service=llm)
    prompt_ab_analyzer = ABTestAnalyzer(prompt_execution_engine)
    prompt_optimizer = PromptOptimizer(prompt_execution_engine, llm_service=llm)
    app.state.prompt_execution_engine = prompt_execution_engine
    app.state.prompt_ab_analyzer = prompt_ab_analyzer
    app.state.prompt_optimizer = prompt_optimizer
    logger.info("PromptExecutionEngine + ABTestAnalyzer + PromptOptimizer created")


def _init_pipeline_engine(app, llm):
    logger.info("[15.2/17] Initializing Pipeline Engine...")
    from app.core.pipeline_engine import PipelineExecutor
    pipeline_executor = PipelineExecutor(llm_service=llm)
    app.state.pipeline_executor = pipeline_executor
    logger.info("PipelineExecutor created")


def _init_finetune_worker(app, llm):
    logger.info("[15.3/17] Initializing Finetune Worker...")
    from app.core.finetune_engine import FinetuneWorker
    finetune_worker = FinetuneWorker(llm_service=llm)
    app.state.finetune_worker = finetune_worker
    logger.info("FinetuneWorker created")


def _init_qa_engine(app, vector_store, llm, embedding_engine):
    logger.info("[15.4/17] Initializing QA Engine...")
    from app.core.qa_engine import RAGEngine, DialogueManager, CitationTracker
    qa_rag_engine = RAGEngine(vector_store=vector_store, llm_service=llm, embedding_engine=embedding_engine)
    qa_dialogue_manager = DialogueManager(llm_service=llm)
    qa_citation_tracker = CitationTracker()
    app.state.qa_rag_engine = qa_rag_engine
    app.state.qa_dialogue_manager = qa_dialogue_manager
    app.state.qa_citation_tracker = qa_citation_tracker
    logger.info("RAGEngine + DialogueManager + CitationTracker created")


def _init_translation_engine(app, llm):
    logger.info("[15.5/17] Initializing Translation Engine...")
    from app.core.translation_engine import TranslationEngine
    translation_engine = TranslationEngine(llm_service=llm)
    app.state.translation_engine = translation_engine
    logger.info("TranslationEngine created")


def _init_content_engine(app, llm):
    logger.info("[15.6/17] Initializing Content Engine...")
    from app.core.content_engine import ContentGenerator, ReviewWorkflow, TemplateRenderer
    from app.core.prompt_engine_service import PromptExecutionEngine
    prompt_engine = getattr(app.state, "prompt_execution_engine", None)
    content_generator = ContentGenerator(llm_service=llm, prompt_engine=prompt_engine)
    review_workflow = ReviewWorkflow()
    template_renderer = TemplateRenderer(llm_service=llm)
    app.state.content_generator = content_generator
    app.state.review_workflow = review_workflow
    app.state.template_renderer = template_renderer
    logger.info("ContentGenerator + ReviewWorkflow + TemplateRenderer created")


def _init_analytics_engine(app, llm):
    logger.info("[15.7/17] Initializing Analytics Engine...")
    from app.core.analytics_engine import AnalyticsEngine
    analytics_engine = AnalyticsEngine(llm_service=llm)
    app.state.analytics_engine = analytics_engine
    logger.info("AnalyticsEngine created")


def _init_dfx(app):
    logger.info("[15.8/17] Initializing DFX components...")
    from app.core.dfx import performance_monitor, reliability_guard, security_auditor, metrics_collector
    app.state.performance_monitor = performance_monitor
    app.state.reliability_guard = reliability_guard
    app.state.security_auditor = security_auditor
    app.state.metrics_collector = metrics_collector
    logger.info("DFX components (PerformanceMonitor + ReliabilityGuard + SecurityAuditor + MetricsCollector) initialized")


def _init_notification_and_alert(app):
    logger.info("[15.9/17] Initializing Notification Service...")
    from app.core.notification_service import notification_service
    from app.core.alert_engine import AlertEngine
    if settings.webhook_urls_list:
        notification_service.configure_webhooks(settings.webhook_urls_list)
    app.state.notification_service = notification_service
    logger.info(f"NotificationService initialized (webhooks: {len(settings.webhook_urls_list)})")

    message_queue = getattr(app.state, "message_queue", None)
    alert_engine = AlertEngine(notification_service=notification_service, message_queue=message_queue)
    app.state.alert_engine = alert_engine
    logger.info(f"AlertEngine created with {len(alert_engine.rules)} default rules, notification_service linked, message_queue={'connected' if message_queue else 'not available'}")


def _init_deployment_managers(app):
    logger.info("[15.10/17] Initializing Deployment Managers...")
    from app.api.deployment import EnvironmentConfigManager, DockerDeploymentManager, HuaweiCloudDeploymentManager, RollbackManager, ServiceMonitor
    app.state.env_config_manager = EnvironmentConfigManager()
    app.state.docker_deployment_manager = DockerDeploymentManager()
    app.state.huawei_cloud_manager = HuaweiCloudDeploymentManager()
    app.state.rollback_manager = RollbackManager()
    app.state.service_monitor = ServiceMonitor(app.state)
    logger.info("Deployment managers (EnvironmentConfig + Docker + HuaweiCloud + Rollback + ServiceMonitor) initialized")


def _init_intel_pipeline(app, llm, vector_store, knowledge_graph, collectors):
    logger.info("[15.11/17] Initializing Intelligence Pipeline...")
    from app.core.intel_pipeline import IntelligencePipeline
    from app.core.source_scheduler import SourceScheduler
    from app.db.database import async_session_factory as _pipeline_session_factory

    # 获取 alert_engine（如果已初始化）
    alert_engine = getattr(app.state, "alert_engine", None)

    intel_pipeline = IntelligencePipeline(
        llm_service=llm,
        db_session_factory=_pipeline_session_factory,
        vector_store=vector_store,
        knowledge_graph=knowledge_graph,
        alert_engine=alert_engine,
    )
    app.state.intel_pipeline = intel_pipeline
    logger.info(f"IntelligencePipeline created (EnhancedThreatClassifier + EnhancedEntityExtractor + PersistentDeduplicator + RiskScorer, alert_engine={'connected' if alert_engine else 'not available'})")

    logger.info("[15.12/17] Initializing Source Scheduler...")
    source_scheduler = SourceScheduler(pipeline=intel_pipeline)
    for name, collector in collectors.items():
        source_scheduler.register_collector(name, collector.collect)
    app.state.source_scheduler = source_scheduler
    logger.info(f"SourceScheduler created with {len(source_scheduler.list_sources())} sources, {len(source_scheduler._collectors)} collectors")

    app.state.active_industry = None
    app.state.active_industry_strategy = None


def _init_csrf(app):
    import secrets
    import os
    import stat
    logger.info("[16/17] Generating CSRF secret...")
    if settings.is_production:
        csrf_secret = os.environ.get("CSRF_SECRET", "")
        if not csrf_secret or len(csrf_secret) < 16:
            raise ValueError("CSRF_SECRET must be set via environment variable in production (min 16 chars)")
        app.state.csrf_secret = csrf_secret
        logger.info("CSRF secret loaded from environment variable")
    else:
        csrf_path = Path(__file__).resolve().parent.parent / ".csrf_secret"
        if not csrf_path.exists():
            csrf_path.write_text(secrets.token_urlsafe(32), encoding="utf-8")
        try:
            os.chmod(str(csrf_path), stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        app.state.csrf_secret = csrf_path.read_text().strip()
        logger.info("CSRF secret ready (dev mode, from file)")


def _restrict_file_permissions(file_path: Path):
    try:
        import os
        import stat
        os.chmod(str(file_path), stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


async def _post_init_services(app, innovation_engines, knowledge_graph, vector_store):
    blacktalk_engine = getattr(app.state, "blacktalk_engine", None)
    if blacktalk_engine:
        await _init_blacktalk_vectors(blacktalk_engine)

    await _init_provenance_from_db(app, innovation_engines["provenance_chain"])

    entity_attribution = innovation_engines["entity_attribution"]
    try:
        entity_attribution.train_from_graph()
        logger.info(f"EntityAttribution TransE trained from graph")
    except Exception as exc:
        logger.warning(f"EntityAttribution TransE training failed: {exc}")

    await _start_auto_collector(app, knowledge_graph)
    await _start_source_scheduler(app)
    await _start_analysis_engine(app, innovation_engines, knowledge_graph)
    await _train_innovation_engines(app, innovation_engines, knowledge_graph)


async def _init_provenance_from_db(app, provenance_chain):
    try:
        from app.db.database import async_session_factory
        from app.db.tables import RawIntelligenceTable, CleanedIntelligenceTable, AnalyzedIntelligenceTable
        from sqlalchemy import select
        async with async_session_factory() as session:
            raw_result = await session.execute(select(RawIntelligenceTable).limit(50))
            raw_items = raw_result.scalars().all()
            for row in raw_items:
                await provenance_chain.record_provenance(
                    intelligence_id=row.id,
                    stage="collected",
                    input_data={"source": row.source, "raw_content": (row.content or "")[:500]},
                    output_data={"content": (row.content or "")[:500], "status": "raw"},
                )
            cleaned_result = await session.execute(select(CleanedIntelligenceTable).limit(50))
            for row in cleaned_result.scalars().all():
                await provenance_chain.record_provenance(
                    intelligence_id=row.id,
                    stage="cleaned",
                    input_data={"source": "raw"},
                    output_data={"content": (row.content or "")[:500], "status": "cleaned"},
                )
            analyzed_result = await session.execute(select(AnalyzedIntelligenceTable).limit(50))
            for row in analyzed_result.scalars().all():
                await provenance_chain.record_provenance(
                    intelligence_id=row.id,
                    stage="analyzed",
                    input_data={"source": "cleaned"},
                    output_data={"analysis_summary": (row.analysis_summary or "")[:500]},
                )
        logger.info(f"Provenance records created for existing intelligence")
    except Exception as exc:
        logger.warning(f"ProvenanceChain auto-generation skipped: {exc}")


async def _start_auto_collector(app, knowledge_graph):
    logger.info("Post-init: Starting AutoCollector service...")
    try:
        from app.core.auto_collector import AutoCollector
        blacktalk_engine = getattr(app.state, "blacktalk_engine", None)
        llm_service = getattr(app.state, "llm", None)
        data_classification = getattr(app.state, "data_classification", None)
        data_minimizer = getattr(app.state, "data_minimizer", None)
        pii_detector = getattr(app.state, "pii_detector", None)
        provenance_chain = getattr(app.state, "provenance_chain", None)
        message_queue = getattr(app.state, "message_queue", None)
        worker_pool = getattr(app.state, "worker_pool", None)
        auto_collector = AutoCollector(
            kg=knowledge_graph,
            blacktalk_engine=blacktalk_engine,
            llm_service=llm_service,
            data_classification=data_classification,
            data_minimizer=data_minimizer,
            pii_detector=pii_detector,
            provenance_chain=provenance_chain,
            message_queue=message_queue,
            worker_pool=worker_pool,
        )
        app.state.auto_collector = auto_collector
        auto_collector.start_auto_collection(interval_minutes=30)
        logger.info(f"AutoCollector started (interval: 30min, running: {auto_collector.is_running}, data_governance: {'enabled' if data_classification else 'disabled'})")
    except Exception as exc:
        logger.warning(f"AutoCollector start failed: {exc}")
        app.state.auto_collector = None


async def _start_source_scheduler(app):
    logger.info("Post-init: Starting Source Scheduler service...")
    try:
        source_scheduler = getattr(app.state, "source_scheduler", None)
        if source_scheduler:
            await source_scheduler.start(base_interval_minutes=10)
            logger.info("SourceScheduler started (base interval: 10min)")
        else:
            logger.warning("SourceScheduler not available, skipping start")
    except Exception as exc:
        logger.warning(f"SourceScheduler start failed: {exc}")


async def _start_analysis_engine(app, innovation_engines, knowledge_graph):
    logger.info("Post-init: Starting Analysis Engine and Scheduler...")
    try:
        from app.engine.analysis_engine import AnalysisEngine
        from app.engine.scheduler import AnalysisScheduler, _build_scheduler_config
        from app.db.database import async_session_factory as _analysis_session_factory

        analysis_engine = AnalysisEngine(
            llm_client=app.state.llm,
            db_session_factory=_analysis_session_factory,
            zero_day_detector=innovation_engines["zero_day_detector"],
            entity_attribution=innovation_engines["entity_attribution"],
            provenance_chain=innovation_engines["provenance_chain"],
            temporal_decay=innovation_engines["temporal_decay"],
            attack_predictor=innovation_engines["attack_chain_predictor"],
            knowledge_graph=knowledge_graph,
        )
        app.state.analysis_engine = analysis_engine

        scheduler_config = _build_scheduler_config()
        analysis_scheduler = AnalysisScheduler(engine=analysis_engine, config=scheduler_config)
        app.state.analysis_scheduler = analysis_scheduler
        analysis_scheduler.start()
        logger.info(f"AnalysisScheduler started (interval: {scheduler_config.schedule_interval_hours}h)")

        logger.info("Post-init: Triggering initial analysis cycle in background...")

        async def _run_initial_analysis():
            try:
                init_result = await analysis_scheduler.trigger_now()
                logger.info(f"Initial analysis cycle result: {init_result}")
            except Exception as exc:
                logger.warning(f"Initial analysis cycle failed: {exc}")

        asyncio.create_task(_run_initial_analysis())
    except Exception as exc:
        logger.warning(f"Analysis Engine/Scheduler initialization failed: {exc}")
        app.state.analysis_engine = None
        app.state.analysis_scheduler = None


async def _train_innovation_engines(app, innovation_engines, knowledge_graph):
    logger.info("Post-init: Training innovation engines with seed data...")
    try:
        import re as _re
        from app.db.database import async_session_factory
        from app.db.tables import RawIntelligenceTable, CleanedIntelligenceTable
        from sqlalchemy import select
        from app.models.entity import Entity, EntityType, Relation, RelationType

        zero_day_detector = innovation_engines["zero_day_detector"]
        attack_chain_predictor = innovation_engines["attack_chain_predictor"]
        temporal_decay = innovation_engines["temporal_decay"]
        intelligence_organism = innovation_engines["intelligence_organism"]

        async with async_session_factory() as session:
            raw_result = await session.execute(select(RawIntelligenceTable).limit(300))
            raw_items = raw_result.scalars().all()
            corpus = [(row.content or "") for row in raw_items if row.content]

        if corpus and len(corpus) >= 5:
            try:
                await asyncio.wait_for(zero_day_detector.train(corpus), timeout=30.0)
                logger.info(f"ZeroDayDetector trained: vocab={len(zero_day_detector._word2idx)}, trained={zero_day_detector._trained}")
            except Exception as exc:
                logger.warning(f"ZeroDayDetector training failed: {exc}")
        else:
            logger.warning(f"ZeroDayDetector: insufficient corpus ({len(corpus)} docs), skipping training")

        await _populate_knowledge_graph(raw_items, knowledge_graph)

        try:
            attack_chain_predictor.train_from_graph()
            logger.info(f"AttackChainPredictor built: {attack_chain_predictor._total_transitions} transitions, graph_nodes={knowledge_graph.graph.number_of_nodes()}")
        except Exception as exc:
            logger.warning(f"AttackChainPredictor build failed: {exc}")

        await _spawn_organisms(raw_items, intelligence_organism)
        await _seed_temporal_decay(raw_items, temporal_decay)

    except Exception as exc:
        logger.warning(f"Post-init engine training skipped: {exc}")
        traceback.print_exc()


async def _populate_knowledge_graph(raw_items, knowledge_graph):
    import re as _re
    from app.models.entity import Entity, EntityType, Relation, RelationType

    logger.info("Post-init: Populating knowledge graph from raw intelligence...")
    try:
        _TG_RE = _re.compile(r'@([a-zA-Z]\w{3,30})')
        _THREAT_KEYWORDS = get_threat_keywords()
        _ETYPE_MAP = {
            "TOOL": EntityType.TOOL,
            "SERVICE": EntityType.SERVICE,
            "BLACKTALK": EntityType.BLACKTALK,
            "PERSON": EntityType.PERSON,
            "MALWARE": EntityType.MALWARE,
            "ORGANIZATION": EntityType.ORGANIZATION,
        }

        entity_value_to_id: Dict[str, str] = {}
        kg_entity_count = 0
        kg_relation_count = 0

        for raw_item in raw_items:
            content = raw_item.content or ""
            if not content or len(content) < 5:
                continue

            doc_entity_ids: list = []

            tg_matches = _TG_RE.findall(content)
            for handle in set(tg_matches):
                val = f"@{handle}"
                entity = Entity(
                    type=EntityType.ACCOUNT,
                    value=val,
                    context=content[:200],
                    source_ids=[raw_item.id],
                    confidence=0.8,
                )
                eid = await knowledge_graph.add_entity(entity)
                entity_value_to_id[val] = eid
                doc_entity_ids.append(eid)
                kg_entity_count += 1

            for keyword, (etype_str, desc) in _THREAT_KEYWORDS.items():
                if keyword not in content:
                    continue
                if keyword in entity_value_to_id:
                    eid = entity_value_to_id[keyword]
                    if eid not in doc_entity_ids:
                        doc_entity_ids.append(eid)
                    continue
                etype = _ETYPE_MAP.get(etype_str, EntityType.BLACKTALK)
                entity = Entity(
                    type=etype,
                    value=keyword,
                    context=desc,
                    source_ids=[raw_item.id],
                    confidence=0.7,
                )
                eid = await knowledge_graph.add_entity(entity)
                entity_value_to_id[keyword] = eid
                doc_entity_ids.append(eid)
                kg_entity_count += 1

            for i in range(len(doc_entity_ids)):
                for j in range(i + 1, min(i + 5, len(doc_entity_ids))):
                    src_id = doc_entity_ids[i]
                    tgt_id = doc_entity_ids[j]
                    if src_id == tgt_id:
                        continue
                    if knowledge_graph.graph.has_edge(src_id, tgt_id):
                        continue
                    relation = Relation(
                        source_entity_id=src_id,
                        target_entity_id=tgt_id,
                        type=RelationType.ASSOCIATED_WITH,
                        confidence=0.5,
                        evidence=f"Co-occurrence in intelligence {raw_item.id[:8]}",
                    )
                    await knowledge_graph.add_relation(relation)
                    kg_relation_count += 1

        await knowledge_graph.save()
        logger.info(f"KnowledgeGraph populated: {kg_entity_count} entities, {kg_relation_count} relations, graph_nodes={knowledge_graph.graph.number_of_nodes()}")
    except Exception as exc:
        logger.warning(f"Knowledge graph population failed: {exc}")
        traceback.print_exc()


async def _spawn_organisms(raw_items, intelligence_organism):
    try:
        spawn_count = 0
        for raw_item in raw_items[:30]:
            try:
                content = raw_item.content or ""
                if not content or len(content) < 20:
                    continue
                species = "ip"
                if "跑分" in content or "洗钱" in content:
                    species = "campaign"
                elif "四件套" in content or "猫池" in content or "黑卡" in content:
                    species = "domain"
                elif "杀猪盘" in content or "诈骗" in content or "话术" in content:
                    species = "ttp"
                elif "接码" in content or "养号" in content or "引流" in content:
                    species = "phone"
                elif "木马" in content or "勒索" in content:
                    species = "organization"
                await intelligence_organism.spawn_organism(
                    intelligence_id=raw_item.id,
                    species=species,
                    initial_data={"content": content[:500], "threat_type": "unknown"},
                    skip_save=True,
                )
                spawn_count += 1
            except Exception as e:
                logger.debug(f"Organism spawn skipped: {e}")
        await intelligence_organism.save_to_disk()
        alive = sum(1 for o in intelligence_organism.organisms.values() if o.is_alive)
        logger.info(f"IntelligenceOrganism spawned: {spawn_count} attempts, {alive} alive")
    except Exception as exc:
        logger.warning(f"IntelligenceOrganism spawn failed: {exc}")


async def _seed_temporal_decay(raw_items, temporal_decay):
    try:
        from app.core.temporal_decay import DEFAULT_HALF_LIVES, THREAT_TYPE_KEYWORDS
        threat_types = list(DEFAULT_HALF_LIVES.keys())
        for tt in threat_types:
            temporal_decay._half_lives[tt] = DEFAULT_HALF_LIVES[tt]
            temporal_decay._observations.setdefault(tt, [])
        for raw_item in raw_items[:50]:
            content = raw_item.content or ""
            if not content:
                continue
            content_lower = content.lower()
            matched_type = "malware"
            for tt, keywords in THREAT_TYPE_KEYWORDS.items():
                if any(kw in content_lower for kw in keywords):
                    matched_type = tt
                    break
            elapsed = 24.0
            if raw_item.collected_at:
                try:
                    delta = datetime.now(timezone.utc) - raw_item.collected_at.replace(tzinfo=timezone.utc) if raw_item.collected_at.tzinfo is None else datetime.now(timezone.utc) - raw_item.collected_at
                    elapsed = max(delta.total_seconds() / 3600, 1.0)
                except Exception:
                    pass
            temporal_decay._observations.setdefault(matched_type, []).append((elapsed, 0.7))
        obs_count = sum(len(v) for v in temporal_decay._observations.values())
        logger.info(f"TemporalDecay seeded: {len(temporal_decay._half_lives)} types, {obs_count} observations")
    except Exception as exc:
        logger.warning(f"TemporalDecay seeding failed: {exc}")


def _init_ner_engine(app, llm):
    logger.info("[17.1/20] Initializing ThreatNEREngine...")
    try:
        from app.core.ner_engine import ThreatNEREngine
        ner_engine = ThreatNEREngine(llm_service=llm)
        app.state.ner_engine = ner_engine
        logger.info("ThreatNEREngine created (spaCy + EnhancedRuleNER + LLMNERExtractor + NERFusion)")
    except Exception as exc:
        logger.warning(f"ThreatNEREngine initialization failed: {exc}")


def _init_domain_finetune(app, llm):
    logger.info("[17.2/20] Initializing Domain Finetune components...")
    try:
        from app.core.domain_finetune import TrainingDataManager, FinetuneJobManager, DomainModelEvaluator
        training_data_manager = TrainingDataManager()
        finetune_job_manager = FinetuneJobManager(llm_service=llm)
        domain_model_evaluator = DomainModelEvaluator(llm_service=llm)
        app.state.training_data_manager = training_data_manager
        app.state.finetune_job_manager = finetune_job_manager
        app.state.domain_model_evaluator = domain_model_evaluator
        logger.info("TrainingDataManager + FinetuneJobManager + DomainModelEvaluator created")
    except Exception as exc:
        logger.warning(f"Domain Finetune initialization failed: {exc}")


def _init_billing(app):
    logger.info("[17.3/20] Initializing Billing & SLA components...")
    try:
        from app.core.billing import BillingEngine, SLADefinition
        billing_engine = BillingEngine()
        sla_definition = SLADefinition()
        app.state.billing_engine = billing_engine
        app.state.sla_definition = sla_definition
        logger.info("BillingEngine + SLADefinition created")
    except Exception as exc:
        logger.warning(f"Billing initialization failed: {exc}")


def _init_backup(app):
    logger.info("[17.4/20] Initializing Backup & Disaster Recovery components...")
    try:
        from app.core.backup import BackupManager, DisasterRecovery, BackupVerifier
        backup_manager = BackupManager()
        disaster_recovery = DisasterRecovery(backup_manager=backup_manager)
        backup_verifier = BackupVerifier()
        app.state.backup_manager = backup_manager
        app.state.disaster_recovery = disaster_recovery
        app.state.backup_verifier = backup_verifier
        logger.info("BackupManager + DisasterRecovery + BackupVerifier created")
    except Exception as exc:
        logger.warning(f"Backup initialization failed: {exc}")


def _init_tenant_and_case(app):
    logger.info("[17.45/20] Initializing Tenant & Case Management...")
    try:
        from app.core.tenant_manager import TenantManager
        from app.core.case_manager import CaseManager
        tenant_manager = TenantManager()
        case_manager = CaseManager()
        app.state.tenant_manager = tenant_manager
        app.state.case_manager = case_manager
        logger.info("TenantManager + CaseManager created")
    except Exception as exc:
        logger.warning(f"Tenant & Case initialization failed: {exc}")
        app.state.tenant_manager = None
        app.state.case_manager = None


def _init_retention(app):
    logger.info("[17.5/20] Initializing Data Retention Manager...")
    try:
        from app.core.data_governance import retention_manager
        app.state.retention_manager = retention_manager
        logger.info("RetentionManager registered to app.state")
    except Exception as exc:
        logger.warning(f"Retention initialization failed: {exc}")


def _init_message_queue(app):
    logger.info("[17.6/20] Initializing Message Queue...")
    try:
        from app.core.message_queue import MessageQueueFactory
        mq_url = getattr(settings, "REDIS_URL", None)
        message_queue = asyncio.get_event_loop().run_until_complete(
            MessageQueueFactory.create(url=mq_url)
        )
        app.state.message_queue = message_queue
        logger.info(f"MessageQueue created (type: {type(message_queue).__name__})")
        return message_queue
    except Exception as exc:
        logger.warning(f"MessageQueue initialization failed: {exc}")
        app.state.message_queue = None
        return None


def _init_worker_pool(app, message_queue):
    logger.info("[17.7/20] Initializing Collection Worker Pool...")
    try:
        from app.core.worker_pool import CollectionWorkerPool
        worker_pool = CollectionWorkerPool(num_workers=4, task_timeout=600.0, max_retries=2)
        if message_queue:
            worker_pool.set_message_queue(message_queue)
        app.state.worker_pool = worker_pool
        logger.info(f"CollectionWorkerPool created (workers=4, message_queue={message_queue is not None})")
        return worker_pool
    except Exception as exc:
        logger.warning(f"WorkerPool initialization failed: {exc}")
        app.state.worker_pool = None
        return None
