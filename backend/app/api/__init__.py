from fastapi import APIRouter
from .agent import router as agent_router
from .agent import report_router as agent_report_router
from .attack_prediction import router as attack_prediction_router
from .attribution import router as attribution_router
from .auth import router as auth_router, api_keys_router
from .blacktalk import router as blacktalk_router
from .dashboard import router as dashboard_router
from .entities import router as entities_router
from .economic import router as economic_router
from .graph import router as graph_router
from .intelligence import router as intelligence_router
from .intelligence import pipeline_router as intelligence_pipeline_router
from .pirs import router as pirs_router
from .provenance import router as provenance_router
from .reports import router as reports_router
from .tasks import router as tasks_router
from .temporal_decay import router as temporal_decay_router
from .zero_day import router as zero_day_router
from .organism import router as organism_router
from .alerts import router as alerts_router
from .precision import router as precision_router
from .innovation import router as innovation_router
from .deepseek import router as deepseek_router
from .analysis import router as analysis_router
from .prompt_engine import router as prompt_engine_router
from .data_pipeline import router as data_pipeline_router
from .finetune import router as finetune_router
from .smartqa import router as smartqa_router
from .content_gen import router as content_gen_router
from .translation import router as translation_router
from .data_analytics import router as data_analytics_router
from .deployment import router as deployment_router
from .dfx import router as dfx_router
from .notification import router as notification_router
from .threat_analysis import router as threat_analysis_router
from .industry_scene import router as industry_scene_router
from .intel_pipeline import router as intel_pipeline_router
from .narrative import router as narrative_router
from .deception import router as deception_router
from .exploit_lifecycle import router as exploit_lifecycle_router
from .game_theory import router as game_theory_router
from .persona import router as persona_router
from .audit_log import router as audit_log_router
from .taxii import taxii_router
from .siem_integration import siem_router
from .compliance import router as compliance_router
from .ner import router as ner_router
from .domain_finetune import router as domain_finetune_router
from .billing import router as billing_router
from .backup import router as backup_router
from .cases import cases_router
from .intelligence_quality import router as intelligence_quality_router
from .event_correlation import router as event_correlation_router
from .threat_behavior import router as threat_behavior_router
from .risk_scoring import router as risk_scoring_router
from .intelligence_fusion import router as intelligence_fusion_router

api_router = APIRouter()


@api_router.get("/version")
async def get_api_version():
    return {"version": "v1", "api_prefix": "/api/v1"}


api_router.include_router(auth_router)
api_router.include_router(api_keys_router)
api_router.include_router(intelligence_router)
api_router.include_router(intelligence_pipeline_router)
api_router.include_router(entities_router)
api_router.include_router(pirs_router)
api_router.include_router(reports_router)
api_router.include_router(blacktalk_router)
api_router.include_router(graph_router)
api_router.include_router(agent_router)
api_router.include_router(agent_report_router)
api_router.include_router(dashboard_router)
api_router.include_router(tasks_router)
api_router.include_router(zero_day_router)
api_router.include_router(attack_prediction_router)
api_router.include_router(provenance_router)
api_router.include_router(attribution_router)
api_router.include_router(temporal_decay_router, prefix="/temporal-decay")
api_router.include_router(organism_router)
api_router.include_router(alerts_router)
api_router.include_router(economic_router)
api_router.include_router(precision_router)
api_router.include_router(innovation_router)
api_router.include_router(deepseek_router)
api_router.include_router(analysis_router)
api_router.include_router(prompt_engine_router)
api_router.include_router(data_pipeline_router)
api_router.include_router(finetune_router, prefix="/finetune")
api_router.include_router(smartqa_router)
api_router.include_router(content_gen_router)
api_router.include_router(translation_router)
api_router.include_router(data_analytics_router)
api_router.include_router(deployment_router)
api_router.include_router(dfx_router)
api_router.include_router(notification_router)
api_router.include_router(threat_analysis_router)
api_router.include_router(industry_scene_router)
api_router.include_router(intel_pipeline_router)
api_router.include_router(narrative_router)
api_router.include_router(deception_router)
api_router.include_router(exploit_lifecycle_router)
api_router.include_router(game_theory_router)
api_router.include_router(persona_router)
api_router.include_router(audit_log_router)
api_router.include_router(taxii_router)
api_router.include_router(siem_router)
api_router.include_router(compliance_router)
api_router.include_router(ner_router)
api_router.include_router(domain_finetune_router)
api_router.include_router(billing_router)
api_router.include_router(backup_router)
api_router.include_router(cases_router)
api_router.include_router(intelligence_quality_router)
api_router.include_router(event_correlation_router)
api_router.include_router(threat_behavior_router)
api_router.include_router(risk_scoring_router)
api_router.include_router(intelligence_fusion_router)
