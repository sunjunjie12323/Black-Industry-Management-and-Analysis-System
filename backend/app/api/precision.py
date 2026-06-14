from fastapi import APIRouter, Depends, Request
from app.core.auth import get_current_user, User
from app.config import settings

router = APIRouter(prefix="/precision", tags=["precision"])

DEFAULT_ENGINE_CHECKS = [
    ("zero_day_detector", "零日检测", ["detect_zero_day_terms"]),
    ("attack_chain_predictor", "攻击链预测", ["predict_next_steps"]),
    ("provenance_chain", "溯源链", ["record_provenance", "verify_provenance", "detect_hallucination"]),
    ("entity_attribution", "实体归因", ["attribute_entity", "find_similar_entities"]),
    ("temporal_decay", "时效衰减", ["batch_decay", "recommendations"]),
    ("intelligence_organism", "情报生命体", ["spawn", "evolve", "check_vitality"]),
    ("alert_engine", "告警引擎", ["evaluate_rule", "get_active_alerts"]),
]


@router.get("/report")
async def get_precision_report(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    report = {
        "engines": [],
        "overall_score": 0.0,
        "evaluation_time": None,
    }
    from datetime import datetime, timezone
    report["evaluation_time"] = datetime.now(timezone.utc).isoformat()

    engine_checks = DEFAULT_ENGINE_CHECKS

    total_methods = 0
    available_methods = 0

    for attr_name, display_name, methods in engine_checks:
        engine = getattr(request.app.state, attr_name, None)
        available = []
        missing = []
        for method in methods:
            if engine and hasattr(engine, method):
                available.append(method)
                available_methods += 1
            else:
                missing.append(method)
            total_methods += 1

        engine_info = {
            "name": display_name,
            "attribute": attr_name,
            "available": engine is not None,
            "methods_available": available,
            "methods_missing": missing,
            "method_coverage": len(available) / len(methods) if methods else 0,
        }
        report["engines"].append(engine_info)

    report["overall_score"] = available_methods / total_methods if total_methods > 0 else 0

    data_checks = {
        "cache_service": hasattr(request.app.state, 'cache_service'),
        "vector_store": hasattr(request.app.state, 'vector_store'),
        "knowledge_graph": hasattr(request.app.state, 'knowledge_graph'),
    }

    report["infrastructure"] = data_checks

    return report


@router.get("/models")
async def get_models_alias(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine_checks = [(a, n) for a, n, _ in DEFAULT_ENGINE_CHECKS]
    models = []
    for attr_name, display_name in engine_checks:
        engine = getattr(request.app.state, attr_name, None)
        models.append({
            "name": display_name,
            "attribute": attr_name,
            "available": engine is not None,
        })
    return {"models": models, "total": len(models)}
