from fastapi import APIRouter, Depends, Request
from loguru import logger

from app.core.auth import User, get_current_user

router = APIRouter(prefix="/innovation", tags=["innovation"])


@router.get("/stats")
async def get_innovation_stats(request: Request, current_user: User = Depends(get_current_user)):
    stats = {}

    zero_day_detector = getattr(request.app.state, "zero_day_detector", None)
    if zero_day_detector is not None:
        vocab_size = len(zero_day_detector._word2idx)
        trained = zero_day_detector._trained
        zero_day_terms_count = len(zero_day_detector._term_vectors)
        stats["zero_day"] = {
            "vocab_size": vocab_size,
            "trained": trained,
            "zero_day_terms_count": zero_day_terms_count,
        }
    else:
        stats["zero_day"] = {
            "vocab_size": 0,
            "trained": False,
            "zero_day_terms_count": 0,
        }

    attack_chain_predictor = getattr(request.app.state, "attack_chain_predictor", None)
    if attack_chain_predictor is not None:
        from app.core.attack_chain_predictor import MITRE_TECHNIQUES
        mitre_techniques_count = len(MITRE_TECHNIQUES)
        total_transitions = attack_chain_predictor._total_transitions
        graph_nodes = 0
        try:
            graph_nodes = attack_chain_predictor.knowledge_graph.graph.number_of_nodes()
        except Exception as exc:
            logger.debug(f"Failed to get graph node count: {exc}")
        stats["attack_chain"] = {
            "mitre_techniques_count": mitre_techniques_count,
            "total_transitions": total_transitions,
            "graph_nodes": graph_nodes,
        }
    else:
        stats["attack_chain"] = {
            "mitre_techniques_count": 0,
            "total_transitions": 0,
            "graph_nodes": 0,
        }

    entity_attribution = getattr(request.app.state, "entity_attribution", None)
    if entity_attribution is not None:
        entity_count = len(entity_attribution._entity2idx)
        relation_count = len(entity_attribution._relation2idx)
        model_trained = entity_attribution._model is not None
        stats["entity_attribution"] = {
            "entity_count": entity_count,
            "relation_count": relation_count,
            "model_trained": model_trained,
        }
    else:
        stats["entity_attribution"] = {
            "entity_count": 0,
            "relation_count": 0,
            "model_trained": False,
        }

    temporal_decay = getattr(request.app.state, "temporal_decay", None)
    if temporal_decay is not None:
        threat_type_count = len(temporal_decay._half_lives)
        observation_count = sum(len(obs) for obs in temporal_decay._observations.values())
        stats["temporal_decay"] = {
            "threat_type_count": threat_type_count,
            "observation_count": observation_count,
        }
    else:
        stats["temporal_decay"] = {
            "threat_type_count": 0,
            "observation_count": 0,
        }

    provenance_chain = getattr(request.app.state, "provenance_chain", None)
    if provenance_chain is not None:
        chain_count = len(provenance_chain._chains)
        total_records = len(provenance_chain._records_by_id)
        stats["provenance"] = {
            "chain_count": chain_count,
            "total_records": total_records,
        }
    else:
        stats["provenance"] = {
            "chain_count": 0,
            "total_records": 0,
        }

    intelligence_organism = getattr(request.app.state, "intelligence_organism", None)
    if intelligence_organism is not None:
        alive_count = sum(1 for o in intelligence_organism.organisms.values() if o.is_alive)
        gene_count = len(intelligence_organism.genes)
        max_generation = 0
        for o in intelligence_organism.organisms.values():
            if o.generation > max_generation:
                max_generation = o.generation
        stats["organism"] = {
            "alive_organism_count": alive_count,
            "gene_count": gene_count,
            "max_generation": max_generation,
        }
    else:
        stats["organism"] = {
            "alive_organism_count": 0,
            "gene_count": 0,
            "max_generation": 0,
        }

    return stats


@router.get("/analyses")
async def get_analyses_alias(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    analyses = []

    zero_day_detector = getattr(request.app.state, "zero_day_detector", None)
    if zero_day_detector is not None:
        analyses.append({
            "type": "zero_day_detection",
            "vocab_size": len(zero_day_detector._word2idx),
            "trained": zero_day_detector._trained,
            "zero_day_terms_count": len(zero_day_detector._term_vectors),
        })

    attack_chain_predictor = getattr(request.app.state, "attack_chain_predictor", None)
    if attack_chain_predictor is not None:
        from app.core.attack_chain_predictor import MITRE_TECHNIQUES
        analyses.append({
            "type": "attack_chain_prediction",
            "mitre_techniques_count": len(MITRE_TECHNIQUES),
            "total_transitions": attack_chain_predictor._total_transitions,
        })

    entity_attribution = getattr(request.app.state, "entity_attribution", None)
    if entity_attribution is not None:
        analyses.append({
            "type": "entity_attribution",
            "entity_count": len(entity_attribution._entity2idx),
            "model_trained": entity_attribution._model is not None,
        })

    return {"analyses": analyses, "total": len(analyses)}
