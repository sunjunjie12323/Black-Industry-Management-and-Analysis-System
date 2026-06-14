from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint'],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

LLM_CALL_COUNT = Counter(
    'llm_calls_total',
    'Total LLM API calls',
    ['model', 'status']
)

LLM_CALL_DURATION = Histogram(
    'llm_call_duration_seconds',
    'LLM API call duration',
    ['model']
)

LLM_TOKENS_USED = Counter(
    'llm_tokens_total',
    'Total LLM tokens used',
    ['model', 'type']
)

INTELLIGENCE_COLLECTED = Counter(
    'intelligence_collected_total',
    'Total intelligence items collected',
    ['source', 'status']
)

ENTITY_COUNT = Gauge(
    'knowledge_graph_entities',
    'Number of entities in knowledge graph',
    ['entity_type']
)

RELATION_COUNT = Gauge(
    'knowledge_graph_relations',
    'Number of relations in knowledge graph'
)

ACTIVE_ORGANISMS = Gauge(
    'intelligence_organisms_active',
    'Number of active intelligence organisms'
)

VECTOR_STORE_SIZE = Gauge(
    'vector_store_documents',
    'Number of documents in vector store',
    ['collection']
)

CIRCUIT_BREAKER_STATE = Gauge(
    'circuit_breaker_open',
    'Whether circuit breaker is open',
    ['service']
)

APP_INFO = Info(
    'threat_intel_app',
    'Application information'
)


def metrics_endpoint():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
