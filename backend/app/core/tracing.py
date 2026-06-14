import functools
import os

from loguru import logger


_tracer = None
_setup_done = False


def setup_tracing(app=None, engine=None):
    global _tracer, _setup_done

    otel_enabled = os.environ.get("OTEL_ENABLED", "false").lower() in ("1", "true", "yes")
    if not otel_enabled:
        logger.info("OpenTelemetry tracing disabled")
        _setup_done = True
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource
    except ImportError:
        logger.warning("OpenTelemetry packages not installed, tracing disabled")
        _setup_done = True
        return

    service_name = os.environ.get("OTEL_SERVICE_NAME", "threat-intel-agent")
    otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

    if otlp_endpoint == "http://localhost:4317":
        try:
            from app.config import settings
            if settings.is_production:
                logger.warning("OTEL endpoint is localhost in production; set OTEL_EXPORTER_OTLP_ENDPOINT")
        except ImportError:
            pass

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        logger.info(f"OpenTelemetry tracing enabled: {service_name} -> {otlp_endpoint}")
    except ImportError:
        logger.warning("OTLP exporter not installed, using default exporter")

    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer(service_name)

    if app:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(app)
        except ImportError:
            logger.debug("FastAPIInstrumentor not available")

    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        HTTPXClientInstrumentor().instrument()
    except ImportError:
        logger.debug("HTTPXClientInstrumentor not available")

    if engine:
        try:
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
            SQLAlchemyInstrumentor().instrument(engine=engine.sync_engine)
        except ImportError:
            logger.debug("SQLAlchemyInstrumentor not available")

    _setup_done = True


def get_tracer(name: str = "threat-intel"):
    try:
        from opentelemetry import trace
        return trace.get_tracer(name)
    except ImportError:
        return None


def traced(name: str = None):
    def decorator(func):
        tracer_name = name or func.__module__

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer(tracer_name)
            if tracer is None:
                return await func(*args, **kwargs)
            with tracer.start_as_current_span(func.__name__) as span:
                span.set_attribute("function", func.__name__)
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    span.set_attribute("error", True)
                    span.set_attribute("error.message", str(e))
                    raise
        return async_wrapper
    return decorator
