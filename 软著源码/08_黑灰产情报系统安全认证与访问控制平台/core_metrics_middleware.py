import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.metrics import REQUEST_COUNT, REQUEST_DURATION


class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        method = request.method

        if path in ("/metrics", "/health", "/health/live", "/health/ready"):
            return await call_next(request)

        start_time = time.monotonic()
        response = await call_next(request)
        duration = time.monotonic() - start_time

        status = str(response.status_code)
        REQUEST_COUNT.labels(method=method, endpoint=path, status=status).inc()
        REQUEST_DURATION.labels(method=method, endpoint=path).observe(duration)

        return response
