import traceback as _tb
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from jose import JWTError
from loguru import logger
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.core.exceptions import AppException
from app.middleware import request_id_ctx


def _build_error_response(
    status_code: int,
    error_code: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    rid = request_id or request_id_ctx.get() or uuid.uuid4().hex
    body: Dict[str, Any] = {
        "success": False,
        "data": None,
        "error_code": error_code,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": rid,
    }
    if details:
        body["details"] = details
    return body


def _attach_request_id(response: JSONResponse, request_id: Optional[str] = None) -> JSONResponse:
    rid = request_id or request_id_ctx.get() or ""
    if rid:
        response.headers["X-Request-ID"] = rid
    return response


async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    rid = request_id_ctx.get() or ""
    body = _build_error_response(
        status_code=exc.status_code,
        error_code=exc.error_code,
        message=exc.detail,
        details=getattr(exc, "details", None),
        request_id=rid,
    )
    return _attach_request_id(JSONResponse(status_code=exc.status_code, content=body), rid)


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    rid = request_id_ctx.get() or ""
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    code_map = {
        400: "BAD_REQUEST",
        401: "AUTH_INVALID_TOKEN",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        415: "UNSUPPORTED_MEDIA_TYPE",
        422: "VALIDATION_ERROR",
        429: "RATE_LIMIT_EXCEEDED",
        500: "INTERNAL_ERROR",
        502: "BAD_GATEWAY",
        503: "SERVICE_UNAVAILABLE",
        504: "GATEWAY_TIMEOUT",
    }
    error_code = code_map.get(exc.status_code, f"HTTP_{exc.status_code}")
    body = _build_error_response(
        status_code=exc.status_code,
        error_code=error_code,
        message=detail,
        request_id=rid,
    )
    return _attach_request_id(JSONResponse(status_code=exc.status_code, content=body, headers=exc.headers or None), rid)


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    rid = request_id_ctx.get() or ""
    field_details = []
    for err in exc.errors():
        field_details.append(
            {
                "field": ".".join(str(p) for p in err.get("loc", [])),
                "message": err.get("msg", ""),
                "type": err.get("type", ""),
            }
        )
    body = _build_error_response(
        status_code=422,
        error_code="VALIDATION_ERROR",
        message="请求参数验证失败",
        details={"fields": field_details},
        request_id=rid,
    )
    return _attach_request_id(JSONResponse(status_code=422, content=body), rid)


async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    rid = request_id_ctx.get() or ""
    logger.error(f"Database error [request_id={rid}]: {exc}")
    body = _build_error_response(
        status_code=500,
        error_code="DATABASE_ERROR",
        message="数据库操作失败,请稍后重试",
        request_id=rid,
    )
    if not settings.is_production:
        body["details"] = {"error": str(exc)[:200]}
    return _attach_request_id(JSONResponse(status_code=500, content=body), rid)


async def jwt_exception_handler(request: Request, exc: JWTError) -> JSONResponse:
    rid = request_id_ctx.get() or ""
    body = _build_error_response(
        status_code=401,
        error_code="AUTH_INVALID_TOKEN",
        message="认证令牌无效或已过期",
        request_id=rid,
    )
    return _attach_request_id(JSONResponse(status_code=401, content=body), rid)


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    rid = request_id_ctx.get() or ""
    error_id = uuid.uuid4().hex[:12]
    tb_str = _tb.format_exc()
    logger.error(f"[error_id={error_id}] Unhandled exception [request_id={rid}]: {exc}\n{tb_str}")
    body = _build_error_response(
        status_code=500,
        error_code="INTERNAL_ERROR",
        message="服务器内部错误,请稍后重试",
        details={"error_id": error_id},
        request_id=rid,
    )
    if not settings.is_production:
        body["details"] = {"error_id": error_id, "error": str(exc)[:200]}
    return _attach_request_id(JSONResponse(status_code=500, content=body), rid)


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppException, app_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(SQLAlchemyError, sqlalchemy_exception_handler)
    app.add_exception_handler(JWTError, jwt_exception_handler)
    app.add_exception_handler(Exception, global_exception_handler)
