from typing import Any, Dict, Optional


class AppException(Exception):
    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"
    detail: str = "An internal server error occurred"

    def __init__(
        self,
        detail: Optional[str] = None,
        error_code: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        if detail is not None:
            self.detail = detail
        if error_code is not None:
            self.error_code = error_code
        if status_code is not None:
            self.status_code = status_code
        self.details = details or {}
        super().__init__(self.detail)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "code": self.error_code,
            "message": self.detail,
        }
        if self.details:
            result["details"] = self.details
        return result


class NotFoundException(AppException):
    status_code = 404
    error_code = "NOT_FOUND"
    detail = "Resource not found"


class UnauthorizedException(AppException):
    status_code = 401
    error_code = "UNAUTHORIZED"
    detail = "Authentication required"


class ForbiddenException(AppException):
    status_code = 403
    error_code = "FORBIDDEN"
    detail = "Insufficient permissions"


class ValidationException(AppException):
    status_code = 422
    error_code = "VALIDATION_ERROR"
    detail = "Validation error"


class LLMException(AppException):
    status_code = 502
    error_code = "LLM_ERROR"
    detail = "LLM service error"


class CollectorException(AppException):
    status_code = 502
    error_code = "COLLECTOR_ERROR"
    detail = "Data collection error"


class AgentException(AppException):
    status_code = 500
    error_code = "AGENT_ERROR"
    detail = "Agent execution error"


class RateLimitExceededException(AppException):
    status_code = 429
    error_code = "RATE_LIMIT_EXCEEDED"
    detail = "Rate limit exceeded"


class DatabaseException(AppException):
    status_code = 500
    error_code = "DATABASE_ERROR"
    detail = "数据库操作失败"


class ConflictException(AppException):
    status_code = 409
    error_code = "CONFLICT"
    detail = "资源冲突"
