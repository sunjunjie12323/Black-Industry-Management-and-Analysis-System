from datetime import datetime, timezone
from typing import Any, Generic, Optional, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")

class ApiResponse(BaseModel, Generic[T]):
    success: bool = True
    data: Optional[T] = None
    message: str = "ok"
    code: int = 200
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    class Config:
        from_attributes = True

class PaginatedData(BaseModel, Generic[T]):
    items: list[T] = []
    total: int = 0
    page: int = 1
    page_size: int = 20
    has_more: bool = False

class ErrorDetail(BaseModel):
    code: int
    message: str
    detail: Optional[str] = None

def success(data: Any = None, message: str = "ok", code: int = 200) -> dict:
    return {
        "success": True,
        "data": data,
        "message": message,
        "code": code,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def error(message: str, code: int = 500, detail: str = None) -> dict:
    return {
        "success": False,
        "data": None,
        "message": message,
        "code": code,
        "detail": detail,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

def paginated(items: list, total: int, page: int = 1, page_size: int = 20) -> dict:
    return success({
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_more": total > page * page_size,
    })
