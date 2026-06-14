from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select


DEFAULT_LIMIT: int = 20
MAX_LIMIT: int = 100


@dataclass
class PageParams:
    limit: int = DEFAULT_LIMIT
    offset: int = 0
    cursor: Optional[str] = None

    def __post_init__(self) -> None:
        if self.limit is None or self.limit <= 0:
            self.limit = DEFAULT_LIMIT
        if self.limit > MAX_LIMIT:
            self.limit = MAX_LIMIT
        if self.offset is None or self.offset < 0:
            self.offset = 0

    @classmethod
    def from_query(
        cls,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
        cursor: Optional[str] = None,
    ) -> "PageParams":
        return cls(limit=limit, offset=offset, cursor=cursor)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "limit": self.limit,
            "offset": self.offset,
            "cursor": self.cursor,
        }


def encode_cursor(value: Any) -> str:
    if value is None:
        return ""
    raw = str(value).encode("utf-8")
    return urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> Optional[str]:
    if not cursor:
        return None
    padding = "=" * (-len(cursor) % 4)
    try:
        return urlsafe_b64decode((cursor + padding).encode("ascii")).decode("utf-8")
    except Exception:
        return None


async def paginate_query(
    query: Select,
    page_params: PageParams,
    session: AsyncSession,
    cursor_column: Optional[Any] = None,
) -> Dict[str, Any]:
    if page_params.cursor and cursor_column is not None:
        decoded = decode_cursor(page_params.cursor)
        if decoded is not None:
            try:
                cursor_value = _coerce_cursor_value(decoded, cursor_column)
                query = query.where(cursor_column > cursor_value)
            except Exception:
                pass

    count_stmt = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_stmt)
    total = int(total_result.scalar() or 0)

    paged_stmt = query.order_by(getattr(cursor_column, "asc", lambda: None)() if cursor_column is not None else None)
    paged_stmt = paged_stmt.limit(page_params.limit).offset(page_params.offset)

    result = await session.execute(paged_stmt)
    items: List[Any] = list(result.scalars().all())

    next_offset: Optional[int] = None
    has_next: bool = False
    if page_params.offset + len(items) < total:
        next_offset = page_params.offset + page_params.limit
        has_next = True

    next_cursor: Optional[str] = None
    if cursor_column is not None and items:
        last = items[-1]
        last_value = getattr(last, cursor_column.key, None) if hasattr(cursor_column, "key") else None
        if last_value is None and hasattr(last, "_mapping"):
            try:
                last_value = last._mapping[cursor_column.key]
            except Exception:
                last_value = None
        if last_value is not None and has_next:
            next_cursor = encode_cursor(last_value)

    return {
        "items": items,
        "total": total,
        "limit": page_params.limit,
        "offset": page_params.offset,
        "next_offset": next_offset,
        "has_next": has_next,
        "next_cursor": next_cursor,
    }


def _coerce_cursor_value(raw: str, column: Any) -> Any:
    py_type = getattr(column, "type", None)
    type_name = type(py_type).__name__ if py_type is not None else ""
    if "Integer" in type_name or "BigInteger" in type_name or "SmallInteger" in type_name:
        return int(raw)
    if "Float" in type_name or "Numeric" in type_name or "Decimal" in type_name:
        return float(raw)
    if "DateTime" in type_name or "Date" in type_name or "Time" in type_name:
        from datetime import datetime
        return datetime.fromisoformat(raw)
    return raw
