import re
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import HTTPException
from loguru import logger
from sqlalchemy.exc import IntegrityError, OperationalError, DataError
from sqlalchemy.ext.asyncio import AsyncSession

_SAFE_OPERATION_RE = re.compile(r"[^\w\u4e00-\u9fff\s]")


def _sanitize_operation(operation: str) -> str:
    return _SAFE_OPERATION_RE.sub("", operation)[:50]


class DBErrorHandler:
    @staticmethod
    @asynccontextmanager
    async def write_operation(db: AsyncSession, operation: str = "操作"):
        safe_op = _sanitize_operation(operation)
        try:
            yield
            await db.commit()
        except IntegrityError as exc:
            await db.rollback()
            orig = str(exc.orig) if exc.orig else str(exc)
            if "unique" in orig.lower() or "duplicate" in orig.lower():
                raise HTTPException(status_code=409, detail=f"{safe_op}失败：数据已存在或名称重复")
            if "foreign key" in orig.lower() or "references" in orig.lower():
                raise HTTPException(status_code=409, detail=f"{safe_op}失败：关联数据不存在")
            if "not null" in orig.lower() or "check constraint" in orig.lower():
                raise HTTPException(status_code=422, detail=f"{safe_op}失败：数据校验不通过")
            logger.error(f"DB IntegrityError during {safe_op}: {orig[:200]}")
            raise HTTPException(status_code=409, detail=f"{safe_op}失败：数据约束冲突")
        except OperationalError as exc:
            await db.rollback()
            logger.error(f"DB OperationalError during {safe_op}: {str(exc)[:200]}")
            raise HTTPException(status_code=503, detail=f"{safe_op}失败：数据库暂时不可用，请稍后重试")
        except DataError as exc:
            await db.rollback()
            logger.error(f"DB DataError during {safe_op}: {str(exc)[:200]}")
            raise HTTPException(status_code=422, detail=f"{safe_op}失败：数据格式错误")
        except Exception as exc:
            await db.rollback()
            logger.error(f"DB Error during {safe_op}: {str(exc)[:200]}")
            raise HTTPException(status_code=500, detail=f"{safe_op}失败：服务器内部错误")

    @staticmethod
    @asynccontextmanager
    async def read_operation(db: AsyncSession, operation: str = "查询"):
        safe_op = _sanitize_operation(operation)
        try:
            yield
        except OperationalError as exc:
            logger.error(f"DB OperationalError during {safe_op}: {str(exc)[:200]}")
            raise HTTPException(status_code=503, detail=f"{safe_op}失败：数据库暂时不可用")
        except Exception as exc:
            logger.error(f"DB Error during {safe_op}: {str(exc)[:200]}")
            raise HTTPException(status_code=500, detail=f"{safe_op}失败：服务器内部错误")


db_write = DBErrorHandler.write_operation
db_read = DBErrorHandler.read_operation
