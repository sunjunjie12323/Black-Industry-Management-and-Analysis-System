from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class UserApiKeyTable(Base):
    __tablename__ = "user_api_keys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_id: Mapped[str] = mapped_column(String(16), nullable=False, unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    secret_prefix: Mapped[str] = mapped_column(String(8), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    rate_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_user_api_keys_user_active", "user_id", "is_active"),
        Index("ix_user_api_keys_expires", "expires_at"),
    )


class UserApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    scopes: List[str] = Field(default_factory=list)
    rate_limit: int = Field(default=60, ge=1, le=100000)
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=3650)


class UserApiKeyOut(BaseModel):
    id: str
    key_id: str
    secret_prefix: str
    name: str
    scopes: List[str] = Field(default_factory=list)
    rate_limit: int
    is_active: bool
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime


class UserApiKeyCreateResponse(UserApiKeyOut):
    secret: str


class ApiKeyAuthResult(BaseModel):
    user_id: str
    key_id: str
    api_key_id: str
    scopes: List[str] = Field(default_factory=list)
    rate_limit: int = 60
