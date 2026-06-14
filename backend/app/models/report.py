from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class ReportStatus(str, Enum):
    DRAFT = "draft"
    REVIEW = "review"
    REVIEWING = "reviewing"
    PUBLISHED = "published"


def _new_id() -> str:
    return uuid4().hex


class Report(BaseModel):
    id: str = Field(default_factory=_new_id)
    title: str
    pir_id: Optional[str] = None
    status: ReportStatus = ReportStatus.DRAFT
    summary: str = ""
    key_findings: List[Any] = Field(default_factory=list)
    threat_actors: List[Any] = Field(default_factory=list)
    iocs: List[Any] = Field(default_factory=list)
    attack_chains: List[Any] = Field(default_factory=list)
    recommendations: List[Any] = Field(default_factory=list)
    evidence_chain: List[Any] = Field(default_factory=list)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    author: str = "system"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    published_at: Optional[datetime] = None
