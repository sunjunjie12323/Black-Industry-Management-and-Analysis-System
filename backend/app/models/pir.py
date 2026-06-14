from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from .intelligence import IntelligenceSource


class PIRStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    FULFILLED = "fulfilled"
    EXPIRED = "expired"


class PIRPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PIRTaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


def _new_id() -> str:
    return uuid4().hex


class PIR(BaseModel):
    id: str = Field(default_factory=_new_id)
    title: str
    description: str = ""
    priority: PIRPriority = PIRPriority.MEDIUM
    status: PIRStatus = PIRStatus.ACTIVE
    keywords: List[str] = Field(default_factory=list)
    target_sources: List[IntelligenceSource] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    fulfilled_at: Optional[datetime] = None
    results_summary: Optional[str] = None


class PIRTask(BaseModel):
    id: str = Field(default_factory=_new_id)
    pir_id: str
    agent_type: str
    task_description: str = ""
    status: PIRTaskStatus = PIRTaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
