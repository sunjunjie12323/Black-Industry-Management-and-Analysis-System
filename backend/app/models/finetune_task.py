from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum


class FinetuneMethod(str, Enum):
    LORA = "lora"
    FULL = "full"


class FinetuneStatus(str, Enum):
    PENDING = "pending"
    PREPARING = "preparing"
    TRAINING = "training"
    EVALUATING = "evaluating"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class FinetuneTask:
    id: str
    name: str
    method: FinetuneMethod
    base_model: str
    status: FinetuneStatus = FinetuneStatus.PENDING
    config_json: str = "{}"
    dataset_ref: Optional[str] = None
    checkpoint_ref: Optional[str] = None
    output_model_ref: Optional[str] = None
    metrics_json: Optional[str] = None
    version: int = 1
    progress: float = 0.0
    error_message: Optional[str] = None
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: str = "system"
    parent_id: Optional[str] = None

    def validate(self) -> list:
        errors = []
        if not self.name.strip():
            errors.append("任务名称不能为空")
        if not self.base_model.strip():
            errors.append("基础模型不能为空")
        if self.progress < 0 or self.progress > 1:
            errors.append("进度值必须在0-1之间")
        return errors

    def get_config(self) -> Dict[str, Any]:
        import json
        try:
            return json.loads(self.config_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def get_metrics(self) -> Dict[str, Any]:
        import json
        if not self.metrics_json:
            return {}
        try:
            return json.loads(self.metrics_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "method": self.method.value if isinstance(self.method, FinetuneMethod) else self.method,
            "base_model": self.base_model,
            "status": self.status.value if isinstance(self.status, FinetuneStatus) else self.status,
            "config_json": self.config_json,
            "dataset_ref": self.dataset_ref,
            "checkpoint_ref": self.checkpoint_ref,
            "output_model_ref": self.output_model_ref,
            "metrics_json": self.metrics_json,
            "version": self.version,
            "progress": self.progress,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_by": self.created_by,
            "parent_id": self.parent_id,
        }
