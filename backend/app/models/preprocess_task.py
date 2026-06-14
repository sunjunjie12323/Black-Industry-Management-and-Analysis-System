from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskType(str, Enum):
    IMPORT = "import"
    CLEAN = "clean"
    LABEL = "label"
    AUGMENT = "augment"
    FORMAT_CONVERT = "format_convert"


@dataclass
class PipelineStep:
    step_type: TaskType
    config: Dict[str, Any]
    order: int

    def to_dict(self) -> Dict:
        return {
            "step_type": self.step_type.value if isinstance(self.step_type, TaskType) else self.step_type,
            "config": self.config,
            "order": self.order,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "PipelineStep":
        return cls(
            step_type=TaskType(data["step_type"]) if isinstance(data.get("step_type"), str) else data["step_type"],
            config=data.get("config", {}),
            order=data.get("order", 0),
        )


@dataclass
class PreprocessTask:
    id: str
    name: str
    task_type: TaskType
    status: TaskStatus = TaskStatus.PENDING
    config_json: str = "{}"
    pipeline_steps: List[PipelineStep] = field(default_factory=list)
    input_data_ref: Optional[str] = None
    output_data_ref: Optional[str] = None
    progress: float = 0.0
    error_message: Optional[str] = None
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: str = "system"

    def validate(self) -> List[str]:
        errors = []
        if not self.name.strip():
            errors.append("任务名称不能为空")
        if self.progress < 0 or self.progress > 1:
            errors.append("进度值必须在0-1之间")
        for step in self.pipeline_steps:
            if step.order < 0:
                errors.append(f"步骤顺序不能为负数: {step.step_type}")
        return errors

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "task_type": self.task_type.value if isinstance(self.task_type, TaskType) else self.task_type,
            "status": self.status.value if isinstance(self.status, TaskStatus) else self.status,
            "config_json": self.config_json,
            "pipeline_steps": [s.to_dict() for s in self.pipeline_steps],
            "input_data_ref": self.input_data_ref,
            "output_data_ref": self.output_data_ref,
            "progress": self.progress,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_by": self.created_by,
        }
