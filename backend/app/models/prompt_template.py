from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict
from enum import Enum


class PromptCategory(str, Enum):
    ANALYSIS = "analysis"
    GENERATION = "generation"
    TRANSLATION = "translation"
    EXTRACTION = "extraction"
    SUMMARIZATION = "summarization"
    CLASSIFICATION = "classification"
    THREAT_INTEL = "threat_intel"
    ATTACK_CHAIN = "attack_chain"
    BLACKTALK = "blacktalk"
    CUSTOM = "custom"


@dataclass
class PromptVariable:
    name: str
    description: str
    default_value: Optional[str] = None
    required: bool = True
    var_type: str = "string"

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "default_value": self.default_value,
            "required": self.required,
            "var_type": self.var_type,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "PromptVariable":
        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            default_value=data.get("default_value"),
            required=data.get("required", True),
            var_type=data.get("var_type", "string"),
        )


@dataclass
class PromptTemplate:
    id: str
    name: str
    description: str
    category: PromptCategory
    content: str
    variables: List[PromptVariable]
    version: int = 1
    is_active: bool = True
    tags: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: str = "system"
    parent_id: Optional[str] = None

    def render(self, **kwargs) -> str:
        result = self.content
        for var in self.variables:
            value = kwargs.get(var.name, var.default_value or "")
            result = result.replace(f"{{{{{var.name}}}}}", str(value))
        return result

    def validate_variables(self, **kwargs) -> List[str]:
        missing = []
        for var in self.variables:
            if var.required and var.name not in kwargs and not var.default_value:
                missing.append(var.name)
        return missing

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value if isinstance(self.category, PromptCategory) else self.category,
            "content": self.content,
            "variables": [v.to_dict() for v in self.variables],
            "version": self.version,
            "is_active": self.is_active,
            "tags": self.tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by": self.created_by,
            "parent_id": self.parent_id,
        }
