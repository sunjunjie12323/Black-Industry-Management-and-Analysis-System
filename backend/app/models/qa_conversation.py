from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum


@dataclass
class QAMessage:
    role: str
    content: str
    references: List[Dict[str, Any]] = field(default_factory=list)
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "role": self.role,
            "content": self.content,
            "references": self.references,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "QAMessage":
        return cls(
            role=data.get("role", "user"),
            content=data.get("content", ""),
            references=data.get("references", []),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
        )


@dataclass
class QAConversation:
    id: str
    title: str
    messages: List[QAMessage] = field(default_factory=list)
    industry: Optional[str] = None
    rag_enabled: bool = True
    model_id: Optional[str] = None
    conversation_type: Optional[str] = None
    is_active: bool = True
    description: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: str = "system"

    def add_message(self, role: str, content: str, references: List[Dict] = None) -> QAMessage:
        msg = QAMessage(
            role=role,
            content=content,
            references=references or [],
            created_at=datetime.now(timezone.utc),
        )
        self.messages.append(msg)
        self.updated_at = datetime.now(timezone.utc)
        return msg

    def get_context_messages(self, max_messages: int = 20) -> List[Dict]:
        recent = self.messages[-max_messages:]
        return [{"role": m.role, "content": m.content} for m in recent]

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "messages": [m.to_dict() for m in self.messages],
            "industry": self.industry,
            "rag_enabled": self.rag_enabled,
            "model_id": self.model_id,
            "conversation_type": self.conversation_type,
            "is_active": self.is_active,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by": self.created_by,
        }
