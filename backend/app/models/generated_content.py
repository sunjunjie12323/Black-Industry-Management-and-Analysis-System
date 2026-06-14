from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict
from enum import Enum


class ContentType(str, Enum):
    REPORT_SUMMARY = "report_summary"
    INTEL_BRIEF = "intel_brief"
    SECURITY_ADVICE = "security_advice"
    TREND_ANALYSIS = "trend_analysis"
    THREAT_ASSESSMENT = "threat_assessment"
    ATTACK_CHAIN_ANALYSIS = "attack_chain_analysis"
    THREAT_SITUATION_BRIEF = "threat_situation_brief"
    HIGH_RISK_ALERT = "high_risk_alert"
    IOC_REPORT = "ioc_report"
    CRIME_PATTERN_ANALYSIS = "crime_pattern_analysis"


class ReviewStatus(str, Enum):
    PENDING = "pending"
    AUTO_CHECKED = "auto_checked"
    EXPERT_REVIEW = "expert_review"
    SUPERVISOR_APPROVED = "supervisor_approved"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVISED = "revised"


@dataclass
class GeneratedContent:
    id: str
    title: str
    content_type: ContentType
    content: str
    review_status: ReviewStatus = ReviewStatus.PENDING
    reviewer: Optional[str] = None
    review_comment: Optional[str] = None
    source_refs: List[str] = field(default_factory=list)
    model_id: Optional[str] = None
    prompt_template_id: Optional[str] = None
    parent_id: Optional[str] = None
    created_at: Optional[datetime] = None
    reviewed_at: Optional[datetime] = None
    created_by: str = "system"

    def approve(self, reviewer: str, comment: str = "") -> None:
        self.review_status = ReviewStatus.APPROVED
        self.reviewer = reviewer
        self.review_comment = comment
        self.reviewed_at = datetime.now(timezone.utc)

    def reject(self, reviewer: str, comment: str = "") -> None:
        self.review_status = ReviewStatus.REJECTED
        self.reviewer = reviewer
        self.review_comment = comment
        self.reviewed_at = datetime.now(timezone.utc)

    def revise(self, new_content: str) -> None:
        self.content = new_content
        self.review_status = ReviewStatus.REVISED
        self.reviewed_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "content_type": self.content_type.value if isinstance(self.content_type, ContentType) else self.content_type,
            "content": self.content,
            "review_status": self.review_status.value if isinstance(self.review_status, ReviewStatus) else self.review_status,
            "reviewer": self.reviewer,
            "review_comment": self.review_comment,
            "source_refs": self.source_refs,
            "model_id": self.model_id,
            "prompt_template_id": self.prompt_template_id,
            "parent_id": self.parent_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "created_by": self.created_by,
        }
