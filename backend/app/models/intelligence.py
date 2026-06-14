from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class IntelligenceSource(str, Enum):
    TELEGRAM = "telegram"
    FORUM = "forum"
    WECHAT = "wechat"
    DARKWEB = "darkweb"
    QQ_GROUP = "qq_group"
    WEIBO = "weibo"
    CISA_KEV = "cisa_kev"
    URLHAUS = "urlhaus"
    MALWARE_BAZAAR = "malware_bazaar"
    ALIENVAULT_OTX = "alienvault_otx"
    RANSOMWARE_WATCH = "ransomware_watch"
    BREACH_TRACKER = "breach_tracker"
    PHISH_TRACKER = "phish_tracker"
    DARKWEB_MONITOR = "darkweb_monitor"
    CRYPTO_TRACKER = "crypto_tracker"
    BOTNET_TRACKER = "botnet_tracker"
    SUPPLY_CHAIN_MONITOR = "supply_chain_monitor"
    ZERODAY_TRACKER = "zeroday_tracker"
    SEED = "seed"
    COMMERCIAL = "commercial"
    REALTIME = "realtime"
    OTHER = "other"


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IntelligenceStatus(str, Enum):
    RAW = "raw"
    CLEANED = "cleaned"
    ANALYZED = "analyzed"
    REPORTED = "reported"


def _new_id() -> str:
    return uuid4().hex


class RawIntelligence(BaseModel):
    id: str = Field(default_factory=_new_id)
    source: IntelligenceSource
    source_url: Optional[str] = None
    content: str
    raw_content: Optional[str] = None
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    status: IntelligenceStatus = IntelligenceStatus.RAW


class CleanedIntelligence(BaseModel):
    id: str = Field(default_factory=_new_id)
    raw_id: str
    content: str
    decoded_content: Optional[str] = None
    blacktalk_terms: Dict[str, str] = Field(default_factory=dict)
    entities: List[str] = Field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.INFO
    cleaned_at: datetime = Field(default_factory=datetime.utcnow)


class AnalyzedIntelligence(BaseModel):
    id: str = Field(default_factory=_new_id)
    cleaned_id: str
    threat_level: ThreatLevel = ThreatLevel.INFO
    threat_categories: List[str] = Field(default_factory=list)
    attack_patterns: List[str] = Field(default_factory=list)
    technique_chain: List[str] = Field(default_factory=list)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    analysis_summary: str = ""
    evidence_refs: List[str] = Field(default_factory=list)
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)


class IntelligenceReport(BaseModel):
    id: str = Field(default_factory=_new_id)
    pir_id: Optional[str] = None
    title: str
    summary: str = ""
    key_findings: List[str] = Field(default_factory=list)
    threat_actors: List[Any] = Field(default_factory=list)
    iocs: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_chain: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
