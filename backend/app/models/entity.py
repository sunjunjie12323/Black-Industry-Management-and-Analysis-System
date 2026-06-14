from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    PHONE = "phone"
    ACCOUNT = "account"
    TOOL = "tool"
    BLACKTALK = "blacktalk"
    ORGANIZATION = "organization"
    PERSON = "person"
    CRYPTO_WALLET = "crypto_wallet"
    PAYMENT_METHOD = "payment_method"
    MALWARE = "malware"
    SERVICE = "service"


class RelationType(str, Enum):
    USES = "uses"
    BELONGS_TO = "belongs_to"
    COMMUNICATES_WITH = "communicates_with"
    OPERATES = "operates"
    SELLS = "sells"
    BUYS = "buys"
    ASSOCIATED_WITH = "associated_with"
    LOCATED_IN = "located_in"
    CONTROLS = "controls"
    DERIVED_FROM = "derived_from"


def _new_id() -> str:
    return uuid4().hex


class Entity(BaseModel):
    id: str = Field(default_factory=_new_id)
    type: EntityType
    value: str
    context: Optional[str] = None
    source_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Relation(BaseModel):
    id: str = Field(default_factory=_new_id)
    source_entity_id: str
    target_entity_id: str
    type: RelationType
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
