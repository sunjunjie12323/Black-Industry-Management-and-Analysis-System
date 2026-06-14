"""
Economic Models — 黑灰产经济系统数据模型
用于API请求/响应的Pydantic模型
"""
from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class MarketStateResponse(BaseModel):
    sector: str
    sector_name: str
    price_index: float
    volume_24h: float
    volatility: float
    trend: str
    risk_score: float
    market_cap_estimate: float
    active_entities: int
    last_updated: str


class EconomicImpactResponse(BaseModel):
    impact_id: str
    sector: str
    estimated_loss: float
    affected_users: int
    geographic_scope: List[str]
    duration_days: int
    confidence: float
    intelligence_source_ids: List[str]
    threat_categories: List[str]
    assessed_at: str


class MarketAlertResponse(BaseModel):
    alert_id: str
    sector: str
    alert_type: str
    severity: str
    message: str
    related_intelligence_ids: List[str]
    economic_impact_ids: List[str]
    created_at: str
    is_resolved: bool


class TransactionResponse(BaseModel):
    tx_id: str
    sector: str
    tx_type: str
    amount: float
    price: float
    total_value: float
    fee: float
    from_entity: str
    to_entity: str
    risk_score: float
    intelligence_ids: List[str]
    timestamp: str
    description: str


class EconomicDashboardResponse(BaseModel):
    total_estimated_loss: float
    total_affected_users: int
    active_alerts: int
    market_states: List[Dict]
    sector_flows: List[Dict]
    recent_transactions: List[Dict]
    impacts: List[Dict]
    alerts: List[Dict]
    updated_at: str


class SimulateImpactRequest(BaseModel):
    threat_categories: List[str] = Field(..., min_length=1, max_length=10)
    threat_level: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    intelligence_ids: List[str] = Field(default_factory=list, max_length=20)
    content_summary: str = Field(default="", max_length=1000)

    @field_validator("threat_categories")
    @classmethod
    def validate_categories(cls, v):
        valid = {"fraud", "gambling", "hacking", "money_laundering", "data_theft", "phishing", "ransomware", "drug", "other"}
        for cat in v:
            if cat not in valid:
                raise ValueError(f"Invalid threat_category: {cat}. Must be one of {valid}")
        return v


class CreateTransactionRequest(BaseModel):
    sector: str = Field(..., pattern="^(fraud|gambling|phishing|money_laundering|account_trading|tool_sales|data_broker|ransomware|ddos_service|phishing_kit)$")
    tx_type: str = Field(..., pattern="^(buy|sell|transfer|payment|fee)$")
    amount: float = Field(..., ge=0, le=1e9)
    price: float = Field(..., ge=0, le=1e9)
    from_entity: str = Field(default="", max_length=128)
    to_entity: str = Field(default="", max_length=128)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    intelligence_ids: List[str] = Field(default_factory=list, max_length=20)
    description: str = Field(default="", max_length=1000)


class EconomicSummaryResponse(BaseModel):
    total_estimated_loss: float
    total_affected_users: int
    active_alerts: int
    total_transactions: int
    total_impacts: int
    top_risk_sectors: List[Dict]
    sector_count: int
