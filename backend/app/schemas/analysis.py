import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class AnalysisResultCreate(BaseModel):
    model_config = {"protected_namespaces": ()}
    analysis_type: str = Field(..., pattern=r"^[a-z_]+$", max_length=32)
    target_id: str = Field("", max_length=64)
    target_type: str = Field("intelligence", max_length=32)
    result_summary: str = ""
    findings: List[Any] = Field(default_factory=list)
    iocs: List[Any] = Field(default_factory=list)
    recommendations: List[Any] = Field(default_factory=list)
    result_data: Dict[str, Any] = Field(default_factory=dict)
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    status: str = "completed"
    error_message: Optional[str] = None
    llm_tokens_used: int = 0
    model_name: str = "deepseek-chat"
    input_content: str = ""


class AnalysisResultResponse(BaseModel):
    model_config = {"from_attributes": True, "protected_namespaces": ()}
    id: str
    analysis_type: str
    target_id: str
    target_type: str
    result_summary: str
    findings: List[Any] = Field(default_factory=list)
    iocs: List[Any] = Field(default_factory=list)
    recommendations: List[Any] = Field(default_factory=list)
    result_data: Dict[str, Any] = Field(default_factory=dict)
    confidence_score: float
    status: str
    error_message: Optional[str] = None
    llm_tokens_used: int
    input_content: str = ""
    model_name: str
    analyzed_at: datetime
    created_at: datetime


class AnalysisResultListResponse(BaseModel):
    items: List[AnalysisResultResponse]
    total: int
    limit: int
    offset: int


class AnalysisStatsResponse(BaseModel):
    total_count: int = 0
    by_type: Dict[str, int] = Field(default_factory=dict)
    by_status: Dict[str, int] = Field(default_factory=dict)
    avg_confidence: float = 0.0
    scheduler_status: Optional[Dict[str, Any]] = None


class AnalysisTypeStatsResponse(BaseModel):
    analysis_type: str
    total_count: int = 0
    detection_count: int = 0
    avg_confidence: float = 0.0
    trend_data: List[Dict[str, Any]] = Field(default_factory=list)
    last_analyzed_at: Optional[datetime] = None


class DeepAnalysisRequest(BaseModel):
    target_identifier: str = Field(..., min_length=1)
    target_type: str = Field("intelligence", max_length=32)
    analysis_depth: str = Field("standard", pattern=r"^(quick|standard|deep)$")
    include_web_search: bool = True
    search_keywords: List[str] = Field(default_factory=list)


class DeepAnalysisResponse(BaseModel):
    result_id: str = ""
    threat_assessment: str = ""
    related_threats: List[Dict[str, Any]] = Field(default_factory=list)
    risk_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    data_sources_used: List[str] = Field(default_factory=list)


class TriggerAnalysisRequest(BaseModel):
    analysis_type: Optional[str] = None
    target_id: Optional[str] = None
    deep_analysis: Optional[DeepAnalysisRequest] = None


class TriggerAnalysisResponse(BaseModel):
    task_id: str
    status: str
    message: str


class SchedulerStatusResponse(BaseModel):
    is_running: bool = False
    last_run_time: Optional[datetime] = None
    next_run_time: Optional[datetime] = None
    total_runs: int = 0
    last_run_duration_seconds: Optional[float] = None
    last_run_items_processed: int = 0
    enabled_analysis_types: List[str] = Field(default_factory=list)
    schedule_interval_hours: float = 6.0
