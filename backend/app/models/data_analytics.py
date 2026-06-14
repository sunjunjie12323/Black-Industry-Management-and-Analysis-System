from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum


class ChartType(str, Enum):
    LINE = "line"
    BAR = "bar"
    PIE = "pie"
    SCATTER = "scatter"
    HEATMAP = "heatmap"
    TREEMAP = "treemap"
    RADAR = "radar"
    FUNNEL = "funnel"
    AREA = "area"
    TABLE = "table"


class QueryType(str, Enum):
    NL_QUERY = "nl_query"
    CHART_RECOMMEND = "chart_recommend"
    ANOMALY_DETECT = "anomaly_detect"
    TREND_PREDICT = "trend_predict"
    DASHBOARD_CONFIG = "dashboard_config"


@dataclass
class AnalyticsQuery:
    query_id: str
    query_type: QueryType
    query_text: str
    context: Optional[Dict[str, Any]] = None
    industry: Optional[str] = None
    created_at: Optional[datetime] = None
    created_by: str = "system"

    def to_dict(self) -> Dict:
        return {
            "query_id": self.query_id,
            "query_type": self.query_type.value if isinstance(self.query_type, QueryType) else self.query_type,
            "query_text": self.query_text,
            "context": self.context,
            "industry": self.industry,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "created_by": self.created_by,
        }


@dataclass
class AnalyticsResult:
    result_id: str
    query_type: QueryType
    query_text: str
    result_data: Dict[str, Any] = field(default_factory=dict)
    chart_config: Dict[str, Any] = field(default_factory=dict)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    prediction: Dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0
    created_at: Optional[datetime] = None
    created_by: str = "system"

    def to_dict(self) -> Dict:
        return {
            "result_id": self.result_id,
            "query_type": self.query_type.value if isinstance(self.query_type, QueryType) else self.query_type,
            "query_text": self.query_text,
            "result_data": self.result_data,
            "chart_config": self.chart_config,
            "anomalies": self.anomalies,
            "prediction": self.prediction,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "created_by": self.created_by,
        }


@dataclass
class DashboardConfig:
    config_id: str
    name: str
    description: Optional[str] = None
    layout: Dict[str, Any] = field(default_factory=dict)
    widgets: List[Dict[str, Any]] = field(default_factory=list)
    industry: Optional[str] = None
    refresh_interval: int = 300
    is_active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: str = "system"

    def to_dict(self) -> Dict:
        return {
            "config_id": self.config_id,
            "name": self.name,
            "description": self.description,
            "layout": self.layout,
            "widgets": self.widgets,
            "industry": self.industry,
            "refresh_interval": self.refresh_interval,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by": self.created_by,
        }


@dataclass
class AnomalyRecord:
    record_id: str
    metric: str
    anomaly_type: str
    severity: str = "medium"
    value: float = 0.0
    expected_value: float = 0.0
    deviation: float = 0.0
    context: Dict[str, Any] = field(default_factory=dict)
    detected_at: Optional[datetime] = None
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "record_id": self.record_id,
            "metric": self.metric,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "value": self.value,
            "expected_value": self.expected_value,
            "deviation": round(self.deviation, 4),
            "context": self.context,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "acknowledged": self.acknowledged,
            "acknowledged_by": self.acknowledged_by,
        }
