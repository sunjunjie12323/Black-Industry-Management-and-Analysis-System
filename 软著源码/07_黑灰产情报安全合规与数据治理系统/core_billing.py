import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


class PlanName(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class ResourceType(str, Enum):
    API_CALL = "api_call"
    INTELLIGENCE = "intelligence"
    STORAGE = "storage"
    LLM_TOKEN = "llm_token"
    USER = "user"


@dataclass
class PricingPlan:
    name: str
    display_name: str
    price_cny: int
    limits: Dict[str, Any]
    features: List[str]

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "price_cny": self.price_cny,
            "price_display": f"¥{self.price_cny:,}/月",
            "limits": self.limits,
            "features": self.features,
        }


PLANS: Dict[str, PricingPlan] = {
    PlanName.FREE: PricingPlan(
        name="free",
        display_name="免费版",
        price_cny=0,
        limits={
            "api_calls_per_day": 100,
            "intelligence_per_day": 100,
            "storage_gb": 1,
            "llm_tokens_per_day": 10000,
            "max_users": 1,
        },
        features=["基础情报查询", "规则NER提取", "基础报告"],
    ),
    PlanName.PRO: PricingPlan(
        name="pro",
        display_name="专业版",
        price_cny=29800,
        limits={
            "api_calls_per_day": 5000,
            "intelligence_per_day": 5000,
            "storage_gb": 100,
            "llm_tokens_per_day": 500000,
            "max_users": 10,
        },
        features=[
            "专业情报分析", "LLM增强NER", "STIX导出",
            "知识图谱", "攻击链预测", "定时报告",
            "优先技术支持",
        ],
    ),
    PlanName.ENTERPRISE: PricingPlan(
        name="enterprise",
        display_name="企业版",
        price_cny=98000,
        limits={
            "api_calls_per_day": -1,
            "intelligence_per_day": -1,
            "storage_gb": -1,
            "llm_tokens_per_day": -1,
            "max_users": -1,
        },
        features=[
            "无限API调用", "TAXII数据交换", "SIEM集成",
            "专属部署", "定制模型微调", "主动学习",
            "SLA保障99.9%", "专属客户经理", "7x24技术支持",
        ],
    ),
}


@dataclass
class SLAReport:
    report_id: str
    start_date: str
    end_date: str
    availability_pct: float
    api_response_time_p95: float
    search_response_time_p95: float
    report_generation_time_p95: float
    data_freshness_delay_minutes: float
    alert_delay_seconds: float
    compliance: Dict[str, bool]
    violations: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "report_id": self.report_id,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "availability_pct": round(self.availability_pct, 4),
            "api_response_time_p95": round(self.api_response_time_p95, 2),
            "search_response_time_p95": round(self.search_response_time_p95, 2),
            "report_generation_time_p95": round(self.report_generation_time_p95, 2),
            "data_freshness_delay_minutes": round(self.data_freshness_delay_minutes, 2),
            "alert_delay_seconds": round(self.alert_delay_seconds, 2),
            "compliance": self.compliance,
            "violations": self.violations,
        }


@dataclass
class UsageRecord:
    tenant_id: str
    resource_type: str
    amount: float
    timestamp: datetime
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "tenant_id": self.tenant_id,
            "resource_type": self.resource_type,
            "amount": self.amount,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class Bill:
    bill_id: str
    tenant_id: str
    period: str
    plan_name: str
    base_cost: float
    usage_costs: Dict[str, float]
    total_cost: float
    currency: str = "CNY"

    def to_dict(self) -> Dict:
        return {
            "bill_id": self.bill_id,
            "tenant_id": self.tenant_id,
            "period": self.period,
            "plan_name": self.plan_name,
            "base_cost": round(self.base_cost, 2),
            "usage_costs": {k: round(v, 2) for k, v in self.usage_costs.items()},
            "total_cost": round(self.total_cost, 2),
            "currency": self.currency,
        }


@dataclass
class UsageSummary:
    tenant_id: str
    period: str
    usage: Dict[str, float]
    limits: Dict[str, Any]
    overage: Dict[str, float]

    def to_dict(self) -> Dict:
        return {
            "tenant_id": self.tenant_id,
            "period": self.period,
            "usage": {k: round(v, 2) for k, v in self.usage.items()},
            "limits": self.limits,
            "overage": {k: round(v, 2) for k, v in self.overage.items()},
        }


OVERAGE_PRICING = {
    ResourceType.API_CALL: 0.01,
    ResourceType.INTELLIGENCE: 0.05,
    ResourceType.STORAGE: 2.0,
    ResourceType.LLM_TOKEN: 0.00002,
    ResourceType.USER: 100.0,
}


class SLADefinition:
    AVAILABILITY_TARGET = 99.9
    API_RESPONSE_TIME_S = 2.0
    SEARCH_RESPONSE_TIME_S = 5.0
    REPORT_GENERATION_TIME_S = 30.0
    DATA_FRESHNESS_DELAY_MIN = 60.0
    ALERT_DELAY_S = 300.0

    def check_sla_compliance(
        self,
        start_date: str,
        end_date: str,
        metrics: Optional[Dict] = None,
    ) -> SLAReport:
        if metrics is None:
            metrics = {
                "availability_pct": 99.95,
                "api_response_time_p95": 1.2,
                "search_response_time_p95": 3.5,
                "report_generation_time_p95": 18.0,
                "data_freshness_delay_minutes": 30.0,
                "alert_delay_seconds": 120.0,
            }

        compliance = {
            "availability": metrics.get("availability_pct", 0) >= self.AVAILABILITY_TARGET,
            "api_response_time": metrics.get("api_response_time_p95", 0) <= self.API_RESPONSE_TIME_S,
            "search_response_time": metrics.get("search_response_time_p95", 0) <= self.SEARCH_RESPONSE_TIME_S,
            "report_generation_time": metrics.get("report_generation_time_p95", 0) <= self.REPORT_GENERATION_TIME_S,
            "data_freshness": metrics.get("data_freshness_delay_minutes", 0) <= self.DATA_FRESHNESS_DELAY_MIN,
            "alert_delay": metrics.get("alert_delay_seconds", 0) <= self.ALERT_DELAY_S,
        }

        violations = []
        if not compliance["availability"]:
            violations.append({
                "metric": "availability",
                "target": f"{self.AVAILABILITY_TARGET}%",
                "actual": f"{metrics.get('availability_pct', 0):.3f}%",
            })
        if not compliance["api_response_time"]:
            violations.append({
                "metric": "api_response_time",
                "target": f"<{self.API_RESPONSE_TIME_S}s",
                "actual": f"{metrics.get('api_response_time_p95', 0):.2f}s",
            })
        if not compliance["search_response_time"]:
            violations.append({
                "metric": "search_response_time",
                "target": f"<{self.SEARCH_RESPONSE_TIME_S}s",
                "actual": f"{metrics.get('search_response_time_p95', 0):.2f}s",
            })
        if not compliance["report_generation_time"]:
            violations.append({
                "metric": "report_generation_time",
                "target": f"<{self.REPORT_GENERATION_TIME_S}s",
                "actual": f"{metrics.get('report_generation_time_p95', 0):.2f}s",
            })
        if not compliance["data_freshness"]:
            violations.append({
                "metric": "data_freshness",
                "target": f"<{self.DATA_FRESHNESS_DELAY_MIN}min",
                "actual": f"{metrics.get('data_freshness_delay_minutes', 0):.1f}min",
            })
        if not compliance["alert_delay"]:
            violations.append({
                "metric": "alert_delay",
                "target": f"<{self.ALERT_DELAY_S}s",
                "actual": f"{metrics.get('alert_delay_seconds', 0):.1f}s",
            })

        return SLAReport(
            report_id=uuid.uuid4().hex[:12],
            start_date=start_date,
            end_date=end_date,
            availability_pct=metrics.get("availability_pct", 0),
            api_response_time_p95=metrics.get("api_response_time_p95", 0),
            search_response_time_p95=metrics.get("search_response_time_p95", 0),
            report_generation_time_p95=metrics.get("report_generation_time_p95", 0),
            data_freshness_delay_minutes=metrics.get("data_freshness_delay_minutes", 0),
            alert_delay_seconds=metrics.get("alert_delay_seconds", 0),
            compliance=compliance,
            violations=violations,
        )


class BillingEngine:
    def __init__(self):
        self._usage_records: Dict[str, List[UsageRecord]] = {}
        self._tenant_plans: Dict[str, str] = {}
        self._max_records_per_tenant = 1000
        self._max_tenants = 100

    def set_tenant_plan(self, tenant_id: str, plan_name: str):
        if plan_name not in PLANS:
            raise ValueError(f"Unknown plan: {plan_name}")
        self._tenant_plans[tenant_id] = plan_name
        if len(self._tenant_plans) > self._max_tenants:
            oldest_key = next(iter(self._tenant_plans))
            del self._tenant_plans[oldest_key]
        logger.info(f"Tenant {tenant_id} set to plan {plan_name}")

    def record_usage(
        self,
        tenant_id: str,
        resource_type: str,
        amount: float,
        metadata: Optional[Dict] = None,
    ):
        record = UsageRecord(
            tenant_id=tenant_id,
            resource_type=resource_type,
            amount=amount,
            timestamp=datetime.now(timezone.utc),
            metadata=metadata or {},
        )
        if tenant_id not in self._usage_records:
            self._usage_records[tenant_id] = []
        self._usage_records[tenant_id].append(record)
        if len(self._usage_records[tenant_id]) > self._max_records_per_tenant:
            self._usage_records[tenant_id] = self._usage_records[tenant_id][-self._max_records_per_tenant:]

    def calculate_bill(self, tenant_id: str, period: str) -> Optional[Bill]:
        plan_name = self._tenant_plans.get(tenant_id, "free")
        plan = PLANS.get(plan_name, PLANS["free"])

        usage = self._aggregate_usage(tenant_id, period)
        overage = self._calculate_overage(tenant_id, plan, usage)

        usage_costs = {}
        for resource_type, overage_amount in overage.items():
            unit_price = OVERAGE_PRICING.get(ResourceType(resource_type), 0)
            usage_costs[resource_type] = overage_amount * unit_price

        total_cost = plan.price_cny + sum(usage_costs.values())

        return Bill(
            bill_id=uuid.uuid4().hex[:12],
            tenant_id=tenant_id,
            period=period,
            plan_name=plan_name,
            base_cost=plan.price_cny,
            usage_costs=usage_costs,
            total_cost=total_cost,
        )

    def get_usage_summary(self, tenant_id: str, period: str) -> UsageSummary:
        plan_name = self._tenant_plans.get(tenant_id, "free")
        plan = PLANS.get(plan_name, PLANS["free"])

        usage = self._aggregate_usage(tenant_id, period)
        overage = self._calculate_overage(tenant_id, plan, usage)

        return UsageSummary(
            tenant_id=tenant_id,
            period=period,
            usage=usage,
            limits=plan.limits,
            overage=overage,
        )

    def _aggregate_usage(self, tenant_id: str, period: str) -> Dict[str, float]:
        usage: Dict[str, float] = defaultdict(float)
        for record in self._usage_records.get(tenant_id, []):
            record_period = record.timestamp.strftime("%Y-%m")
            if record_period == period:
                usage[record.resource_type] += record.amount
        return dict(usage)

    def _calculate_overage(
        self,
        tenant_id: str,
        plan: PricingPlan,
        usage: Dict[str, float],
    ) -> Dict[str, float]:
        overage: Dict[str, float] = {}
        limit_mapping = {
            ResourceType.API_CALL: "api_calls_per_day",
            ResourceType.INTELLIGENCE: "intelligence_per_day",
            ResourceType.STORAGE: "storage_gb",
            ResourceType.LLM_TOKEN: "llm_tokens_per_day",
            ResourceType.USER: "max_users",
        }

        for resource_type, limit_key in limit_mapping.items():
            limit = plan.limits.get(limit_key, -1)
            if limit == -1:
                continue
            actual = usage.get(resource_type, 0)
            if actual > limit:
                overage[resource_type] = actual - limit

        return overage

    def get_tenant_plan(self, tenant_id: str) -> str:
        return self._tenant_plans.get(tenant_id, "free")


def get_plan(plan_name: str) -> Optional[PricingPlan]:
    return PLANS.get(plan_name)


def compare_plans() -> List[Dict]:
    return [plan.to_dict() for plan in PLANS.values()]
