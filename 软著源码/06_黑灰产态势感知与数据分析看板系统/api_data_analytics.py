import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.analytics_engine import AnalyticsEngine
from app.core.auth import User, get_current_user
from app.core.db_utils import db_write
from app.db.database import get_db
from app.db.tables import AnalyticsResultTable, DashboardConfigTable, AnomalyRecordTable, RawIntelligenceTable
from app.models.data_analytics import AnalyticsQuery, AnalyticsResult, ChartType

router = APIRouter(prefix="/data-analytics", tags=["数据分析看板"])


class NLQueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000)
    context: Optional[Dict[str, Any]] = None
    industry: Optional[str] = None


class ChartRecommendRequest(BaseModel):
    data: List[Dict[str, Any]] = Field(default_factory=list)
    analysis_type: Optional[str] = None
    industry: Optional[str] = None


class AnomalyDetectRequest(BaseModel):
    data: List[Dict[str, Any]] = Field(default_factory=list)
    metric_field: str = "value"
    timestamp_field: str = "timestamp"
    sensitivity: float = Field(1.5, ge=0.5, le=5.0)


class TrendPredictRequest(BaseModel):
    data: List[Dict[str, Any]] = Field(default_factory=list)
    metric_field: str = "value"
    timestamp_field: str = "timestamp"
    periods: int = Field(7, ge=1, le=90)
    method: str = Field("auto", pattern=r"^(auto|arima|exponential_smoothing|linear|prophet)$")


class DashboardConfigRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    description: Optional[str] = None
    layout: Dict[str, Any] = Field(default_factory=dict)
    widgets: List[Dict[str, Any]] = Field(default_factory=list)
    industry: Optional[str] = None
    refresh_interval: int = Field(300, ge=30, le=3600)


class ExportRequest(BaseModel):
    format: str = Field("json", pattern=r"^(json|csv|excel)$")
    result_ids: List[str] = Field(default_factory=list)
    include_charts: bool = True


class NLQueryV2Request(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000)
    context: Optional[Dict[str, Any]] = None
    industry: Optional[str] = None


class ChartConfigRequest(BaseModel):
    chart_type: str = Field(..., min_length=1)
    data: List[Dict[str, Any]] = Field(default_factory=list)
    query: str = Field(..., min_length=1)
    industry: Optional[str] = None


class TimeSeriesAnomalyRequest(BaseModel):
    data: List[Dict[str, Any]] = Field(default_factory=list)
    metric_field: str = "value"
    timestamp_field: str = "timestamp"
    window_size: int = Field(7, ge=3, le=30)


class ForecastArimaRequest(BaseModel):
    data: List[Dict[str, Any]] = Field(default_factory=list)
    metric_field: str = "value"
    timestamp_field: str = "timestamp"
    periods: int = Field(7, ge=1, le=90)


class ForecastAccuracyRequest(BaseModel):
    actual: List[float] = Field(..., min_length=1)
    predicted: List[float] = Field(..., min_length=1)


class AnomalyAckRequest(BaseModel):
    acknowledged_by: str = Field(..., min_length=1)
    note: Optional[str] = None


def _get_analytics_engine(request: Request) -> AnalyticsEngine:
    engine = getattr(request.app.state, "analytics_engine", None)
    if engine is None:
        llm = getattr(request.app.state, "llm", None)
        engine = AnalyticsEngine(llm_service=llm)
        request.app.state.analytics_engine = engine
    return engine


def _result_row_to_dict(row) -> Dict:
    return {
        "id": row.id,
        "query_type": row.query_type,
        "query_text": row.query_text,
        "result_json": row.result_json,
        "chart_config_json": row.chart_config_json,
        "anomalies_json": row.anomalies_json,
        "prediction_json": row.prediction_json,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "created_by": row.created_by,
    }


@router.post("/query")
async def natural_language_query(
    request: Request,
    data: NLQueryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)
    context = dict(data.context) if data.context else {}
    if data.industry:
        context["industry"] = data.industry
    parsed = await engine.parse_natural_language_query(data.query, context=context)

    result_id = uuid.uuid4().hex
    result_json = json.dumps(parsed, ensure_ascii=False, default=str)

    row = AnalyticsResultTable(
        id=result_id,
        query_type="nl_query",
        query_text=data.query,
        result_json=result_json,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="自然语言查询结果保存"):
        db.add(row)
    await db.refresh(row)

    return {
        "result_id": result_id,
        "parsed_query": parsed,
        "query_text": data.query,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.post("/chart-recommend")
async def recommend_chart(
    request: Request,
    data: ChartRecommendRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)
    recommendations = await engine.recommend_charts(data.data, analysis_type=data.analysis_type)

    result_id = uuid.uuid4().hex
    chart_config_json = json.dumps(recommendations, ensure_ascii=False, default=str)

    row = AnalyticsResultTable(
        id=result_id,
        query_type="chart_recommend",
        query_text=f"Chart recommendation for {len(data.data)} data points",
        chart_config_json=chart_config_json,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="图表推荐结果保存"):
        db.add(row)
    await db.refresh(row)

    return {
        "result_id": result_id,
        "recommendations": recommendations,
        "data_points": len(data.data),
    }


@router.post("/anomaly-detect")
async def detect_anomalies(
    request: Request,
    data: AnomalyDetectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)
    if not data.data:
        raise HTTPException(status_code=400, detail="异常检测数据不能为空")
    if len(data.data) < 5:
        raise HTTPException(status_code=400, detail="异常检测至少需要5个数据点")
    anomalies = await engine.detect_anomalies(
        data=data.data,
        metric_field=data.metric_field,
        timestamp_field=data.timestamp_field,
        sensitivity=data.sensitivity,
    )

    result_id = uuid.uuid4().hex
    anomalies_json = json.dumps(anomalies, ensure_ascii=False, default=str)

    row = AnalyticsResultTable(
        id=result_id,
        query_type="anomaly_detect",
        query_text=f"Anomaly detection on {data.metric_field}",
        anomalies_json=anomalies_json,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="异常检测结果保存"):
        db.add(row)
    await db.refresh(row)

    anomaly_count = 0
    if isinstance(anomalies, dict):
        anomaly_count = anomalies.get("anomaly_count", len(anomalies.get("anomalies", [])))
    elif isinstance(anomalies, list):
        anomaly_count = len(anomalies)

    return {
        "result_id": result_id,
        "anomalies": anomalies,
        "total_data_points": len(data.data),
        "anomaly_count": anomaly_count,
    }


@router.post("/trend-predict")
async def predict_trend(
    request: Request,
    data: TrendPredictRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)
    if not data.data:
        raise HTTPException(status_code=400, detail="趋势预测数据不能为空")
    if len(data.data) < 3:
        raise HTTPException(status_code=400, detail="趋势预测至少需要3个数据点")
    prediction = await engine.predict_trend(
        data=data.data,
        metric_field=data.metric_field,
        timestamp_field=data.timestamp_field,
        periods=data.periods,
        method=data.method,
    )

    result_id = uuid.uuid4().hex
    prediction_json = json.dumps(prediction, ensure_ascii=False, default=str)

    row = AnalyticsResultTable(
        id=result_id,
        query_type="trend_predict",
        query_text=f"Trend prediction for {data.metric_field} ({data.periods} periods)",
        prediction_json=prediction_json,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="趋势预测结果保存"):
        db.add(row)
    await db.refresh(row)

    return {
        "result_id": result_id,
        "prediction": prediction,
        "periods": data.periods,
        "method": data.method,
    }


@router.get("/dashboard/stats")
async def get_dashboard_stats(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)
    stats = await engine.get_dashboard_stats()

    return stats


@router.get("/results")
async def list_results(
    query_type: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(AnalyticsResultTable)
    count_stmt = select(func.count()).select_from(AnalyticsResultTable)

    if query_type:
        stmt = stmt.where(AnalyticsResultTable.query_type == query_type)
        count_stmt = count_stmt.where(AnalyticsResultTable.query_type == query_type)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(AnalyticsResultTable.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    return {"items": [_result_row_to_dict(r) for r in rows], "total": total, "offset": offset, "limit": limit}


@router.get("/results/{result_id}")
async def get_result(
    result_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(AnalyticsResultTable).where(AnalyticsResultTable.id == result_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="分析结果不存在")
    return _result_row_to_dict(row)


@router.post("/export")
async def export_results(
    data: ExportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not data.result_ids:
        raise HTTPException(status_code=400, detail="请指定要导出的结果ID")

    try:
        stmt = select(AnalyticsResultTable).where(AnalyticsResultTable.id.in_(data.result_ids))
        result = await db.execute(stmt)
        rows = result.scalars().all()
    except Exception as e:
        logger.error(f"Failed to query export results: {e}")
        raise HTTPException(status_code=500, detail="查询导出结果失败，请稍后重试")

    if not rows:
        raise HTTPException(status_code=404, detail="未找到指定的分析结果")

    export_data = []
    for row in rows:
        item = {
            "id": row.id,
            "query_type": row.query_type,
            "query_text": row.query_text,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        if row.result_json:
            try:
                item["result"] = json.loads(row.result_json)
            except (json.JSONDecodeError, TypeError):
                item["result"] = row.result_json
        if data.include_charts and row.chart_config_json:
            try:
                item["chart_config"] = json.loads(row.chart_config_json)
            except (json.JSONDecodeError, TypeError):
                item["chart_config"] = row.chart_config_json
        export_data.append(item)

    if data.format == "csv":
        import io
        import csv
        output = io.StringIO()
        if export_data:
            fieldnames = list(export_data[0].keys())
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for item in export_data:
                flat = {k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v for k, v in item.items()}
                writer.writerow(flat)
        return {"format": "csv", "data": output.getvalue(), "count": len(export_data)}

    return {"format": data.format, "data": export_data, "count": len(export_data)}


@router.post("/dashboard/config", status_code=201)
async def create_dashboard_config(
    data: DashboardConfigRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    config_id = uuid.uuid4().hex
    created_by = current_user.username if hasattr(current_user, "username") else "system"

    row = DashboardConfigTable(
        id=config_id,
        name=data.name,
        description=data.description,
        layout_json=json.dumps(data.layout, ensure_ascii=False),
        widgets_json=json.dumps(data.widgets, ensure_ascii=False),
        industry=data.industry,
        refresh_interval=data.refresh_interval,
        is_active=True,
        created_by=created_by,
    )
    async with db_write(db, operation="创建看板配置"):
        db.add(row)
    await db.refresh(row)

    return {
        "config_id": config_id,
        "name": data.name,
        "description": data.description,
        "layout": data.layout,
        "widgets": data.widgets,
        "industry": data.industry,
        "refresh_interval": data.refresh_interval,
        "is_active": True,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "created_by": created_by,
    }


@router.get("/dashboard/configs")
async def list_dashboard_configs(
    industry: Optional[str] = None,
    is_active: Optional[bool] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(DashboardConfigTable)
    count_stmt = select(func.count()).select_from(DashboardConfigTable)

    if industry:
        stmt = stmt.where(DashboardConfigTable.industry == industry)
        count_stmt = count_stmt.where(DashboardConfigTable.industry == industry)
    if is_active is not None:
        stmt = stmt.where(DashboardConfigTable.is_active == is_active)
        count_stmt = count_stmt.where(DashboardConfigTable.is_active == is_active)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(DashboardConfigTable.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    items = []
    for row in rows:
        items.append({
            "config_id": row.id,
            "name": row.name,
            "description": row.description,
            "layout": json.loads(row.layout_json) if row.layout_json else {},
            "widgets": json.loads(row.widgets_json) if row.widgets_json else [],
            "industry": row.industry,
            "refresh_interval": row.refresh_interval,
            "is_active": row.is_active,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            "created_by": row.created_by,
        })

    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.put("/dashboard/config/{config_id}")
async def update_dashboard_config(
    config_id: str,
    data: DashboardConfigRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(DashboardConfigTable).where(DashboardConfigTable.id == config_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="看板配置不存在")

    async with db_write(db, operation="更新看板配置"):
        row.name = data.name
        row.description = data.description
        row.layout_json = json.dumps(data.layout, ensure_ascii=False)
        row.widgets_json = json.dumps(data.widgets, ensure_ascii=False)
        row.industry = data.industry
        row.refresh_interval = data.refresh_interval
    await db.refresh(row)

    return {
        "config_id": row.id,
        "name": row.name,
        "description": row.description,
        "layout": json.loads(row.layout_json) if row.layout_json else {},
        "widgets": json.loads(row.widgets_json) if row.widgets_json else [],
        "industry": row.industry,
        "refresh_interval": row.refresh_interval,
        "is_active": row.is_active,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.delete("/dashboard/config/{config_id}")
async def delete_dashboard_config(
    config_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(DashboardConfigTable).where(DashboardConfigTable.id == config_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="看板配置不存在")

    async with db_write(db, operation="停用看板配置"):
        row.is_active = False
    return {"message": "看板配置已停用", "config_id": config_id}


@router.get("/chart-types")
async def list_chart_types(
    current_user: User = Depends(get_current_user),
):
    chart_types = [
        {"value": "line", "label": "折线图", "description": "展示数据随时间变化的趋势", "best_for": ["时序数据", "趋势分析"]},
        {"value": "bar", "label": "柱状图", "description": "对比不同类别的数据量", "best_for": ["分类对比", "排名"]},
        {"value": "pie", "label": "饼图", "description": "展示各部分占总体的比例", "best_for": ["占比分析", "分布"]},
        {"value": "scatter", "label": "散点图", "description": "展示两个变量之间的关系", "best_for": ["相关性", "分布"]},
        {"value": "heatmap", "label": "热力图", "description": "展示数据的密度和强度分布", "best_for": ["密度分析", "时间分布"]},
        {"value": "treemap", "label": "树图", "description": "展示层级数据的占比关系", "best_for": ["层级结构", "占比"]},
        {"value": "radar", "label": "雷达图", "description": "多维度数据对比", "best_for": ["多维评估", "能力画像"]},
        {"value": "funnel", "label": "漏斗图", "description": "展示流程中的转化率", "best_for": ["转化分析", "流程"]},
    ]
    return {"chart_types": chart_types, "total": len(chart_types)}


@router.get("/anomaly-rules")
async def list_anomaly_rules(
    current_user: User = Depends(get_current_user),
):
    rules = [
        {"id": "zscore", "name": "Z-Score异常检测", "description": "基于标准差的统计异常检测", "sensitivity_range": [1.0, 5.0], "default_sensitivity": 1.5},
        {"id": "iqr", "name": "IQR异常检测", "description": "基于四分位距的异常检测", "sensitivity_range": [0.5, 3.0], "default_sensitivity": 1.5},
        {"id": "isolation_forest", "name": "隔离森林", "description": "基于集成学习的异常检测", "sensitivity_range": [0.01, 0.5], "default_sensitivity": 0.1},
        {"id": "dbscan", "name": "DBSCAN聚类", "description": "基于密度的聚类异常检测", "sensitivity_range": [0.1, 2.0], "default_sensitivity": 0.5},
    ]
    return {"rules": rules, "total": len(rules)}


@router.get("/prediction-methods")
async def list_prediction_methods(
    current_user: User = Depends(get_current_user),
):
    methods = [
        {"id": "auto", "name": "自动选择", "description": "系统自动选择最佳预测方法", "min_data_points": 5},
        {"id": "arima", "name": "ARIMA", "description": "自回归积分滑动平均模型", "min_data_points": 20},
        {"id": "exponential_smoothing", "name": "指数平滑", "description": "加权指数平滑预测", "min_data_points": 5},
        {"id": "linear", "name": "线性回归", "description": "线性趋势拟合", "min_data_points": 3},
        {"id": "prophet", "name": "Prophet", "description": "Facebook Prophet时间序列预测", "min_data_points": 30},
    ]
    return {"methods": methods, "total": len(methods)}


@router.post("/anomalies/{record_id}/acknowledge")
async def acknowledge_anomaly(
    record_id: str,
    data: AnomalyAckRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(AnomalyRecordTable).where(AnomalyRecordTable.id == record_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="异常记录不存在")

    async with db_write(db, operation="确认异常记录"):
        row.acknowledged = True
        row.acknowledged_by = data.acknowledged_by
    await db.refresh(row)

    return {
        "id": row.id,
        "metric": row.metric,
        "anomaly_type": row.anomaly_type,
        "severity": row.severity,
        "value": row.value,
        "expected_value": row.expected_value,
        "deviation": row.deviation,
        "context": json.loads(row.context_json) if row.context_json else None,
        "detected_at": row.detected_at.isoformat() if row.detected_at else None,
        "acknowledged": row.acknowledged,
        "acknowledged_by": row.acknowledged_by,
    }


@router.get("/anomalies")
async def list_anomalies(
    metric: Optional[str] = None,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(AnomalyRecordTable)
    count_stmt = select(func.count()).select_from(AnomalyRecordTable)

    if metric:
        stmt = stmt.where(AnomalyRecordTable.metric == metric)
        count_stmt = count_stmt.where(AnomalyRecordTable.metric == metric)
    if severity:
        stmt = stmt.where(AnomalyRecordTable.severity == severity)
        count_stmt = count_stmt.where(AnomalyRecordTable.severity == severity)
    if acknowledged is not None:
        stmt = stmt.where(AnomalyRecordTable.acknowledged == acknowledged)
        count_stmt = count_stmt.where(AnomalyRecordTable.acknowledged == acknowledged)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(AnomalyRecordTable.detected_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    items = []
    for row in rows:
        items.append({
            "id": row.id,
            "metric": row.metric,
            "anomaly_type": row.anomaly_type,
            "severity": row.severity,
            "value": row.value,
            "expected_value": row.expected_value,
            "deviation": row.deviation,
            "context": json.loads(row.context_json) if row.context_json else None,
            "detected_at": row.detected_at.isoformat() if row.detected_at else None,
            "acknowledged": row.acknowledged,
            "acknowledged_by": row.acknowledged_by,
        })

    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.get("/dashboard/realtime")
async def get_realtime_stats(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    active_users = 0
    requests_per_minute = 0.0

    perf_monitor = getattr(request.app.state, "performance_monitor", None)
    if perf_monitor is not None:
        try:
            summary = perf_monitor.get_summary()
            active_users = summary.get("active_requests", 0)
            global_qps = summary.get("global_qps", 0.0)
            requests_per_minute = round(global_qps * 60, 2)
        except Exception as e:
            logger.warning(f"Failed to get performance monitor summary: {e}")

    recent_anomalies_count = 0
    try:
        cutoff = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        anomaly_count_result = await db.execute(
            select(func.count()).select_from(AnomalyRecordTable).where(
                AnomalyRecordTable.detected_at >= cutoff
            )
        )
        recent_anomalies_count = anomaly_count_result.scalar() or 0
    except Exception as exc:
        logger.warning(f"Failed to query recent anomalies count: {exc}")

    latest_intelligence_count = 0
    try:
        intel_count_result = await db.execute(
            select(func.count()).select_from(RawIntelligenceTable)
        )
        latest_intelligence_count = intel_count_result.scalar() or 0
    except Exception as exc:
        logger.warning(f"Failed to query latest intelligence count: {exc}")

    return {
        "active_users": active_users,
        "requests_per_minute": requests_per_minute,
        "recent_anomalies_count": recent_anomalies_count,
        "latest_intelligence_count": latest_intelligence_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/dashboard/presets")
async def get_dashboard_presets(
    industry: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    presets = {
        "threat_intel_overview": {
            "industry": "threat_intel_overview",
            "label": "黑灰产情报总览",
            "widgets": [
                {"type": "line", "title": "黑灰产活动趋势", "metric": "threat_activity_trend", "span": 6},
                {"type": "bar", "title": "威胁类型分布", "metric": "threat_type_distribution", "span": 3},
                {"type": "pie", "title": "高危预警等级分布", "metric": "alert_level_distribution", "span": 3},
                {"type": "heatmap", "title": "攻击来源地域分布", "metric": "attack_source_region", "span": 4},
                {"type": "line", "title": "IoC指标增长趋势", "metric": "ioc_growth_trend", "span": 4},
                {"type": "bar", "title": "黑话术语活跃度", "metric": "blacktalk_activity", "span": 4},
            ],
        },
        "manufacturing": {
            "industry": "manufacturing",
            "label": "智能制造",
            "widgets": [
                {"type": "line", "title": "供应链攻击趋势", "metric": "supply_chain_threats", "span": 6},
                {"type": "bar", "title": "工业间谍活动统计", "metric": "industrial_espionage_count", "span": 3},
                {"type": "pie", "title": "威胁类型分布", "metric": "threat_type_distribution", "span": 3},
                {"type": "heatmap", "title": "攻击来源地域分布", "metric": "attack_source_region", "span": 4},
                {"type": "line", "title": "设备篡改检测趋势", "metric": "device_tampering_trend", "span": 4},
                {"type": "bar", "title": "知识产权窃取事件", "metric": "ip_theft_incidents", "span": 4},
            ],
        },
        "education": {
            "industry": "education",
            "label": "智慧教育",
            "widgets": [
                {"type": "line", "title": "作弊产业链活动趋势", "metric": "cheating_chain_trend", "span": 6},
                {"type": "bar", "title": "论文代写黑产统计", "metric": "ghostwriting_count", "span": 3},
                {"type": "pie", "title": "教育黑灰产类型分布", "metric": "education_threat_distribution", "span": 3},
                {"type": "heatmap", "title": "题库泄露来源分布", "metric": "exam_leak_source", "span": 4},
                {"type": "line", "title": "学历造假趋势", "metric": "degree_forgery_trend", "span": 4},
                {"type": "bar", "title": "钓鱼攻击统计", "metric": "phishing_attack_count", "span": 4},
            ],
        },
        "healthcare": {
            "industry": "healthcare",
            "label": "医疗健康",
            "widgets": [
                {"type": "line", "title": "假药流通趋势", "metric": "counterfeit_drug_trend", "span": 6},
                {"type": "bar", "title": "医保欺诈统计", "metric": "insurance_fraud_count", "span": 3},
                {"type": "pie", "title": "医疗黑灰产类型分布", "metric": "healthcare_threat_distribution", "span": 3},
                {"type": "heatmap", "title": "医疗数据交易地域分布", "metric": "medical_data_trafficking_region", "span": 4},
                {"type": "line", "title": "勒索软件攻击趋势", "metric": "ransomware_attack_trend", "span": 4},
                {"type": "bar", "title": "处方药非法销售统计", "metric": "illegal_drug_sales_count", "span": 4},
            ],
        },
        "finance": {
            "industry": "finance",
            "label": "金融服务",
            "widgets": [
                {"type": "line", "title": "电信诈骗趋势", "metric": "telecom_fraud_trend", "span": 6},
                {"type": "bar", "title": "洗钱风险统计", "metric": "money_laundering_risk_count", "span": 3},
                {"type": "pie", "title": "金融黑灰产类型分布", "metric": "finance_threat_distribution", "span": 3},
                {"type": "heatmap", "title": "异常交易地域分布", "metric": "abnormal_transaction_region", "span": 4},
                {"type": "line", "title": "跑分平台活跃度趋势", "metric": "relay_fraud_trend", "span": 4},
                {"type": "bar", "title": "非法集资事件统计", "metric": "illegal_fundraising_count", "span": 4},
            ],
        },
    }

    if industry:
        preset = presets.get(industry)
        if not preset:
            raise HTTPException(status_code=404, detail=f"未找到行业'{industry}'的看板预设")
        return {"preset": preset}

    return {"presets": presets, "total": len(presets)}


@router.post("/query-v2")
async def natural_language_query_v2(
    request: Request,
    data: NLQueryV2Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)
    llm = getattr(request.app.state, "llm", None)

    query_text = data.query
    if data.industry:
        industry_labels = {
            "threat_intel_overview": "黑灰产情报总览",
            "manufacturing": "智能制造", "education": "智慧教育", "healthcare": "医疗健康", "finance": "金融服务",
        }
        label = industry_labels.get(data.industry, data.industry)
        query_text = f"[{label}行业上下文] {data.query}"

    result = await engine.parse_query_with_llm(
        query=query_text,
        llm_service=llm,
        db_session=db,
    )

    result_id = uuid.uuid4().hex
    result_json = json.dumps(result.to_dict() if hasattr(result, "to_dict") else result, ensure_ascii=False, default=str)

    row = AnalyticsResultTable(
        id=result_id,
        query_type="nl_query_v2",
        query_text=data.query,
        result_json=result_json,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="自然语言查询V2结果保存"):
        db.add(row)
    await db.refresh(row)

    return {
        "result_id": result_id,
        "result": result.to_dict() if hasattr(result, "to_dict") else result,
        "query_text": data.query,
    }


@router.post("/chart-config")
async def generate_chart_config(
    request: Request,
    data: ChartConfigRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)

    chart_config = engine.generate_chart_config(
        chart_type=data.chart_type,
        data=data.data,
        query=data.query,
        industry=data.industry,
    )

    result_id = uuid.uuid4().hex
    config_json = json.dumps(chart_config, ensure_ascii=False, default=str)

    row = AnalyticsResultTable(
        id=result_id,
        query_type="chart_config",
        query_text=f"Chart config for {data.chart_type}: {data.query[:100]}",
        chart_config_json=config_json,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="图表配置结果保存"):
        db.add(row)
    await db.refresh(row)

    return {
        "result_id": result_id,
        "chart_config": chart_config,
        "chart_type": data.chart_type,
    }


@router.post("/time-series-anomaly")
async def detect_time_series_anomaly(
    request: Request,
    data: TimeSeriesAnomalyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)

    if len(data.data) < 5:
        raise HTTPException(status_code=400, detail="时序异常检测至少需要5个数据点")

    values = []
    timestamps = []
    for item in data.data:
        val = item.get(data.metric_field)
        if val is not None:
            try:
                values.append(float(val))
            except (ValueError, TypeError):
                continue
        ts = item.get(data.timestamp_field, "")
        timestamps.append(str(ts) if ts else "")

    anomaly_result = engine.detect_time_series_anomaly(
        values=values,
        timestamps=timestamps if timestamps else None,
        window_size=data.window_size,
    )

    result_id = uuid.uuid4().hex
    anomalies_json = json.dumps(anomaly_result.to_dict(), ensure_ascii=False, default=str)

    row = AnalyticsResultTable(
        id=result_id,
        query_type="time_series_anomaly",
        query_text=f"Time series anomaly on {data.metric_field}",
        anomalies_json=anomalies_json,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="时序异常检测结果保存"):
        db.add(row)
    await db.refresh(row)

    return {
        "result_id": result_id,
        "anomalies": anomaly_result.to_dict(),
        "algorithm": "time_series",
        "total_points": len(values),
        "anomaly_count": anomaly_result.anomaly_count,
    }


@router.post("/forecast-arima")
async def forecast_arima(
    request: Request,
    data: ForecastArimaRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)

    if len(data.data) < 10:
        raise HTTPException(status_code=400, detail="ARIMA预测至少需要10个数据点")

    values = []
    dates = []
    for item in data.data:
        val = item.get(data.metric_field)
        if val is not None:
            try:
                values.append(float(val))
            except (ValueError, TypeError):
                continue
        ts = item.get(data.timestamp_field, "")
        dates.append(str(ts) if ts else "")

    forecast_result = engine.forecast_trend_sync(
        values=values,
        dates=dates if dates else None,
        forecast_days=data.periods,
        method="arima",
    )

    result_id = uuid.uuid4().hex
    prediction_json = json.dumps(forecast_result.to_dict(), ensure_ascii=False, default=str)

    row = AnalyticsResultTable(
        id=result_id,
        query_type="forecast_arima",
        query_text=f"ARIMA forecast for {data.metric_field} ({data.periods} periods)",
        prediction_json=prediction_json,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="ARIMA预测结果保存"):
        db.add(row)
    await db.refresh(row)

    return {
        "result_id": result_id,
        "prediction": forecast_result.to_dict(),
        "method": "arima",
        "periods": data.periods,
    }


@router.post("/forecast-accuracy")
async def evaluate_forecast_accuracy_endpoint(
    request: Request,
    data: ForecastAccuracyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)

    accuracy = engine.evaluate_forecast_accuracy(
        actual=data.actual,
        predicted=data.predicted,
    )

    return {
        "accuracy": accuracy,
        "data_points": len(data.actual),
    }


@router.get("/statistics")
async def get_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query_counts = {}
    for qt in ["nl_query", "nl_query_v2", "chart_recommend", "chart_config", "anomaly_detect", "time_series_anomaly", "trend_predict", "forecast_arima"]:
        count_result = await db.execute(
            select(func.count()).select_from(AnalyticsResultTable).where(
                AnalyticsResultTable.query_type == qt
            )
        )
        query_counts[qt] = count_result.scalar() or 0

    total_queries_result = await db.execute(
        select(func.count()).select_from(AnalyticsResultTable)
    )
    total_queries = total_queries_result.scalar() or 0

    dashboard_config_count_result = await db.execute(
        select(func.count()).select_from(DashboardConfigTable).where(
            DashboardConfigTable.is_active == True
        )
    )
    dashboard_config_count = dashboard_config_count_result.scalar() or 0

    total_anomaly_result = await db.execute(
        select(func.count()).select_from(AnomalyRecordTable)
    )
    total_anomalies = total_anomaly_result.scalar() or 0

    unack_anomaly_result = await db.execute(
        select(func.count()).select_from(AnomalyRecordTable).where(
            AnomalyRecordTable.acknowledged == False
        )
    )
    unacknowledged_anomalies = unack_anomaly_result.scalar() or 0

    severity_counts = {}
    for sev in ["low", "medium", "high", "critical"]:
        sev_result = await db.execute(
            select(func.count()).select_from(AnomalyRecordTable).where(
                AnomalyRecordTable.severity == sev
            )
        )
        severity_counts[sev] = sev_result.scalar() or 0

    trend_predict_count = query_counts.get("trend_predict", 0)
    forecast_arima_count = query_counts.get("forecast_arima", 0)

    return {
        "query_counts": query_counts,
        "total_queries": total_queries,
        "dashboard_config_count": dashboard_config_count,
        "anomaly_detection": {
            "total": total_anomalies,
            "unacknowledged": unacknowledged_anomalies,
            "by_severity": severity_counts,
        },
        "trend_prediction": {
            "total": trend_predict_count + forecast_arima_count,
            "trend_predict": trend_predict_count,
            "forecast_arima": forecast_arima_count,
        },
    }


@router.get("/dashboard-summary")
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    recent_queries_result = await db.execute(
        select(AnalyticsResultTable)
        .order_by(AnalyticsResultTable.created_at.desc())
        .limit(10)
    )
    recent_queries = [_result_row_to_dict(r) for r in recent_queries_result.scalars().all()]

    recent_anomalies_result = await db.execute(
        select(AnomalyRecordTable)
        .order_by(AnomalyRecordTable.detected_at.desc())
        .limit(10)
    )
    recent_anomalies = []
    for row in recent_anomalies_result.scalars().all():
        recent_anomalies.append({
            "id": row.id,
            "metric": row.metric,
            "anomaly_type": row.anomaly_type,
            "severity": row.severity,
            "value": row.value,
            "expected_value": row.expected_value,
            "deviation": row.deviation,
            "detected_at": row.detected_at.isoformat() if row.detected_at else None,
            "acknowledged": row.acknowledged,
        })

    recent_predictions_result = await db.execute(
        select(AnalyticsResultTable)
        .where(AnalyticsResultTable.query_type.in_(["trend_predict", "forecast_arima"]))
        .order_by(AnalyticsResultTable.created_at.desc())
        .limit(10)
    )
    recent_predictions = [_result_row_to_dict(r) for r in recent_predictions_result.scalars().all()]

    active_dashboards_result = await db.execute(
        select(DashboardConfigTable)
        .where(DashboardConfigTable.is_active == True)
        .order_by(DashboardConfigTable.created_at.desc())
        .limit(5)
    )
    active_dashboards = []
    for row in active_dashboards_result.scalars().all():
        active_dashboards.append({
            "config_id": row.id,
            "name": row.name,
            "industry": row.industry,
            "refresh_interval": row.refresh_interval,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        })

    return {
        "recent_queries": recent_queries,
        "recent_anomalies": recent_anomalies,
        "recent_predictions": recent_predictions,
        "active_dashboards": active_dashboards,
    }


class NL2SQLRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    query: str = Field(..., min_length=1, max_length=2000)


class DataInsightRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    data: List[Dict[str, Any]] = Field(..., min_length=1)
    query: str = Field("", max_length=1000)


@router.post("/nl2sql")
async def nl_to_sql(
    data: NL2SQLRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)
    result = await engine.nl_to_sql(query=data.query, db_session=db)
    return result


@router.post("/data-insight")
async def generate_data_insight(
    data: DataInsightRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = _get_analytics_engine(request)
    result = await engine.generate_data_insight(data=data.data, query=data.query)
    return result
