import json
from typing import Any, Dict, List, Optional

from app.db.tables import AnalysisResultTable


def safe_json_loads(json_str: Optional[str], default: Any = None) -> Any:
    """
    安全解析 JSON 字符串，失败时返回默认值。
    
    Args:
        json_str: 要解析的 JSON 字符串
        default: 解析失败时的默认值（默认 None）
    
    Returns:
        解析后的对象，或默认值
    """
    if default is None:
        default = {} if isinstance(json_str, str) and json_str.strip().startswith("{") else []
    
    if not json_str:
        return default if default is not None else []
    
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError, ValueError):
        return default if default is not None else []


def safe_json_loads_list(json_str: Optional[str]) -> List:
    """安全解析 JSON 字符串为列表"""
    return safe_json_loads(json_str, default=[])


def safe_json_loads_dict(json_str: Optional[str]) -> Dict:
    """安全解析 JSON 字符串为字典"""
    return safe_json_loads(json_str, default={})


def truncate_content(content: Optional[str], max_length: int = 300, suffix: str = "...") -> str:
    """
    截断内容到指定长度。
    
    Args:
        content: 原始内容
        max_length: 最大长度
        suffix: 截断后缀
    
    Returns:
        截断后的字符串
    """
    if not content:
        return ""
    if len(content) <= max_length:
        return content
    return content[:max_length] + suffix


def row_to_dict(row: AnalysisResultTable) -> dict:
    findings = []
    iocs = []
    recommendations = []
    result_data = {}
    try:
        findings = json.loads(row.findings_json) if row.findings_json else []
    except (json.JSONDecodeError, TypeError):
        pass
    try:
        iocs = json.loads(row.iocs_json) if row.iocs_json else []
    except (json.JSONDecodeError, TypeError):
        pass
    try:
        recommendations = json.loads(row.recommendations_json) if row.recommendations_json else []
    except (json.JSONDecodeError, TypeError):
        pass
    try:
        result_data = json.loads(row.result_data_json) if row.result_data_json else {}
    except (json.JSONDecodeError, TypeError):
        pass
    return {
        "id": row.id,
        "analysis_type": row.analysis_type,
        "target_id": row.target_id,
        "target_type": row.target_type,
        "result_summary": row.result_summary,
        "findings": findings,
        "iocs": iocs,
        "recommendations": recommendations,
        "result_data": result_data,
        "confidence_score": row.confidence_score,
        "status": row.status,
        "error_message": row.error_message,
        "model_name": row.model_name,
        "analyzed_at": row.analyzed_at.isoformat() if row.analyzed_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
