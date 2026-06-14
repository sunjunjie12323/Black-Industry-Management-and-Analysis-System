"""
API工具函数模块
提供公共的辅助函数，避免代码重复
"""
import json
from typing import Dict, Any


def raw_intelligence_to_dict(item) -> Dict[str, Any]:
    """
    将RawIntelligenceTable ORM对象转为字典
    从cleaned关联中提取实体和威胁等级
    """
    metadata = {}
    if item.metadata_json:
        try:
            metadata = json.loads(item.metadata_json)
        except (json.JSONDecodeError, TypeError):
            pass
    entities = []
    iocs = []
    threat_level = "info"
    if item.cleaned:
        if item.cleaned.entities_json:
            try:
                entities = json.loads(item.cleaned.entities_json)
            except (json.JSONDecodeError, TypeError):
                pass
        threat_level = item.cleaned.threat_level or "info"
    return {
        "id": item.id,
        "content": item.content,
        "source": item.source,
        "collected_at": item.collected_at.isoformat() if item.collected_at else None,
        "entities": entities,
        "iocs": iocs,
        "threat_level": threat_level,
        "metadata": metadata,
    }
