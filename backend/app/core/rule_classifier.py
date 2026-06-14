import re
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from app.core.seed_data import load_classification_rules


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _normalize(text: str) -> str:
    return (text or "").lower()


class RuleBasedClassifier:
    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        if rules is None:
            rules = load_classification_rules()
        self._categories: Dict[str, Dict[str, Any]] = rules.get("categories", {}) or {}
        self._severity_keywords: Dict[str, Dict[str, Any]] = rules.get("severity_keywords", {}) or {}

    def classify(self, text: str) -> Dict[str, Any]:
        if not text:
            return {
                "category": "unknown",
                "category_label": "未分类",
                "confidence": 0.0,
                "severity": "info",
                "matched_keywords": [],
                "scores": {},
            }

        text_norm = _normalize(text)

        scores: Dict[str, float] = {}
        matched: Dict[str, List[str]] = {}

        for cat_key, cat_info in self._categories.items():
            weight = float(cat_info.get("weight", 1.0) or 1.0)
            kw_zh = cat_info.get("keywords_zh", []) or []
            kw_en = cat_info.get("keywords_en", []) or []
            hits: List[str] = []
            score = 0.0
            for kw in kw_zh:
                if not kw:
                    continue
                count = text_norm.count(_normalize(kw))
                if count > 0:
                    hits.append(kw)
                    score += count * weight
            for kw in kw_en:
                if not kw:
                    continue
                count = text_norm.count(_normalize(kw))
                if count > 0:
                    hits.append(kw)
                    score += count * weight
            if score > 0:
                scores[cat_key] = score
                matched[cat_key] = hits

        if not scores:
            category = "unknown"
            category_label = "未分类"
            confidence = 0.0
            primary_matched: List[str] = []
        else:
            sorted_cats = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
            category = sorted_cats[0][0]
            cat_info = self._categories.get(category, {})
            label_zh = cat_info.get("label_zh", category)
            label_en = cat_info.get("label_en", category)
            category_label = label_zh if re.search(r'[\u4e00-\u9fff]', text) else label_en
            total_score = sum(scores.values())
            confidence = min(1.0, sorted_cats[0][1] / max(total_score, 1.0))
            primary_matched = matched.get(category, [])

        severity = self._assess_severity(text)

        return {
            "category": category,
            "category_label": category_label,
            "confidence": round(confidence, 4),
            "severity": severity,
            "matched_keywords": primary_matched,
            "scores": {k: round(v, 4) for k, v in scores.items()},
        }

    def _assess_severity(self, text: str) -> str:
        if not self._severity_keywords:
            return "info"
        text_norm = _normalize(text)
        best_severity: Optional[str] = None
        best_score = 0
        for sev_key, sev_info in self._severity_keywords.items():
            if sev_key not in _SEVERITY_ORDER:
                continue
            zh_list = sev_info.get("zh", []) or []
            en_list = sev_info.get("en", []) or []
            score = 0
            for kw in zh_list:
                if kw and _normalize(kw) in text_norm:
                    score += text_norm.count(_normalize(kw))
            for kw in en_list:
                if kw and _normalize(kw) in text_norm:
                    score += text_norm.count(_normalize(kw))
            if score > best_score:
                best_score = score
                best_severity = sev_key
        if best_severity is None:
            return "info"
        return best_severity

    def list_categories(self) -> List[str]:
        return list(self._categories.keys())


rule_classifier = RuleBasedClassifier()
