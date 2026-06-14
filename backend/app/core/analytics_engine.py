import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from app.config import settings

ALLOWED_TABLES = {
    "raw_intelligence", "cleaned_intelligence", "entity",
    "report", "pir", "finetune_tasks", "qa_conversations",
    "generated_contents", "prompt_templates", "alert",
    "analytics_result", "dashboard_config", "anomaly_record",
    "blacktalk_term", "graph_entity", "graph_relation",
    "provenance_record", "decay_record", "user",
}

SQL_INJECTION_PATTERNS = [
    r";\s*DROP\s", r";\s*DELETE\s", r";\s*UPDATE\s", r";\s*INSERT\s",
    r";\s*ALTER\s", r";\s*CREATE\s", r";\s*TRUNCATE\s",
    r"UNION\s+SELECT", r"--\s*$", r"/\*", r"\*/",
    r"xp_cmdshell", r"INTO\s+OUTFILE", r"LOAD_FILE",
    r"INFORMATION_SCHEMA", r"EXEC\s", r"EXECUTE\s",
    r"GRANT\s", r"REVOKE\s", r"SHUTDOWN\s",
]

MAX_QUERY_ROWS = 500


def _validate_sql_safety(sql: str) -> str | None:
    if not sql or not sql.strip():
        return "SQL为空"
    stripped = sql.strip()
    if not stripped.upper().startswith("SELECT"):
        return "只允许SELECT查询"
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, stripped, re.IGNORECASE):
            return f"检测到危险SQL模式: {pattern}"
    if ";" in stripped[:-1]:
        remainder = stripped[:-1] if stripped.endswith(";") else stripped
        if ";" in remainder:
            return "不允许多语句查询"
    return None


def _extract_table_names(sql: str) -> list[str]:
    from_pattern = re.compile(r'\bFROM\s+(\w+)', re.IGNORECASE)
    join_pattern = re.compile(r'\bJOIN\s+(\w+)', re.IGNORECASE)
    tables = [m.group(1) for m in from_pattern.finditer(sql)]
    tables.extend(m.group(1) for m in join_pattern.finditer(sql))
    return tables


async def _execute_safe_sql(db_session, sql: str, max_rows: int = MAX_QUERY_ROWS) -> list[dict]:
    error = _validate_sql_safety(sql)
    if error:
        raise ValueError(f"SQL安全校验失败: {error}")

    tables = _extract_table_names(sql)
    for t in tables:
        if t.lower() not in ALLOWED_TABLES:
            raise ValueError(f"不允许查询表: {t}")

    from sqlalchemy import text
    result = await db_session.execute(text(sql))
    columns = result.keys()
    rows = result.fetchmany(max_rows)
    return [dict(zip(columns, row)) for row in rows]


@dataclass
class QueryResult:
    query: str
    sql: str
    data: List[Dict[str, Any]]
    chart_type: str
    chart_config: Dict[str, Any]
    explanation: str
    execution_time_ms: float

    def to_dict(self) -> Dict:
        return {
            "query": self.query,
            "sql": self.sql,
            "data": self.data[:100],
            "chart_type": self.chart_type,
            "chart_config": self.chart_config,
            "explanation": self.explanation,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "total_rows": len(self.data),
        }


@dataclass
class AnomalyResult:
    metric: str
    anomalies: List[Dict[str, Any]]
    algorithm: str
    threshold: float
    total_points: int
    anomaly_count: int

    def to_dict(self) -> Dict:
        return {
            "metric": self.metric,
            "anomalies": self.anomalies,
            "algorithm": self.algorithm,
            "threshold": self.threshold,
            "total_points": self.total_points,
            "anomaly_count": self.anomaly_count,
            "anomaly_rate": round(self.anomaly_count / max(1, self.total_points), 4),
        }


@dataclass
class ForecastResult:
    metric: str
    historical: List[Dict[str, Any]]
    predicted: List[Dict[str, Any]]
    confidence_lower: List[Dict[str, Any]]
    confidence_upper: List[Dict[str, Any]]
    method: str
    forecast_days: int
    accuracy_metrics: Dict[str, float]

    def to_dict(self) -> Dict:
        safe_metrics = {}
        for k, v in self.accuracy_metrics.items():
            try:
                safe_metrics[k] = round(v, 4)
            except (TypeError, ValueError):
                safe_metrics[k] = 0.0
        return {
            "metric": self.metric,
            "historical": self.historical,
            "predicted": self.predicted,
            "confidence_lower": self.confidence_lower,
            "confidence_upper": self.confidence_upper,
            "method": self.method,
            "forecast_days": self.forecast_days,
            "accuracy_metrics": safe_metrics,
        }


class NLQueryEngine:
    QUERY_PATTERNS = [
        {
            "keywords": ["威胁等级", "等级分布", "threat level", "级别"],
            "table": "cleaned_intelligence",
            "column": "threat_level",
            "agg": "count",
            "chart": "pie",
            "sql_template": "SELECT threat_level, COUNT(*) as count FROM cleaned_intelligence GROUP BY threat_level",
        },
        {
            "keywords": ["来源", "数据源", "source", "渠道"],
            "table": "raw_intelligence",
            "column": "source",
            "agg": "count",
            "chart": "bar",
            "sql_template": "SELECT source, COUNT(*) as count FROM raw_intelligence GROUP BY source",
        },
        {
            "keywords": ["实体", "实体类型", "entity", "类型分布"],
            "table": "entity",
            "column": "type",
            "agg": "count",
            "chart": "bar",
            "sql_template": "SELECT type, COUNT(*) as count FROM entity GROUP BY type",
        },
        {
            "keywords": ["趋势", "时间", "每日", "变化", "trend", "daily"],
            "table": "raw_intelligence",
            "column": "collected_at",
            "agg": "daily_count",
            "chart": "line",
            "sql_template": "SELECT DATE(collected_at) as date, COUNT(*) as count FROM raw_intelligence GROUP BY DATE(collected_at) ORDER BY date",
        },
        {
            "keywords": ["微调", "训练", "finetune", "任务状态"],
            "table": "finetune_tasks",
            "column": "status",
            "agg": "count",
            "chart": "pie",
            "sql_template": "SELECT status, COUNT(*) as count FROM finetune_tasks GROUP BY status",
        },
        {
            "keywords": ["对话", "问答", "conversation", "行业分布"],
            "table": "qa_conversations",
            "column": "industry",
            "agg": "count",
            "chart": "bar",
            "sql_template": "SELECT industry, COUNT(*) as count FROM qa_conversations GROUP BY industry",
        },
        {
            "keywords": ["内容", "生成", "审核", "content", "review"],
            "table": "generated_contents",
            "column": "review_status",
            "agg": "count",
            "chart": "pie",
            "sql_template": "SELECT review_status, COUNT(*) as count FROM generated_contents GROUP BY review_status",
        },
        {
            "keywords": ["提示词", "模板", "prompt", "分类"],
            "table": "prompt_templates",
            "column": "category",
            "agg": "count",
            "chart": "bar",
            "sql_template": "SELECT category, COUNT(*) as count FROM prompt_templates GROUP BY category",
        },
    ]

    async def parse_query(self, query: str, db_session=None) -> QueryResult:
        import time
        start = time.time()

        query_lower = query.lower()
        matched_pattern = None
        best_score = 0

        for pattern in self.QUERY_PATTERNS:
            score = sum(1 for kw in pattern["keywords"] if kw in query_lower)
            if score > best_score:
                best_score = score
                matched_pattern = pattern

        if not matched_pattern:
            matched_pattern = {
                "sql_template": "SELECT '总览' as category, COUNT(*) as count FROM raw_intelligence",
                "chart": "bar",
                "table": "overview",
            }

        sql = matched_pattern.get("sql_template", "SELECT '总览' as category, COUNT(*) as count FROM raw_intelligence")
        chart_type = matched_pattern.get("chart", "bar")
        data = []

        if db_session:
            try:
                data = await _execute_safe_sql(db_session, sql)
            except ValueError as exc:
                logger.warning(f"SQL安全校验失败: {exc}")
            except Exception as exc:
                logger.warning(f"NL查询执行失败: {exc}")

        chart_config = self._generate_chart_config(chart_type, data, query)

        explanation = self._generate_explanation(matched_pattern, query, len(data))

        return QueryResult(
            query=query,
            sql=sql,
            data=data,
            chart_type=chart_type,
            chart_config=chart_config,
            explanation=explanation,
            execution_time_ms=(time.time() - start) * 1000,
        )

    async def parse_query_with_llm(self, query: str, llm_service=None, db_session=None) -> QueryResult:
        import time
        start = time.time()

        rule_result = None
        try:
            rule_result = await self.parse_query(query, db_session)
            if rule_result.data and "总览" not in rule_result.sql:
                return rule_result
        except Exception as exc:
            logger.warning(f"规则查询解析失败: {exc}")

        if not llm_service:
            if rule_result:
                return rule_result
            return QueryResult(
                query=query,
                sql="",
                data=[],
                chart_type="bar",
                chart_config={},
                explanation="LLM服务不可用，且规则匹配失败",
                execution_time_ms=(time.time() - start) * 1000,
            )

        sql_injection_patterns = [
            r";\s*DROP\s", r";\s*DELETE\s", r";\s*UPDATE\s", r";\s*INSERT\s",
            r"UNION\s+SELECT", r"--\s*$", r"/\*", r"\*/", r"xp_cmdshell",
            r"INTO\s+OUTFILE", r"LOAD_FILE", r"INFORMATION_SCHEMA",
        ]

        schema_info = """
数据库表结构:
- raw_intelligence: id, source, content, collected_at, processed
- cleaned_intelligence: id, raw_id, threat_level, category, summary, cleaned_at
- entity: id, name, type, risk_score, first_seen, last_seen
- report: id, title, content, created_at, status
- pir: id, title, description, priority, status, created_at
- finetune_tasks: id, name, status, created_at
- qa_conversations: id, question, answer, industry, created_at
- generated_contents: id, type, content, review_status, created_at
- prompt_templates: id, name, category, content, created_at
"""

        prompt = f"""你是一个SQL生成助手。根据用户的自然语言查询，生成对应的SQL查询语句。

{schema_info}

规则:
1. 只生成SELECT查询，不要生成任何修改数据的语句
2. 只返回SQL语句，不要任何解释
3. 使用标准SQL语法
4. 如果无法理解查询，返回空字符串

用户查询: {query}

SQL:"""

        try:
            llm_response = await llm_service.generate(prompt)
            if not isinstance(llm_response, str):
                llm_response = str(llm_response) if llm_response is not None else ""
            generated_sql = llm_response.strip()

            if generated_sql.startswith("```"):
                generated_sql = re.sub(r'^```\w*\n?', '', generated_sql)
                generated_sql = re.sub(r'\n?```$', '', generated_sql)
            generated_sql = generated_sql.strip()

            if not generated_sql.upper().startswith("SELECT"):
                if rule_result:
                    return rule_result
                return QueryResult(
                    query=query,
                    sql="",
                    data=[],
                    chart_type="bar",
                    chart_config={},
                    explanation="LLM未生成有效SELECT查询",
                    execution_time_ms=(time.time() - start) * 1000,
                )

            for pattern in sql_injection_patterns:
                if re.search(pattern, generated_sql, re.IGNORECASE):
                    logger.warning(f"SQL注入风险检测: {generated_sql}")
                    if rule_result:
                        return rule_result
                    return QueryResult(
                        query=query,
                        sql="",
                        data=[],
                        chart_type="bar",
                        chart_config={},
                        explanation="检测到SQL注入风险，查询已拦截",
                        execution_time_ms=(time.time() - start) * 1000,
                    )

            sql = generated_sql
            data = []

            if db_session:
                try:
                    data = await _execute_safe_sql(db_session, sql)
                except ValueError as exc:
                    logger.warning(f"LLM生成SQL安全校验失败: {exc}")
                    if rule_result:
                        return rule_result
                except Exception as exc:
                    logger.warning(f"LLM生成SQL执行失败: {exc}")
                    if rule_result:
                        return rule_result

            chart_type = "bar"
            if any(kw in query.lower() for kw in ["趋势", "时间", "变化", "trend"]):
                chart_type = "line"
            elif any(kw in query.lower() for kw in ["分布", "占比", "比例"]):
                chart_type = "pie"

            chart_config = self._generate_chart_config(chart_type, data, query)
            explanation = f"通过LLM解析查询「{query}」，生成SQL并返回{len(data)}条结果"

            return QueryResult(
                query=query,
                sql=sql,
                data=data,
                chart_type=chart_type,
                chart_config=chart_config,
                explanation=explanation,
                execution_time_ms=(time.time() - start) * 1000,
            )
        except Exception as exc:
            logger.warning(f"LLM查询解析失败: {exc}")
            if rule_result:
                return rule_result
            return QueryResult(
                query=query,
                sql="",
                data=[],
                chart_type="bar",
                chart_config={},
                explanation="LLM解析失败，请稍后重试",
                execution_time_ms=(time.time() - start) * 1000,
            )

    def _generate_chart_config(
        self, chart_type: str, data: List[Dict], query: str
    ) -> Dict[str, Any]:
        config = {
            "type": chart_type,
            "title": query[:50],
            "responsive": True,
        }

        if data and chart_type in ("bar", "line", "area"):
            keys = list(data[0].keys()) if data else []
            if len(keys) >= 2:
                config["xField"] = keys[0]
                config["yField"] = keys[1]
        elif data and chart_type == "pie":
            keys = list(data[0].keys()) if data else []
            if len(keys) >= 2:
                config["angleField"] = keys[1]
                config["colorField"] = keys[0]

        return config

    def _generate_explanation(
        self, pattern: Dict, query: str, result_count: int
    ) -> str:
        table = pattern.get("table", "未知")
        return f"查询「{query}」对应数据表 {table}，返回{result_count}条结果"

    def generate_chart_config(self, chart_type: str, data: List[Dict], query: str, industry: str = None) -> Dict[str, Any]:
        INDUSTRY_THEMES = {
            "金融": {"primary": "#1890ff", "secondary": "#2fc25b", "palette": ["#1890ff", "#2fc25b", "#facc14", "#f04864", "#8543e0"]},
            "电商": {"primary": "#ff4d4f", "secondary": "#fa8c16", "palette": ["#ff4d4f", "#fa8c16", "#1890ff", "#2fc25b", "#8543e0"]},
            "游戏": {"primary": "#722ed1", "secondary": "#eb2f96", "palette": ["#722ed1", "#eb2f96", "#1890ff", "#2fc25b", "#facc14"]},
            "社交": {"primary": "#13c2c2", "secondary": "#1890ff", "palette": ["#13c2c2", "#1890ff", "#2fc25b", "#facc14", "#f04864"]},
            "通用": {"primary": "#1890ff", "secondary": "#2fc25b", "palette": ["#1890ff", "#2fc25b", "#facc14", "#f04864", "#8543e0"]},
        }

        theme = INDUSTRY_THEMES.get(industry, INDUSTRY_THEMES["通用"])

        config = {
            "type": chart_type,
            "title": {"text": query[:50], "style": {"fontSize": 16, "fontWeight": 500}},
            "responsive": True,
            "color": theme["palette"],
            "tooltip": {"show": True, "trigger": "axis" if chart_type in ("bar", "line", "area") else "item"},
            "legend": {"show": True, "position": "top"},
            "animation": True,
        }

        if not data:
            return config

        keys = list(data[0].keys())
        if len(keys) < 2:
            return config

        if chart_type in ("bar", "line", "area"):
            config["xAxis"] = {
                "type": "category",
                "data": [str(row.get(keys[0], "")) for row in data],
                "axisLabel": {"rotate": 45 if len(data) > 10 else 0},
            }
            config["yAxis"] = {"type": "value"}
            series_item = {
                "name": keys[1],
                "type": chart_type if chart_type != "area" else "line",
                "data": [row.get(keys[1], 0) for row in data],
                "smooth": True,
            }
            if chart_type == "area":
                series_item["areaStyle"] = {"opacity": 0.3}
            if chart_type == "bar":
                series_item["itemStyle"] = {"color": theme["primary"]}
            elif chart_type == "line":
                series_item["lineStyle"] = {"color": theme["primary"], "width": 2}
                series_item["itemStyle"] = {"color": theme["primary"]}
            config["series"] = [series_item]
        elif chart_type in ("pie", "donut"):
            config["series"] = [{
                "type": "pie",
                "radius": ["40%", "70%"] if chart_type == "donut" else "70%",
                "data": [{"name": str(row.get(keys[0], "")), "value": row.get(keys[1], 0)} for row in data],
                "label": {"show": True, "formatter": "{b}: {d}%"},
                "emphasis": {"itemStyle": {"shadowBlur": 10, "shadowOffsetX": 0, "shadowColor": "rgba(0,0,0,0.5)"}},
            }]
        elif chart_type == "scatter":
            if len(keys) >= 3:
                config["xAxis"] = {"type": "value"}
                config["yAxis"] = {"type": "value"}
                config["series"] = [{
                    "type": "scatter",
                    "data": [[row.get(keys[1], 0), row.get(keys[2], 0)] for row in data],
                    "symbolSize": 8,
                }]
            else:
                config["xAxis"] = {"type": "category", "data": [str(row.get(keys[0], "")) for row in data]}
                config["yAxis"] = {"type": "value"}
                config["series"] = [{"type": "scatter", "data": [row.get(keys[1], 0) for row in data]}]
        elif chart_type == "radar":
            config["radar"] = {
                "indicator": [{"name": str(row.get(keys[0], "")), "max": max(row.get(keys[1], 0) * 1.2, 1)} for row in data]
            }
            config["series"] = [{
                "type": "radar",
                "data": [{"value": [row.get(keys[1], 0) for row in data]}],
            }]

        return config


class AnomalyDetector:
    def __init__(self):
        self._zscore_threshold = 2.0
        self._iqr_multiplier = 1.5

    def detect_zscore(
        self,
        values: List[float],
        timestamps: Optional[List[str]] = None,
        threshold: float = 2.0,
    ) -> AnomalyResult:
        if len(values) < 3:
            return AnomalyResult(
                metric="value",
                anomalies=[],
                algorithm="zscore",
                threshold=threshold,
                total_points=len(values),
                anomaly_count=0,
            )

        mean_val = sum(values) / len(values)
        variance = sum((v - mean_val) ** 2 for v in values) / len(values)
        std_val = math.sqrt(variance) if variance > 0 else 0

        anomalies = []
        for i, val in enumerate(values):
            if std_val > 0:
                z_score = abs(val - mean_val) / std_val
                if z_score > threshold:
                    anomaly = {
                        "index": i,
                        "value": val,
                        "expected": round(mean_val, 2),
                        "z_score": round(z_score, 4),
                        "direction": "spike" if val > mean_val else "drop",
                    }
                    if timestamps and i < len(timestamps):
                        anomaly["timestamp"] = timestamps[i]
                    anomalies.append(anomaly)

        return AnomalyResult(
            metric="value",
            anomalies=anomalies,
            algorithm="zscore",
            threshold=threshold,
            total_points=len(values),
            anomaly_count=len(anomalies),
        )

    def detect_iqr(
        self,
        values: List[float],
        timestamps: Optional[List[str]] = None,
        multiplier: float = 1.5,
    ) -> AnomalyResult:
        if len(values) < 4:
            return AnomalyResult(
                metric="value",
                anomalies=[],
                algorithm="iqr",
                threshold=multiplier,
                total_points=len(values),
                anomaly_count=0,
            )

        sorted_vals = sorted(values)
        n = len(sorted_vals)
        q1_idx = n // 4
        q3_idx = 3 * n // 4
        q1 = sorted_vals[q1_idx]
        q3 = sorted_vals[q3_idx]
        iqr = q3 - q1

        lower_bound = q1 - multiplier * iqr
        upper_bound = q3 + multiplier * iqr

        anomalies = []
        for i, val in enumerate(values):
            if val < lower_bound or val > upper_bound:
                anomaly = {
                    "index": i,
                    "value": val,
                    "expected": round((q1 + q3) / 2, 2),
                    "bounds": {"lower": round(lower_bound, 2), "upper": round(upper_bound, 2)},
                    "direction": "spike" if val > upper_bound else "drop",
                }
                if timestamps and i < len(timestamps):
                    anomaly["timestamp"] = timestamps[i]
                anomalies.append(anomaly)

        return AnomalyResult(
            metric="value",
            anomalies=anomalies,
            algorithm="iqr",
            threshold=multiplier,
            total_points=len(values),
            anomaly_count=len(anomalies),
        )

    def detect_isolation_forest_simplified(
        self,
        values: List[float],
        timestamps: Optional[List[str]] = None,
        contamination: float = 0.1,
    ) -> AnomalyResult:
        if len(values) < 10:
            return self.detect_zscore(values, timestamps)

        n = len(values)
        mean_val = sum(values) / n
        std_val = math.sqrt(sum((v - mean_val) ** 2 for v in values) / n)

        if std_val == 0:
            return AnomalyResult(
                metric="value", anomalies=[], algorithm="isolation_forest",
                threshold=contamination, total_points=n, anomaly_count=0,
            )

        scores = []
        for val in values:
            depth = 0
            current_min = min(values)
            current_max = max(values)
            temp_val = val
            for _ in range(50):
                if temp_val < current_min or temp_val > current_max:
                    break
                split = (current_min + current_max) / 2
                depth += 1
                if temp_val < split:
                    current_max = split
                else:
                    current_min = split

            path_length = depth + 0.5
            c_n = 2 * (math.log(n - 1) + 0.5772) - 2 * (n - 1) / n if n > 1 else 0
            anomaly_score = 2 ** (-path_length / c_n) if c_n > 0 else 0.5
            scores.append(anomaly_score)

        threshold_score = sorted(scores)[int(n * (1 - contamination))]

        anomalies = []
        for i, (val, score) in enumerate(zip(values, scores)):
            if score > threshold_score:
                anomaly = {
                    "index": i,
                    "value": val,
                    "anomaly_score": round(score, 4),
                    "direction": "spike" if val > mean_val else "drop",
                }
                if timestamps and i < len(timestamps):
                    anomaly["timestamp"] = timestamps[i]
                anomalies.append(anomaly)

        return AnomalyResult(
            metric="value",
            anomalies=anomalies,
            algorithm="isolation_forest",
            threshold=contamination,
            total_points=n,
            anomaly_count=len(anomalies),
        )

    def detect_time_series_anomaly(self, values: List[float], timestamps: List[str], window_size: int = 7) -> AnomalyResult:
        n = len(values)
        if n < window_size * 2:
            return self.detect_zscore(values, timestamps)

        ma = []
        for i in range(n):
            start_idx = max(0, i - window_size + 1)
            window = values[start_idx:i + 1]
            ma.append(sum(window) / len(window))

        residuals = [values[i] - ma[i] for i in range(n)]

        mean_res = sum(residuals) / n
        var_res = sum((r - mean_res) ** 2 for r in residuals) / n
        std_res = math.sqrt(var_res) if var_res > 0 else 0

        threshold = 2.0
        anomalies = []

        for i in range(n):
            if std_res > 0:
                z_score = abs(residuals[i] - mean_res) / std_res
                if z_score > threshold:
                    anomaly = {
                        "index": i,
                        "value": values[i],
                        "expected": round(ma[i], 2),
                        "residual": round(residuals[i], 4),
                        "z_score": round(z_score, 4),
                        "direction": "spike" if values[i] > ma[i] else "drop",
                        "moving_average": round(ma[i], 2),
                    }
                    if timestamps and i < len(timestamps):
                        anomaly["timestamp"] = timestamps[i]
                    anomalies.append(anomaly)

        return AnomalyResult(
            metric="value",
            anomalies=anomalies,
            algorithm="time_series_ma_stl",
            threshold=threshold,
            total_points=n,
            anomaly_count=len(anomalies),
        )

    def detect_collective_anomaly(self, data_matrix: List[List[float]], threshold: float = 2.0) -> Dict[str, Any]:
        if not data_matrix or not data_matrix[0]:
            return {"collective_anomalies": [], "metric_count": 0, "total_events": 0}

        n_points = len(data_matrix[0])
        n_metrics = len(data_matrix)

        metric_results = []
        for metric_idx, metric_values in enumerate(data_matrix):
            result = self.detect_zscore(metric_values, threshold=threshold)
            metric_results.append(result)

        joint_scores = [0.0] * n_points
        for metric_idx, result in enumerate(metric_results):
            for anomaly in result.anomalies:
                idx = anomaly["index"]
                if idx < n_points:
                    joint_scores[idx] += anomaly.get("z_score", threshold)

        mean_joint = sum(joint_scores) / n_points if n_points > 0 else 0
        std_joint = math.sqrt(sum((s - mean_joint) ** 2 for s in joint_scores) / n_points) if n_points > 0 else 0

        collective_anomalies = []
        for i in range(n_points):
            if std_joint > 0 and (joint_scores[i] - mean_joint) / std_joint > threshold:
                contributing_metrics = []
                for metric_idx, result in enumerate(metric_results):
                    for anomaly in result.anomalies:
                        if anomaly["index"] == i:
                            contributing_metrics.append({
                                "metric_index": metric_idx,
                                "value": anomaly["value"],
                                "z_score": anomaly.get("z_score", 0),
                            })

                if len(contributing_metrics) >= 2:
                    collective_anomalies.append({
                        "index": i,
                        "joint_score": round(joint_scores[i], 4),
                        "contributing_metrics": contributing_metrics,
                        "metric_count": len(contributing_metrics),
                    })

        return {
            "collective_anomalies": collective_anomalies,
            "metric_count": n_metrics,
            "total_events": len(collective_anomalies),
            "threshold": threshold,
            "individual_results": [r.to_dict() for r in metric_results],
        }


class TrendForecaster:
    def forecast_linear(
        self,
        historical_values: List[float],
        historical_dates: List[str],
        forecast_days: int = 7,
    ) -> ForecastResult:
        n = len(historical_values)
        if n < 2:
            return ForecastResult(
                metric="value",
                historical=[{"date": d, "value": v} for d, v in zip(historical_dates, historical_values)],
                predicted=[],
                confidence_lower=[],
                confidence_upper=[],
                method="linear",
                forecast_days=forecast_days,
                accuracy_metrics={},
            )

        x = list(range(n))
        y = historical_values

        x_mean = sum(x) / n
        y_mean = sum(y) / n

        ss_xy = sum((xi - x_mean) * (yi - y_mean) for xi, yi in zip(x, y))
        ss_xx = sum((xi - x_mean) ** 2 for xi in x)

        slope = ss_xy / ss_xx if ss_xx > 0 else 0
        intercept = y_mean - slope * x_mean

        residuals = [y[i] - (slope * x[i] + intercept) for i in range(n)]
        std_err = math.sqrt(sum(r ** 2 for r in residuals) / max(1, n - 2)) if n > 2 else 0

        historical = [{"date": d, "value": v} for d, v in zip(historical_dates, historical_values)]

        predicted = []
        confidence_lower = []
        confidence_upper = []

        try:
            last_date = datetime.strptime(historical_dates[-1], "%Y-%m-%d")
        except (ValueError, IndexError):
            last_date = datetime.now(timezone.utc)

        for i in range(1, forecast_days + 1):
            future_x = n + i - 1
            pred_val = max(0, slope * future_x + intercept)
            pred_date = (last_date + timedelta(days=i)).strftime("%Y-%m-%d")

            t_val = 1.96
            margin = t_val * std_err * math.sqrt(1 + 1 / n + (future_x - x_mean) ** 2 / max(1, ss_xx))

            predicted.append({"date": pred_date, "value": round(pred_val, 2)})
            confidence_lower.append({"date": pred_date, "value": round(max(0, pred_val - margin), 2)})
            confidence_upper.append({"date": pred_date, "value": round(pred_val + margin, 2)})

        mape = 0
        if n > 2:
            actual = historical_values[-min(7, n):]
            fitted = [slope * (n - min(7, n) + j) + intercept for j in range(len(actual))]
            mape_vals = [abs(a - f) / max(abs(a), 0.001) for a, f in zip(actual, fitted)]
            mape = sum(mape_vals) / len(mape_vals) if mape_vals else 0

        return ForecastResult(
            metric="value",
            historical=historical,
            predicted=predicted,
            confidence_lower=confidence_lower,
            confidence_upper=confidence_upper,
            method="linear_regression",
            forecast_days=forecast_days,
            accuracy_metrics={"mape": mape, "r_squared": 1 - sum(r ** 2 for r in residuals) / max(1, sum((yi - y_mean) ** 2 for yi in y))},
        )

    def forecast_exponential_smoothing(
        self,
        historical_values: List[float],
        historical_dates: List[str],
        forecast_days: int = 7,
        alpha: float = 0.3,
    ) -> ForecastResult:
        n = len(historical_values)
        if n < 3:
            return self.forecast_linear(historical_values, historical_dates, forecast_days)

        smoothed = [historical_values[0]]
        for i in range(1, n):
            s = alpha * historical_values[i] + (1 - alpha) * smoothed[-1]
            smoothed.append(s)

        trend = (smoothed[-1] - smoothed[-2]) if n >= 2 else 0

        historical = [{"date": d, "value": v} for d, v in zip(historical_dates, historical_values)]

        predicted = []
        confidence_lower = []
        confidence_upper = []

        try:
            last_date = datetime.strptime(historical_dates[-1], "%Y-%m-%d")
        except (ValueError, IndexError):
            last_date = datetime.now(timezone.utc)

        residuals = [historical_values[i] - smoothed[i] for i in range(n)]
        std_err = math.sqrt(sum(r ** 2 for r in residuals) / n) if n > 0 else 0

        for i in range(1, forecast_days + 1):
            pred_val = max(0, smoothed[-1] + trend * i)
            pred_date = (last_date + timedelta(days=i)).strftime("%Y-%m-%d")
            margin = 1.96 * std_err * math.sqrt(i)

            predicted.append({"date": pred_date, "value": round(pred_val, 2)})
            confidence_lower.append({"date": pred_date, "value": round(max(0, pred_val - margin), 2)})
            confidence_upper.append({"date": pred_date, "value": round(pred_val + margin, 2)})

        return ForecastResult(
            metric="value",
            historical=historical,
            predicted=predicted,
            confidence_lower=confidence_lower,
            confidence_upper=confidence_upper,
            method="exponential_smoothing",
            forecast_days=forecast_days,
            accuracy_metrics={"alpha": alpha, "std_error": std_err},
        )

    def forecast_arima(
        self,
        historical_values: List[float],
        historical_dates: List[str],
        forecast_days: int = 7,
        order: Tuple = (1, 1, 1),
        max_iter: int = 20,
        tol: float = 1e-6,
    ) -> ForecastResult:
        p, d, q = order
        n = len(historical_values)
        if n < 4 or d < 0 or d > 2:
            return self.forecast_linear(historical_values, historical_dates, forecast_days)

        current = list(historical_values)
        for _ in range(d):
            if len(current) < 2:
                return self.forecast_linear(historical_values, historical_dates, forecast_days)
            current = [current[i] - current[i - 1] for i in range(1, len(current))]

        diff = current
        m = len(diff)

        ar_coefs = [0.0] * max(p, 1)
        ma_coefs = [0.0] * max(q, 1)

        for _ in range(max_iter):
            eps = [0.0] * m
            for t in range(m):
                ar_term = sum(ar_coefs[j] * diff[t - j - 1] for j in range(min(p, t)))
                ma_term = sum(ma_coefs[j] * eps[t - j - 1] for j in range(min(q, t)))
                eps[t] = diff[t] - ar_term - ma_term

            if m < 2:
                break

            x_vars = []
            y_dep = []
            for t in range(1, m):
                row = []
                for j in range(p):
                    row.append(diff[t - j - 1])
                for j in range(q):
                    row.append(eps[t - j - 1])
                x_vars.append(row)
                y_dep.append(diff[t])

            k = len(y_dep)
            if k < max(p + q, 1):
                break

            num_params = p + q
            if num_params == 0:
                break

            means = [sum(x_vars[i][j] for i in range(k)) / k for j in range(num_params)]
            y_mean = sum(y_dep) / k

            cov_mat = [[0.0] * num_params for _ in range(num_params)]
            cov_y = [0.0] * num_params
            for i in range(k):
                for a in range(num_params):
                    for b in range(num_params):
                        cov_mat[a][b] += (x_vars[i][a] - means[a]) * (x_vars[i][b] - means[b])
                    cov_y[a] += (x_vars[i][a] - means[a]) * (y_dep[i] - y_mean)

            det = self._determinant(cov_mat, num_params)
            if abs(det) < 1e-12:
                for param_idx in range(num_params):
                    var_val = cov_mat[param_idx][param_idx]
                    if var_val > 1e-12:
                        if param_idx < p:
                            ar_coefs[param_idx] = cov_y[param_idx] / var_val
                        else:
                            ma_coefs[param_idx - p] = cov_y[param_idx] / var_val
                break

            adjugate = self._adjugate_matrix(cov_mat, num_params)
            new_params = []
            for param_idx in range(num_params):
                val = sum(adjugate[param_idx][j] * cov_y[j] for j in range(num_params)) / det
                new_params.append(max(-0.99, min(0.99, val)))

            for j in range(p):
                ar_coefs[j] = new_params[j]
            for j in range(q):
                ma_coefs[j] = new_params[p + j]

            converged = True
            old_all = list(ar_coefs) + list(ma_coefs)
            new_all = new_params
            for old_val, new_val in zip(old_all[:len(new_all)], new_all[:len(old_all)]):
                if abs(old_val - new_val) > tol:
                    converged = False
                    break
            if converged:
                break

        eps_final = [0.0] * m
        for t in range(m):
            ar_term = sum(ar_coefs[j] * diff[t - j - 1] for j in range(min(p, t)))
            ma_term = sum(ma_coefs[j] * eps_final[t - j - 1] for j in range(min(q, t)))
            eps_final[t] = diff[t] - ar_term - ma_term

        residual_var = sum(e ** 2 for e in eps_final) / m if m > 0 else 0
        std_err = math.sqrt(residual_var) if residual_var > 0 else 0

        historical = [{"date": d, "value": v} for d, v in zip(historical_dates, historical_values)]

        predicted = []
        confidence_lower = []
        confidence_upper = []

        try:
            last_date = datetime.strptime(historical_dates[-1], "%Y-%m-%d")
        except (ValueError, IndexError):
            last_date = datetime.now(timezone.utc)

        last_diffs = [diff[-i - 1] for i in range(min(p, len(diff)))]
        last_eps_list = [eps_final[-i - 1] for i in range(min(q, len(eps_final)))]
        last_val = historical_values[-1]

        for h in range(1, forecast_days + 1):
            pred_diff = 0.0
            for j in range(p):
                if h <= j + 1 and j < len(last_diffs):
                    pred_diff += ar_coefs[j] * last_diffs[j]
                elif h > j + 1 and h - 2 - j < len(predicted):
                    prev_pred = predicted[h - 2 - j]["value"]
                    base = predicted[h - 3 - j]["value"] if h >= 3 + j else last_val
                    pred_diff += ar_coefs[j] * (prev_pred - base)

            for j in range(q):
                if h <= j + 1 and j < len(last_eps_list):
                    pred_diff += ma_coefs[j] * last_eps_list[j]

            pred_val = last_val + pred_diff if h == 1 else predicted[-1]["value"] + pred_diff
            pred_val = max(0, pred_val)

            pred_date = (last_date + timedelta(days=h)).strftime("%Y-%m-%d")

            ar_contribution = sum(ar_coefs[j] ** 2 for j in range(p))
            cumulative_var = residual_var * (1 + (h - 1) * ar_contribution) if ar_contribution < 1 else residual_var * h
            margin = 1.96 * math.sqrt(cumulative_var)

            predicted.append({"date": pred_date, "value": round(pred_val, 2)})
            confidence_lower.append({"date": pred_date, "value": round(max(0, pred_val - margin), 2)})
            confidence_upper.append({"date": pred_date, "value": round(pred_val + margin, 2)})

        fitted_diff = [0.0] * m
        for t in range(m):
            ar_term = sum(ar_coefs[j] * diff[t - j - 1] for j in range(min(p, t)))
            ma_term = sum(ma_coefs[j] * eps_final[t - j - 1] for j in range(min(q, t)))
            fitted_diff[t] = ar_term + ma_term

        fitted = [historical_values[0]]
        for _ in range(d):
            fitted = [fitted[0]]
        fitted = [historical_values[0]]
        for t in range(m):
            fitted.append(fitted[-1] + fitted_diff[t])

        ss_res = sum((historical_values[i] - fitted[i]) ** 2 for i in range(n))
        y_mean = sum(historical_values) / n
        ss_tot = sum((v - y_mean) ** 2 for v in historical_values)
        r_squared = 1 - ss_res / ss_tot if ss_tot > 0 else 0

        mape_vals = []
        for i in range(max(1, n - 7), n):
            if abs(historical_values[i]) > 0.001:
                mape_vals.append(abs(historical_values[i] - fitted[i]) / abs(historical_values[i]))
        mape = sum(mape_vals) / len(mape_vals) if mape_vals else 0

        return ForecastResult(
            metric="value",
            historical=historical,
            predicted=predicted,
            confidence_lower=confidence_lower,
            confidence_upper=confidence_upper,
            method=f"arima({p},{d},{q})",
            forecast_days=forecast_days,
            accuracy_metrics={
                "ar_coefficients": [round(c, 4) for c in ar_coefs],
                "ma_coefficients": [round(c, 4) for c in ma_coefs],
                "order": (p, d, q),
                "mape": round(mape, 4),
                "r_squared": round(r_squared, 4),
                "std_error": round(std_err, 4),
            },
        )

    def _determinant(self, matrix, n):
        if n == 1:
            return matrix[0][0]
        if n == 2:
            return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
        det = 0
        for col in range(n):
            minor = [
                [matrix[r][c] for c in range(n) if c != col]
                for r in range(1, n)
            ]
            sign = (-1) ** col
            det += sign * matrix[0][col] * self._determinant(minor, n - 1)
        return det

    def _adjugate_matrix(self, matrix, n):
        cofactors = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                minor = [
                    [matrix[r][c] for c in range(n) if c != j]
                    for r in range(n) if r != i
                ]
                cofactors[i][j] = ((-1) ** (i + j)) * self._determinant(minor, n - 1)
        return [[cofactors[j][i] for j in range(n)] for i in range(n)]

    def evaluate_forecast_accuracy(self, actual: List[float], predicted: List[float]) -> Dict[str, float]:
        n = len(actual)
        if n == 0 or len(predicted) == 0 or n != len(predicted):
            return {"mae": 0.0, "rmse": 0.0, "mape": 0.0, "smape": 0.0, "r_squared": 0.0, "n": 0}

        errors = [a - p for a, p in zip(actual, predicted)]
        abs_errors = [abs(e) for e in errors]
        sq_errors = [e ** 2 for e in errors]

        mae = sum(abs_errors) / n
        rmse = math.sqrt(sum(sq_errors) / n)

        mape_sum = 0.0
        smape_sum = 0.0
        valid_count = 0

        for a, p in zip(actual, predicted):
            if abs(a) > 0.001:
                mape_sum += abs(a - p) / abs(a)
                denom = (abs(a) + abs(p)) / 2
                if denom > 0:
                    smape_sum += abs(a - p) / denom
                valid_count += 1

        mape = mape_sum / valid_count if valid_count > 0 else 0.0
        smape = smape_sum / valid_count if valid_count > 0 else 0.0

        mean_actual = sum(actual) / n if n > 0 else 0.0
        ss_tot = sum((a - mean_actual) ** 2 for a in actual)
        ss_res = sum(e ** 2 for e in errors)
        r_squared = 1 - ss_res / ss_tot if ss_tot > 0 else 0.0

        return {
            "mae": round(mae, 4),
            "rmse": round(rmse, 4),
            "mape": round(mape, 4),
            "smape": round(smape, 4),
            "r_squared": round(r_squared, 4),
            "n": n,
        }


class AnalyticsEngine:
    def __init__(self, llm_service=None):
        self._nl_query = NLQueryEngine()
        self._anomaly_detector = AnomalyDetector()
        self._forecaster = TrendForecaster()
        self._llm = llm_service

    async def parse_natural_language_query(
        self, query: str, context: Optional[Dict] = None, db_session=None
    ) -> Dict[str, Any]:
        try:
            result = await self._nl_query.parse_query(query, db_session)
            result_dict = result.to_dict()
        except Exception as exc:
            logger.warning(f"自然语言查询解析失败: {exc}")
            result_dict = {
                "query": query,
                "sql": "",
                "data": [],
                "chart_type": "bar",
                "chart_config": {},
                "explanation": f"查询解析失败: {exc}",
                "execution_time_ms": 0,
                "total_rows": 0,
            }
        return result_dict

    async def parse_query_with_llm(
        self, query: str, llm_service=None, db_session=None
    ) -> QueryResult:
        return await self._nl_query.parse_query_with_llm(
            query=query, llm_service=llm_service or self._llm, db_session=db_session
        )

    def generate_chart_config(
        self, chart_type: str, data: List[Dict], query: str, industry: str = None
    ) -> Dict[str, Any]:
        return self._nl_query.generate_chart_config(
            chart_type=chart_type, data=data, query=query, industry=industry
        )

    def detect_time_series_anomaly(
        self, values: List[float], timestamps: List[str], window_size: int = 7
    ) -> AnomalyResult:
        return self._anomaly_detector.detect_time_series_anomaly(
            values=values, timestamps=timestamps, window_size=window_size
        )

    def evaluate_forecast_accuracy(
        self, actual: List[float], predicted: List[float]
    ) -> Dict[str, float]:
        return self._forecaster.evaluate_forecast_accuracy(
            actual=actual, predicted=predicted
        )

    async def natural_language_query(
        self, query: str, db_session=None
    ) -> QueryResult:
        return await self._nl_query.parse_query(query, db_session)

    async def recommend_charts(
        self,
        data: List[Dict[str, Any]],
        analysis_type: Optional[str] = None,
        industry: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query_hint = analysis_type or ""
        if data:
            keys = list(data[0].keys()) if data else []
            query_hint += " " + " ".join(keys[:3])

        base_recs = self.recommend_chart(query_hint, {"rows": len(data), "columns": len(data[0].keys()) if data else 0})

        for rec in base_recs:
            if data and rec.get("chart_type") in ("bar", "line", "area", "scatter"):
                keys = list(data[0].keys())
                numeric_keys = [k for k in keys if len(data) > 0 and isinstance(data[0].get(k), (int, float))]
                category_keys = [k for k in keys if k not in numeric_keys]
                if numeric_keys and category_keys:
                    rec["xField"] = category_keys[0]
                    rec["yField"] = numeric_keys[0]
                elif len(keys) >= 2:
                    rec["xField"] = keys[0]
                    rec["yField"] = keys[1]
            elif data and rec.get("chart_type") in ("pie", "donut"):
                keys = list(data[0].keys())
                numeric_keys = [k for k in keys if len(data) > 0 and isinstance(data[0].get(k), (int, float))]
                category_keys = [k for k in keys if k not in numeric_keys]
                if numeric_keys and category_keys:
                    rec["angleField"] = numeric_keys[0]
                    rec["colorField"] = category_keys[0]

        return base_recs

    async def detect_anomalies(
        self,
        data: List[Dict[str, Any]],
        metric_field: str = "value",
        timestamp_field: str = "timestamp",
        sensitivity: float = 1.5,
    ) -> Dict[str, Any]:
        values = []
        timestamps = []
        for item in data:
            val = item.get(metric_field)
            if val is not None:
                try:
                    values.append(float(val))
                except (ValueError, TypeError) as exc:
                    logger.warning(f"异常检测数值转换失败: {exc}")
                    continue
            ts = item.get(timestamp_field, "")
            timestamps.append(str(ts) if ts else "")

        if not values:
            return {
                "metric": metric_field,
                "anomalies": [],
                "algorithm": "none",
                "threshold": sensitivity,
                "total_points": 0,
                "anomaly_count": 0,
            }

        if sensitivity >= 2.5:
            result = self._anomaly_detector.detect_zscore(values, timestamps, threshold=sensitivity)
        elif sensitivity >= 1.0:
            result = self._anomaly_detector.detect_iqr(values, timestamps, multiplier=sensitivity)
        else:
            result = self._anomaly_detector.detect_isolation_forest_simplified(
                values, timestamps, contamination=max(0.01, sensitivity * 0.1)
            )

        try:
            result_dict = result.to_dict()
        except (TypeError, ValueError, OverflowError) as exc:
            logger.warning(f"趋势预测结果序列化失败: {exc}")
            result_dict = {
                "metric": metric_field,
                "historical": [],
                "predicted": [],
                "method": method,
                "forecast_days": periods,
                "accuracy_metrics": {},
                "error": f"结果序列化失败: {exc}",
            }
        return result_dict

    async def predict_trend(
        self,
        data: List[Dict[str, Any]],
        metric_field: str = "value",
        timestamp_field: str = "timestamp",
        periods: int = 7,
        method: str = "auto",
    ) -> Dict[str, Any]:
        values = []
        dates = []
        for item in data:
            val = item.get(metric_field)
            if val is not None:
                try:
                    values.append(float(val))
                except (ValueError, TypeError) as exc:
                    logger.warning(f"趋势预测数值转换失败: {exc}")
                    continue
            ts = item.get(timestamp_field, "")
            dates.append(str(ts) if ts else "")

        if len(values) < 2:
            return {
                "metric": metric_field,
                "historical": [],
                "predicted": [],
                "method": method,
                "periods": periods,
                "accuracy_metrics": {},
                "error": "数据点不足，至少需要2个数据点",
            }

        if method == "exponential_smoothing":
            result = self._forecaster.forecast_exponential_smoothing(values, dates, periods)
        elif method == "linear":
            result = self._forecaster.forecast_linear(values, dates, periods)
        elif method == "arima":
            result = self._forecaster.forecast_arima(values, dates, periods)
        elif method == "prophet":
            if len(values) >= 30:
                result = self._forecaster.forecast_exponential_smoothing(values, dates, periods)
            else:
                result = self._forecaster.forecast_linear(values, dates, periods)
        else:
            if len(values) >= 7:
                recent_trend = values[-1] - values[-7]
                mean_val = sum(values) / len(values) if len(values) > 0 else 0
                if mean_val != 0 and abs(recent_trend) > mean_val * 0.1:
                    result = self._forecaster.forecast_exponential_smoothing(values, dates, periods)
                else:
                    result = self._forecaster.forecast_linear(values, dates, periods)
            else:
                result = self._forecaster.forecast_linear(values, dates, periods)

        return result.to_dict()

    async def get_dashboard_stats(self) -> Dict[str, Any]:
        stats = {
            "total_intelligence": 0,
            "total_entities": 0,
            "total_reports": 0,
            "active_pirs": 0,
            "threat_distribution": {},
            "source_distribution": {},
            "recent_activity": [],
        }

        try:
            from app.db.database import async_session_factory
            from app.db.tables import (
                RawIntelligenceTable,
                CleanedIntelligenceTable,
                EntityTable,
                ReportTable,
                PIRTable,
            )
            from sqlalchemy import select, func

            async with async_session_factory() as session:
                raw_count = await session.execute(select(func.count()).select_from(RawIntelligenceTable))
                stats["total_intelligence"] = raw_count.scalar() or 0

                entity_count = await session.execute(select(func.count()).select_from(EntityTable))
                stats["total_entities"] = entity_count.scalar() or 0

                report_count = await session.execute(select(func.count()).select_from(ReportTable))
                stats["total_reports"] = report_count.scalar() or 0

                pir_count = await session.execute(
                    select(func.count()).select_from(PIRTable).where(PIRTable.status == "active")
                )
                stats["active_pirs"] = pir_count.scalar() or 0

                threat_result = await session.execute(
                    select(CleanedIntelligenceTable.threat_level, func.count())
                    .group_by(CleanedIntelligenceTable.threat_level)
                )
                for row in threat_result.fetchall():
                    stats["threat_distribution"][row[0]] = row[1]

                source_result = await session.execute(
                    select(RawIntelligenceTable.source, func.count())
                    .group_by(RawIntelligenceTable.source)
                    .order_by(func.count().desc())
                    .limit(10)
                )
                for row in source_result.fetchall():
                    stats["source_distribution"][row[0]] = row[1]

                recent_result = await session.execute(
                    select(RawIntelligenceTable)
                    .order_by(RawIntelligenceTable.collected_at.desc())
                    .limit(5)
                )
                for row in recent_result.scalars().all():
                    stats["recent_activity"].append({
                        "id": row.id,
                        "source": row.source,
                        "content_preview": (row.content or "")[:100],
                        "collected_at": row.collected_at.isoformat() if row.collected_at else None,
                    })
        except Exception as exc:
            logger.warning(f"Dashboard stats query failed: {exc}")

        return stats

    def detect_anomalies_sync(
        self,
        values: List[float],
        timestamps: Optional[List[str]] = None,
        algorithm: str = "zscore",
        threshold: float = 2.0,
    ) -> AnomalyResult:
        if not values or len(values) == 0:
            return AnomalyResult(
                metric="value",
                anomalies=[],
                algorithm=algorithm,
                threshold=threshold,
                total_points=0,
                anomaly_count=0,
            )
        if algorithm == "iqr":
            return self._anomaly_detector.detect_iqr(values, timestamps, threshold)
        elif algorithm == "isolation_forest":
            return self._anomaly_detector.detect_isolation_forest_simplified(
                values, timestamps, contamination=threshold
            )
        else:
            return self._anomaly_detector.detect_zscore(values, timestamps, threshold)

    def forecast_trend_sync(
        self,
        values: List[float],
        dates: List[str],
        forecast_days: int = 7,
        method: str = "auto",
    ) -> ForecastResult:
        if not values or len(values) < 2:
            return ForecastResult(
                metric="value",
                historical=[{"date": d, "value": v} for d, v in zip(dates, values)],
                predicted=[],
                confidence_lower=[],
                confidence_upper=[],
                method=method,
                forecast_days=forecast_days,
                accuracy_metrics={},
            )
        if method == "exponential_smoothing":
            return self._forecaster.forecast_exponential_smoothing(values, dates, forecast_days)
        elif method == "linear":
            return self._forecaster.forecast_linear(values, dates, forecast_days)
        elif method == "arima":
            return self._forecaster.forecast_arima(values, dates, forecast_days)
        else:
            if len(values) >= 7:
                recent_trend = values[-1] - values[-7] if len(values) >= 7 else 0
                mean_val = sum(values) / len(values) if len(values) > 0 else 0
                if mean_val != 0 and abs(recent_trend) > mean_val * 0.1:
                    return self._forecaster.forecast_exponential_smoothing(values, dates, forecast_days)
            return self._forecaster.forecast_linear(values, dates, forecast_days)

    def recommend_chart(self, query: str, data_shape: Optional[Dict] = None) -> List[Dict]:
        query_lower = query.lower()
        recommendations = []

        if any(kw in query_lower for kw in ["趋势", "变化", "时间", "trend"]):
            recommendations = [
                {"chart_type": "line", "priority": 1, "reason": "折线图适合展示时间序列趋势"},
                {"chart_type": "area", "priority": 2, "reason": "面积图可突出趋势的累积效果"},
            ]
        elif any(kw in query_lower for kw in ["分布", "占比", "比例", "distribution"]):
            recommendations = [
                {"chart_type": "pie", "priority": 1, "reason": "饼图适合展示各部分占比"},
                {"chart_type": "donut", "priority": 2, "reason": "环形图更清晰展示分类占比"},
            ]
        elif any(kw in query_lower for kw in ["对比", "比较", "compare"]):
            recommendations = [
                {"chart_type": "bar", "priority": 1, "reason": "柱状图适合对比不同类别的数值"},
                {"chart_type": "grouped_bar", "priority": 2, "reason": "分组柱状图可同时对比多个维度"},
            ]
        elif any(kw in query_lower for kw in ["关系", "关联", "relation"]):
            recommendations = [
                {"chart_type": "network", "priority": 1, "reason": "网络图适合展示实体间关系"},
                {"chart_type": "sankey", "priority": 2, "reason": "桑基图适合展示流量流向关系"},
            ]
        elif any(kw in query_lower for kw in ["异常", "anomaly", "离群"]):
            recommendations = [
                {"chart_type": "scatter", "priority": 1, "reason": "散点图适合识别异常值"},
                {"chart_type": "line", "priority": 2, "reason": "折线图可标注异常点"},
            ]
        else:
            recommendations = [
                {"chart_type": "bar", "priority": 1, "reason": "柱状图通用性强"},
                {"chart_type": "table", "priority": 2, "reason": "表格适合精确数值展示"},
            ]

        if data_shape:
            n_rows = data_shape.get("rows", 0)
            if n_rows > 1000:
                recommendations = [
                    {"chart_type": "heatmap", "priority": 0, "reason": "大数据量适合热力图"},
                ] + recommendations

        return recommendations

    async def nl_to_sql(self, query: str, db_session=None) -> Dict:
        import time
        start = time.time()

        if self._llm is None:
            return {
                "query": query,
                "generated_sql": "",
                "results": [],
                "row_count": 0,
                "execution_time_ms": round((time.time() - start) * 1000, 2),
                "error": "LLM服务不可用，无法将自然语言转换为SQL",
            }

        schema_description = """
数据库表结构（黑灰产威胁情报系统）:

1. raw_intelligence (原始情报)
   - id: VARCHAR(64) 主键
   - source: VARCHAR(32) 来源 (darkweb/telegram/forum/wechat/web)
   - source_url: TEXT 来源URL
   - content: TEXT 情报内容
   - raw_content: TEXT 原始内容
   - collected_at: DATETIME 采集时间
   - status: VARCHAR(16) 状态 (raw/cleaned/analyzed)
   - metadata_json: TEXT 元数据JSON

2. cleaned_intelligence (清洗后情报)
   - id: VARCHAR(64) 主键
   - raw_id: VARCHAR(64) 外键→raw_intelligence.id
   - content: TEXT 清洗后内容
   - decoded_content: TEXT 解码内容
   - blacktalk_terms_json: TEXT 黑话术语JSON
   - entities_json: TEXT 实体JSON
   - threat_level: VARCHAR(16) 威胁等级 (critical/high/medium/low/info)
   - cleaned_at: DATETIME 清洗时间

3. analyzed_intelligence (分析后情报)
   - id: VARCHAR(64) 主键
   - cleaned_id: VARCHAR(64) 外键→cleaned_intelligence.id
   - threat_level: VARCHAR(16) 威胁等级
   - threat_categories_json: TEXT 威胁分类JSON
   - attack_patterns_json: TEXT 攻击模式JSON
   - technique_chain_json: TEXT 技术链JSON
   - confidence_score: FLOAT 置信度 (0-1)
   - analysis_summary: TEXT 分析摘要
   - evidence_refs_json: TEXT 证据引用JSON
   - analyzed_at: DATETIME 分析时间

4. entity (实体)
   - id: VARCHAR(64) 主键
   - type: VARCHAR(32) 类型 (ip/domain/url/phone/email/crypto_address/account/tool/organization)
   - value: VARCHAR(512) 值
   - context: TEXT 上下文
   - source_ids_json: TEXT 来源ID JSON
   - confidence: FLOAT 置信度
   - first_seen: DATETIME 首次发现
   - last_seen: DATETIME 最近发现

5. report (报告)
   - id: VARCHAR(64) 主键
   - title: VARCHAR(256) 标题
   - pir_id: VARCHAR(64) 外键→pir.id
   - status: VARCHAR(16) 状态 (draft/published/archived)
   - summary: TEXT 摘要
   - key_findings_json: TEXT 关键发现JSON
   - threat_actors_json: TEXT 威胁行为者JSON
   - iocs_json: TEXT IoC指标JSON
   - attack_chains_json: TEXT 攻击链JSON
   - recommendations_json: TEXT 建议措施JSON
   - confidence_score: FLOAT 置信度
   - author: VARCHAR(128) 作者
   - created_at: DATETIME 创建时间
   - published_at: DATETIME 发布时间

6. pir (情报需求)
   - id: VARCHAR(64) 主键
   - title: VARCHAR(256) 标题
   - description: TEXT 描述
   - priority: VARCHAR(16) 优先级 (critical/high/medium/low)
   - status: VARCHAR(16) 状态 (active/fulfilled/closed)
   - keywords_json: TEXT 关键词JSON
   - target_sources_json: TEXT 目标来源JSON
   - created_at: DATETIME 创建时间
   - fulfilled_at: DATETIME 完成时间

7. qa_conversations (问答对话)
   - id: VARCHAR(64) 主键
   - title: VARCHAR(256) 标题
   - messages_json: TEXT 消息JSON
   - industry: VARCHAR(32) 行业
   - rag_enabled: BOOLEAN 是否启用RAG
   - model_id: VARCHAR(128) 模型ID
   - conversation_type: VARCHAR(32) 对话类型
   - is_active: BOOLEAN 是否活跃
   - created_at: DATETIME 创建时间

8. generated_contents (生成内容)
   - id: VARCHAR(64) 主键
   - title: VARCHAR(256) 标题
   - content_type: VARCHAR(32) 内容类型
   - content: TEXT 内容
   - review_status: VARCHAR(16) 审核状态 (pending/approved/rejected)
   - reviewer: VARCHAR(128) 审核人
   - model_id: VARCHAR(128) 模型ID
   - prompt_template_id: VARCHAR(64) 提示词模板ID
   - created_at: DATETIME 创建时间

9. industry_scene_configs (行业场景配置)
   - id: VARCHAR(64) 主键
   - industry: VARCHAR(32) 行业
   - name: VARCHAR(256) 名称
   - config_json: TEXT 配置JSON
   - is_active: BOOLEAN 是否启用
   - description: TEXT 描述
   - created_at: DATETIME 创建时间

10. prompt_templates (提示词模板)
    - id: VARCHAR(64) 主键
    - name: VARCHAR(256) 名称
    - description: TEXT 描述
    - category: VARCHAR(32) 分类
    - content: TEXT 模板内容
    - variables_json: TEXT 变量JSON
    - version: INTEGER 版本
    - is_active: BOOLEAN 是否启用
    - tags_json: TEXT 标签JSON
    - created_at: DATETIME 创建时间

11. preprocess_tasks (预处理任务)
    - id: VARCHAR(64) 主键
    - name: VARCHAR(256) 名称
    - task_type: VARCHAR(32) 任务类型
    - status: VARCHAR(16) 状态 (pending/running/completed/failed)
    - config_json: TEXT 配置JSON
    - progress: FLOAT 进度
    - error_message: TEXT 错误信息
    - created_at: DATETIME 创建时间

12. finetune_tasks (微调任务)
    - id: VARCHAR(64) 主键
    - name: VARCHAR(256) 名称
    - method: VARCHAR(16) 方法
    - base_model: VARCHAR(256) 基础模型
    - status: VARCHAR(16) 状态 (pending/running/completed/failed)
    - progress: FLOAT 进度
    - metrics_json: TEXT 指标JSON
    - created_at: DATETIME 创建时间

13. analytics_results (分析结果)
    - id: VARCHAR(64) 主键
    - query_type: VARCHAR(32) 查询类型
    - query_text: TEXT 查询文本
    - result_json: TEXT 结果JSON
    - chart_config_json: TEXT 图表配置JSON
    - anomalies_json: TEXT 异常JSON
    - prediction_json: TEXT 预测JSON
    - created_at: DATETIME 创建时间

14. anomaly_records (异常记录)
    - id: VARCHAR(64) 主键
    - metric: VARCHAR(64) 指标
    - anomaly_type: VARCHAR(32) 异常类型
    - severity: VARCHAR(16) 严重程度 (critical/high/medium/low)
    - value: FLOAT 实际值
    - expected_value: FLOAT 期望值
    - deviation: FLOAT 偏差
    - detected_at: DATETIME 检测时间
    - acknowledged: BOOLEAN 是否确认

15. dashboard_configs (仪表盘配置)
    - id: VARCHAR(64) 主键
    - name: VARCHAR(256) 名称
    - description: TEXT 描述
    - layout_json: TEXT 布局JSON
    - widgets_json: TEXT 组件JSON
    - industry: VARCHAR(32) 行业
    - refresh_interval: INTEGER 刷新间隔(秒)
    - is_active: BOOLEAN 是否启用
    - created_at: DATETIME 创建时间
"""

        system_prompt = (
            "你是一个SQL生成专家，专门为黑灰产威胁情报系统生成SQL查询。\n"
            "规则:\n"
            "1. 只生成SELECT查询语句，严禁生成INSERT/UPDATE/DELETE/DROP/ALTER等修改数据的语句\n"
            "2. 只返回纯SQL语句，不要任何解释、注释或Markdown格式\n"
            "3. 使用SQLite兼容的SQL语法\n"
            "4. 日期函数使用DATE()和DATETIME()\n"
            "5. 如果无法理解查询，返回空字符串\n"
            "6. 合理使用JOIN关联表，但不要过度关联\n"
            "7. 对文本字段使用LIKE进行模糊匹配\n"
            "8. 对JSON字段使用LIKE进行简单搜索\n"
        )

        prompt = f"{schema_description}\n\n用户查询: {query}\n\n请生成对应的SQL查询语句:"

        try:
            llm_response = await self._llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_ANALYSIS,
                max_tokens=settings.LLM_MAX_TOKENS_MEDIUM,
            )
            if not isinstance(llm_response, str):
                llm_response = str(llm_response) if llm_response is not None else ""
            generated_sql = llm_response.strip()

            if generated_sql.startswith("```"):
                generated_sql = re.sub(r'^```\w*\n?', '', generated_sql)
                generated_sql = re.sub(r'\n?```$', '', generated_sql)
            generated_sql = generated_sql.strip()

            sql_upper = generated_sql.upper().strip()
            if not sql_upper.startswith("SELECT"):
                return {
                    "query": query,
                    "generated_sql": generated_sql,
                    "results": [],
                    "row_count": 0,
                    "execution_time_ms": round((time.time() - start) * 1000, 2),
                    "error": "生成的SQL不是SELECT语句，已拦截",
                }

            forbidden_patterns = [
                r";\s*DROP\s", r";\s*DELETE\s", r";\s*UPDATE\s", r";\s*INSERT\s",
                r";\s*ALTER\s", r";\s*CREATE\s", r";\s*TRUNCATE\s",
                r"UNION\s+SELECT", r"--\s*$", r"/\*", r"\*/",
                r"xp_cmdshell", r"INTO\s+OUTFILE", r"LOAD_FILE",
                r"INFORMATION_SCHEMA",
            ]
            for pattern in forbidden_patterns:
                if re.search(pattern, generated_sql, re.IGNORECASE):
                    logger.warning(f"SQL注入风险检测: {generated_sql}")
                    return {
                        "query": query,
                        "generated_sql": generated_sql,
                        "results": [],
                        "row_count": 0,
                        "execution_time_ms": round((time.time() - start) * 1000, 2),
                        "error": "检测到SQL注入风险，查询已拦截",
                    }

            results = []
            row_count = 0

            if db_session:
                try:
                    results = await _execute_safe_sql(db_session, generated_sql)
                    row_count = len(results)
                except ValueError as exc:
                    logger.warning(f"nl_to_sql安全校验失败: {exc}")
                    return {
                        "query": query,
                        "generated_sql": generated_sql,
                        "results": [],
                        "row_count": 0,
                        "execution_time_ms": round((time.time() - start) * 1000, 2),
                        "error": f"SQL安全校验失败: {exc}",
                    }
                except Exception as exc:
                    logger.warning(f"nl_to_sql执行失败: {exc}")
                    return {
                        "query": query,
                        "generated_sql": generated_sql,
                        "results": [],
                        "row_count": 0,
                        "execution_time_ms": round((time.time() - start) * 1000, 2),
                        "error": "SQL执行失败，请稍后重试",
                    }

            return {
                "query": query,
                "generated_sql": generated_sql,
                "results": results[:500],
                "row_count": row_count,
                "execution_time_ms": round((time.time() - start) * 1000, 2),
            }
        except Exception as exc:
            logger.error(f"nl_to_sql LLM调用失败: {exc}")
            return {
                "query": query,
                "generated_sql": "",
                "results": [],
                "row_count": 0,
                "execution_time_ms": round((time.time() - start) * 1000, 2),
                "error": "LLM调用失败，请稍后重试",
            }

    async def generate_data_insight(self, data: List[Dict], query: str) -> Dict:
        if self._llm is None:
            return {
                "insight": "LLM服务不可用，无法生成数据洞察",
                "key_points": [],
                "data_summary": {"total_rows": len(data), "columns": list(data[0].keys()) if data else []},
                "recommendations": [],
            }

        max_data_chars = 8000
        try:
            data_str = json.dumps(data, ensure_ascii=False, default=str)
        except (TypeError, ValueError, OverflowError) as exc:
            logger.warning(f"数据序列化失败: {exc}")
            data_str = str(data)[:max_data_chars]
        if len(data_str) > max_data_chars:
            truncated = data[:50]
            try:
                data_str = json.dumps(truncated, ensure_ascii=False, default=str)
            except (TypeError, ValueError, OverflowError):
                data_str = str(truncated)[:max_data_chars]
            if len(data_str) > max_data_chars:
                truncated = data[:20]
                try:
                    data_str = json.dumps(truncated, ensure_ascii=False, default=str)
                except (TypeError, ValueError, OverflowError):
                    data_str = str(truncated)[:max_data_chars]
            data_str += f"\n... (共{len(data)}条数据，已截断显示)"

        system_prompt = (
            "你是一个黑灰产威胁情报数据分析专家。根据用户提供的查询和数据，生成深入的数据洞察。\n"
            "请严格按以下JSON格式返回，不要添加其他内容：\n"
            "{\n"
            '  "insight": "整体洞察总结(200字内)",\n'
            '  "key_points": ["关键发现1", "关键发现2", "关键发现3"],\n'
            '  "data_summary": {"total_rows": 数字, "columns": ["列名"], "value_range": "数值范围描述"},\n'
            '  "recommendations": ["建议1", "建议2"]\n'
            "}"
        )

        prompt = f"用户查询: {query}\n\n数据结果:\n{data_str}\n\n请分析以上数据并生成洞察:"

        try:
            llm_response = await self._llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
                max_tokens=settings.LLM_MAX_TOKENS_LONG,
            )
            response_text = llm_response.strip()

            if response_text.startswith("```"):
                response_text = re.sub(r'^```\w*\n?', '', response_text)
                response_text = re.sub(r'\n?```$', '', response_text)
                response_text = response_text.strip()

            try:
                parsed = json.loads(response_text)
                return {
                    "insight": parsed.get("insight", ""),
                    "key_points": parsed.get("key_points", []),
                    "data_summary": parsed.get("data_summary", {"total_rows": len(data), "columns": list(data[0].keys()) if data else []}),
                    "recommendations": parsed.get("recommendations", []),
                }
            except json.JSONDecodeError:
                return {
                    "insight": response_text[:500],
                    "key_points": [],
                    "data_summary": {"total_rows": len(data), "columns": list(data[0].keys()) if data else []},
                    "recommendations": [],
                }
        except Exception as exc:
            logger.error(f"generate_data_insight LLM调用失败: {exc}")
            return {
                "insight": "洞察生成失败，请稍后重试",
                "key_points": [],
                "data_summary": {"total_rows": len(data), "columns": list(data[0].keys()) if data else []},
                "recommendations": [],
            }
