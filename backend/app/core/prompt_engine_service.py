import json
import math
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


@dataclass
class PromptExecutionResult:
    template_id: str
    rendered_prompt: str
    llm_response: str
    latency_ms: float
    tokens_used: int
    success: bool
    error_message: Optional[str] = None
    timestamp: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "template_id": self.template_id,
            "rendered_prompt": self.rendered_prompt[:500],
            "llm_response": self.llm_response[:500],
            "latency_ms": round(self.latency_ms, 2),
            "tokens_used": self.tokens_used,
            "success": self.success,
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class ABTestResult:
    test_id: str
    template_a_id: str
    template_b_id: str
    sample_size_a: int
    sample_size_b: int
    success_rate_a: float
    success_rate_b: float
    avg_latency_a: float
    avg_latency_b: float
    avg_tokens_a: float
    avg_tokens_b: float
    p_value: float
    is_significant: bool
    confidence_level: float
    winner: Optional[str] = None
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            "test_id": self.test_id,
            "template_a_id": self.template_a_id,
            "template_b_id": self.template_b_id,
            "sample_size_a": self.sample_size_a,
            "sample_size_b": self.sample_size_b,
            "success_rate_a": round(self.success_rate_a, 4),
            "success_rate_b": round(self.success_rate_b, 4),
            "avg_latency_a": round(self.avg_latency_a, 2),
            "avg_latency_b": round(self.avg_latency_b, 2),
            "avg_tokens_a": round(self.avg_tokens_a, 2),
            "avg_tokens_b": round(self.avg_tokens_b, 2),
            "p_value": round(self.p_value, 6),
            "is_significant": self.is_significant,
            "confidence_level": self.confidence_level,
            "winner": self.winner,
            "recommendation": self.recommendation,
        }


class PromptExecutionEngine:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._execution_history: Dict[str, List[PromptExecutionResult]] = defaultdict(list)
        self._max_history_per_template = 1000
        self._max_templates = 100

    async def execute_prompt(
        self,
        template_content: str,
        variables: Dict[str, Any],
        template_id: str = "",
        llm_override=None,
        timeout: float = 60.0,
    ) -> PromptExecutionResult:
        rendered = self._render_template(template_content, variables)
        llm = llm_override or self._llm
        start = datetime.now(timezone.utc)

        if not llm:
            return PromptExecutionResult(
                template_id=template_id,
                rendered_prompt=rendered,
                llm_response="",
                latency_ms=0,
                tokens_used=0,
                success=False,
                error_message="LLM服务未配置",
                timestamp=start,
            )

        try:
            import asyncio
            response = await asyncio.wait_for(
                llm.chat(rendered),
                timeout=timeout,
            )
            end = datetime.now(timezone.utc)
            latency = (end - start).total_seconds() * 1000

            tokens_used = 0
            llm_text = ""
            if isinstance(response, dict):
                llm_text = response.get("content", response.get("text", str(response)))
                tokens_used = response.get("usage", {}).get("total_tokens", 0)
            elif isinstance(response, str):
                llm_text = response
            else:
                llm_text = str(response)

            result = PromptExecutionResult(
                template_id=template_id,
                rendered_prompt=rendered,
                llm_response=llm_text,
                latency_ms=latency,
                tokens_used=tokens_used,
                success=True,
                timestamp=start,
            )
        except asyncio.TimeoutError:
            end = datetime.now(timezone.utc)
            result = PromptExecutionResult(
                template_id=template_id,
                rendered_prompt=rendered,
                llm_response="",
                latency_ms=(end - start).total_seconds() * 1000,
                tokens_used=0,
                success=False,
                error_message=f"LLM调用超时({timeout}s)",
                timestamp=start,
            )
        except Exception as exc:
            end = datetime.now(timezone.utc)
            result = PromptExecutionResult(
                template_id=template_id,
                rendered_prompt=rendered,
                llm_response="",
                latency_ms=(end - start).total_seconds() * 1000,
                tokens_used=0,
                success=False,
                error_message="LLM调用失败",
                timestamp=start,
            )

        if template_id:
            self._execution_history[template_id].append(result)
            if len(self._execution_history[template_id]) > self._max_history_per_template:
                self._execution_history[template_id] = self._execution_history[template_id][-self._max_history_per_template:]
            if len(self._execution_history) > self._max_templates:
                oldest_key = next(iter(self._execution_history))
                del self._execution_history[oldest_key]

        return result

    def _render_template(self, content: str, variables: Dict[str, Any]) -> str:
        result = content

        default_pattern = r"\{\{(\w+)\s*\|\s*default\(['\"]([^'\"]*)['\"]\)\}\}"
        for match in re.finditer(default_pattern, result):
            var_name = match.group(1)
            default_val = match.group(2)
            if var_name in variables and variables[var_name] is not None:
                result = result.replace(match.group(0), str(variables[var_name]))
            else:
                result = result.replace(match.group(0), default_val)

        conditional_pattern = r"\{%\s*if\s+(\w+)\s*%\}(.*?)\{%\s*endif\s*%\}"
        def _replace_conditional(m):
            var_name = m.group(1)
            body = m.group(2)
            if var_name in variables and variables[var_name]:
                return body
            return ""
        result = re.sub(conditional_pattern, _replace_conditional, result, flags=re.DOTALL)

        conditional_else_pattern = r"\{%\s*if\s+(\w+)\s*%\}(.*?)\{%\s*else\s*%\}(.*?)\{%\s*endif\s*%\}"
        def _replace_conditional_else(m):
            var_name = m.group(1)
            if_body = m.group(2)
            else_body = m.group(3)
            if var_name in variables and variables[var_name]:
                return if_body
            return else_body
        result = re.sub(conditional_else_pattern, _replace_conditional_else, result, flags=re.DOTALL)

        for key, value in variables.items():
            pattern = "{{" + re.escape(key) + "}}"
            result = re.sub(pattern, str(value), result)

        remaining = re.findall(r"\{\{(\w+)(?:\s*\|\s*default\([^)]*\))?\}\}", result)
        if remaining:
            logger.warning(f"未填充的变量: {remaining}")

        return result

    def render_template_advanced(self, content: str, variables: Dict[str, Any]) -> Tuple[str, List[str]]:
        import re as _re
        warnings = []
        result = content

        def replace_conditional(match):
            var_name = match.group(1)
            body = match.group(2)
            val = variables.get(var_name)
            if val:
                return body
            return ""
        result = _re.sub(r'\{\{#if\s+(\w+)\}\}(.*?)\{\{/if\}\}', replace_conditional, result, flags=_re.DOTALL)

        def replace_nested(match):
            path = match.group(1)
            parts = path.split('.')
            val = variables
            for part in parts:
                if isinstance(val, dict):
                    val = val.get(part)
                else:
                    val = None
                    break
            if val is None:
                warnings.append(f"嵌套变量 {path} 未找到")
                return f"{{{{{path}}}}}"
            return str(val)
        result = _re.sub(r'\{\{(\w+\.\w+)\}\}', replace_nested, result)

        def replace_default(match):
            var_name = match.group(1)
            default_val = match.group(2)
            val = variables.get(var_name, default_val)
            return str(val)
        result = _re.sub(r'\{\{(\w+)\|default:([^}]+)\}\}', replace_default, result)

        def replace_simple(match):
            var_name = match.group(1)
            val = variables.get(var_name)
            if val is None:
                warnings.append(f"变量 {var_name} 未填充")
                return f"{{{{{var_name}}}}}"
            return str(val)
        result = _re.sub(r'\{\{(\w+)\}\}', replace_simple, result)

        return result, warnings

    def compute_version_diff(self, content_v1: str, content_v2: str, vars_v1: Dict = None, vars_v2: Dict = None) -> Dict[str, Any]:
        import difflib

        try:
            lines_v1 = content_v1.splitlines(keepends=True)
            lines_v2 = content_v2.splitlines(keepends=True)

            diff = difflib.unified_diff(lines_v1, lines_v2, fromfile="v1", tofile="v2", lineterm="")
            diff_text = "".join(diff)

            added = sum(1 for line in diff_text.splitlines() if line.startswith("+") and not line.startswith("+++"))
            removed = sum(1 for line in diff_text.splitlines() if line.startswith("-") and not line.startswith("---"))

            vars_v1 = vars_v1 or {}
            vars_v2 = vars_v2 or {}
            vars_added = set(vars_v2.keys()) - set(vars_v1.keys())
            vars_removed = set(vars_v1.keys()) - set(vars_v2.keys())
            vars_common = set(vars_v1.keys()) & set(vars_v2.keys())
            vars_changed = {k for k in vars_common if vars_v1.get(k) != vars_v2.get(k)}

            similarity = difflib.SequenceMatcher(None, content_v1, content_v2).ratio()

            return {
                "diff_text": diff_text,
                "lines_added": added,
                "lines_removed": removed,
                "similarity": round(similarity, 4),
                "variables_added": list(vars_added),
                "variables_removed": list(vars_removed),
                "variables_changed": list(vars_changed),
                "is_minor_change": similarity > 0.9,
                "is_major_change": similarity < 0.5,
            }
        except Exception as exc:
            logger.warning(f"版本差异计算失败: {exc}")
            return {
                "diff_text": "",
                "lines_added": 0,
                "lines_removed": 0,
                "similarity": 0.0,
                "variables_added": [],
                "variables_removed": [],
                "variables_changed": [],
                "is_minor_change": False,
                "is_major_change": False,
                "error": "版本差异计算失败",
            }

    def get_execution_stats(self, template_id: str) -> Dict[str, Any]:
        history = self._execution_history.get(template_id, [])
        if not history:
            return {"template_id": template_id, "total_executions": 0}

        total = len(history)
        successes = [r for r in history if r.success]
        failures = [r for r in history if not r.success]

        latencies = [r.latency_ms for r in successes]
        tokens = [r.tokens_used for r in successes]

        return {
            "template_id": template_id,
            "total_executions": total,
            "success_count": len(successes),
            "failure_count": len(failures),
            "success_rate": round(len(successes) / total, 4) if total > 0 else 0,
            "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0,
            "p95_latency_ms": round(self._percentile(latencies, 95), 2) if latencies else 0,
            "avg_tokens": round(sum(tokens) / len(tokens), 2) if tokens else 0,
            "last_execution": history[-1].timestamp.isoformat() if history[-1].timestamp else None,
        }

    def get_execution_history(
        self, template_id: str, limit: int = 50, offset: int = 0
    ) -> List[Dict]:
        history = self._execution_history.get(template_id, [])
        page = history[-(offset + limit):len(history) - offset] if offset > 0 else history[-limit:]
        return [r.to_dict() for r in reversed(page)]

    @staticmethod
    def _percentile(data: List[float], pct: int) -> float:
        if not data:
            return 0.0
        sorted_data = sorted(data)
        idx = (pct / 100) * (len(sorted_data) - 1)
        lower = int(idx)
        upper = min(lower + 1, len(sorted_data) - 1)
        frac = idx - lower
        return sorted_data[lower] * (1 - frac) + sorted_data[upper] * frac


class ABTestAnalyzer:
    def __init__(self, execution_engine: PromptExecutionEngine):
        self._engine = execution_engine
        self._test_results: Dict[str, ABTestResult] = {}
        self._max_test_results = 50

    def analyze_test(
        self,
        test_id: str,
        template_a_id: str,
        template_b_id: str,
        confidence_level: float = 0.95,
    ) -> ABTestResult:
        stats_a = self._engine.get_execution_stats(template_a_id)
        stats_b = self._engine.get_execution_stats(template_b_id)

        n_a = stats_a.get("total_executions", 0)
        n_b = stats_b.get("total_executions", 0)
        p_a = stats_a.get("success_rate", 0)
        p_b = stats_b.get("success_rate", 0)

        p_value = self._two_proportion_z_test(n_a, p_a, n_b, p_b)
        is_significant = p_value < (1 - confidence_level)

        winner = None
        recommendation = ""
        if is_significant:
            if p_a > p_b:
                winner = template_a_id
                recommendation = f"模板A成功率({p_a:.2%})显著高于模板B({p_b:.2%})，建议采用模板A"
            else:
                winner = template_b_id
                recommendation = f"模板B成功率({p_b:.2%})显著高于模板A({p_a:.2%})，建议采用模板B"
        else:
            recommendation = f"差异不显著(p={p_value:.4f})，建议继续收集数据或根据其他指标(延迟/Token)决策"

        latency_a = stats_a.get("avg_latency_ms", 0)
        latency_b = stats_b.get("avg_latency_ms", 0)
        if not is_significant and latency_a > 0 and latency_b > 0:
            if latency_a < latency_b * 0.8:
                recommendation += f"；模板A延迟({latency_a:.0f}ms)明显优于模板B({latency_b:.0f}ms)"
            elif latency_b < latency_a * 0.8:
                recommendation += f"；模板B延迟({latency_b:.0f}ms)明显优于模板A({latency_a:.0f}ms)"

        result = ABTestResult(
            test_id=test_id,
            template_a_id=template_a_id,
            template_b_id=template_b_id,
            sample_size_a=n_a,
            sample_size_b=n_b,
            success_rate_a=p_a,
            success_rate_b=p_b,
            avg_latency_a=latency_a,
            avg_latency_b=latency_b,
            avg_tokens_a=stats_a.get("avg_tokens", 0),
            avg_tokens_b=stats_b.get("avg_tokens", 0),
            p_value=p_value,
            is_significant=is_significant,
            confidence_level=confidence_level,
            winner=winner,
            recommendation=recommendation,
        )
        self._test_results[test_id] = result
        if len(self._test_results) > self._max_test_results:
            oldest_key = next(iter(self._test_results))
            del self._test_results[oldest_key]
        return result

    def get_test_result(self, test_id: str) -> Optional[ABTestResult]:
        return self._test_results.get(test_id)

    def allocate_traffic(self, template_a_id: str, template_b_id: str, ratio: float = 0.5, strategy: str = "balanced") -> Dict[str, Any]:
        import hashlib
        import random

        if strategy == "balanced":
            traffic_a = ratio
            traffic_b = 1.0 - ratio
        elif strategy == "revenue_optimized":
            stats_a = self._engine.get_execution_stats(template_a_id)
            stats_b = self._engine.get_execution_stats(template_b_id)
            sr_a = stats_a.get("success_rate", 0.5)
            sr_b = stats_b.get("success_rate", 0.5)
            total_sr = sr_a + sr_b
            if total_sr > 0:
                traffic_a = sr_a / total_sr
                traffic_b = sr_b / total_sr
            else:
                traffic_a = 0.5
                traffic_b = 0.5
        elif strategy == "bayesian":
            stats_a = self._engine.get_execution_stats(template_a_id)
            stats_b = self._engine.get_execution_stats(template_b_id)
            n_a = stats_a.get("total_executions", 0)
            n_b = stats_b.get("total_executions", 0)
            s_a = stats_a.get("success_count", 0)
            s_b = stats_b.get("success_count", 0)
            alpha_a = s_a + 1
            beta_a = n_a - s_a + 1
            alpha_b = s_b + 1
            beta_b = n_b - s_b + 1
            samples_a = [random.betavariate(alpha_a, beta_a) for _ in range(1000)]
            samples_b = [random.betavariate(alpha_b, beta_b) for _ in range(1000)]
            wins_a = sum(1 for a, b in zip(samples_a, samples_b) if a > b)
            traffic_a = wins_a / 1000
            traffic_b = 1.0 - traffic_a
        else:
            traffic_a = 0.5
            traffic_b = 0.5

        return {
            "template_a_id": template_a_id,
            "template_b_id": template_b_id,
            "traffic_a": round(traffic_a, 4),
            "traffic_b": round(traffic_b, 4),
            "strategy": strategy,
            "routing_function": "hash_based",
        }

    def route_request(self, template_a_id: str, template_b_id: str, user_id: str = "", allocation: Dict = None) -> str:
        import hashlib

        if allocation is None:
            allocation = self.allocate_traffic(template_a_id, template_b_id)

        traffic_a = allocation.get("traffic_a", 0.5)

        if user_id:
            hash_val = int(hashlib.sha256(user_id.encode()).hexdigest(), 16) % 10000
            threshold = int(traffic_a * 10000)
            return template_a_id if hash_val < threshold else template_b_id
        else:
            return template_a_id if secrets.randbelow(10000) / 10000 < traffic_a else template_b_id

    @staticmethod
    def _two_proportion_z_test(n1: int, p1: float, n2: int, p2: float) -> float:
        if n1 < 2 or n2 < 2:
            return 1.0

        p_pool = (p1 * n1 + p2 * n2) / (n1 + n2)
        if p_pool <= 0 or p_pool >= 1:
            return 1.0

        se = math.sqrt(p_pool * (1 - p_pool) * (1 / n1 + 1 / n2))
        if se <= 0:
            return 1.0

        z = abs(p1 - p2) / se

        p_value = 2 * (1 - _normal_cdf(z))
        return max(0, min(1, p_value))


def _normal_cdf(x: float) -> float:
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


class PromptOptimizer:
    def __init__(self, execution_engine: PromptExecutionEngine, llm_service=None):
        self._engine = execution_engine
        self._llm = llm_service

    async def suggest_improvements(self, template_id: str, template_content: str) -> List[Dict[str, Any]]:
        stats = self._engine.get_execution_stats(template_id)
        suggestions = []

        success_rate = stats.get("success_rate", 0)
        avg_latency = stats.get("avg_latency_ms", 0)
        total = stats.get("total_executions", 0)

        if total < 10:
            suggestions.append({
                "type": "data_collection",
                "priority": "high",
                "message": f"执行次数不足({total}次)，建议至少收集30次执行结果后再优化",
            })
            return suggestions

        if success_rate < 0.8:
            suggestions.append({
                "type": "reliability",
                "priority": "high",
                "message": f"成功率偏低({success_rate:.1%})，建议检查提示词清晰度和变量完整性",
                "action": "review_prompt_clarity",
            })

        if avg_latency > 5000:
            suggestions.append({
                "type": "performance",
                "priority": "medium",
                "message": f"平均延迟较高({avg_latency:.0f}ms)，建议精简提示词长度或减少输出要求",
                "action": "reduce_prompt_length",
            })

        var_count = len(re.findall(r"\{\{(\w+)\}\}", template_content))
        if var_count > 8:
            suggestions.append({
                "type": "complexity",
                "priority": "medium",
                "message": f"变量数量较多({var_count}个)，可能导致LLM混淆，建议拆分为多步提示词",
                "action": "split_prompt",
            })

        if len(template_content) > 3000:
            suggestions.append({
                "type": "length",
                "priority": "low",
                "message": f"提示词较长({len(template_content)}字符)，可能增加Token消耗和延迟",
                "action": "condense_prompt",
            })

        if self._llm and total >= 20:
            try:
                optimization_prompt = (
                    f"分析以下提示词模板的执行统计并提出优化建议：\n"
                    f"成功率: {success_rate:.1%}\n"
                    f"平均延迟: {avg_latency:.0f}ms\n"
                    f"执行次数: {total}\n"
                    f"提示词内容:\n{template_content[:1000]}\n\n"
                    f"请给出3条具体的优化建议，每条包含type和suggestion字段。"
                )
                response = await self._llm.chat(optimization_prompt)
                if isinstance(response, dict):
                    llm_text = response.get("content", "")
                elif isinstance(response, str):
                    llm_text = response
                else:
                    llm_text = str(response)

                if llm_text:
                    suggestions.append({
                        "type": "llm_analysis",
                        "priority": "info",
                        "message": llm_text[:500],
                        "action": "llm_suggested",
                    })
            except Exception as exc:
                logger.warning(f"LLM优化建议生成失败: {exc}")

        return suggestions

    def compare_versions(
        self, template_id_v1: str, template_id_v2: str
    ) -> Dict[str, Any]:
        stats_v1 = self._engine.get_execution_stats(template_id_v1)
        stats_v2 = self._engine.get_execution_stats(template_id_v2)

        return {
            "version_a": stats_v1,
            "version_b": stats_v2,
            "success_rate_delta": round(
                stats_v2.get("success_rate", 0) - stats_v1.get("success_rate", 0), 4
            ),
            "latency_delta_ms": round(
                stats_v2.get("avg_latency_ms", 0) - stats_v1.get("avg_latency_ms", 0), 2
            ),
            "token_delta": round(
                stats_v2.get("avg_tokens", 0) - stats_v1.get("avg_tokens", 0), 2
            ),
        }
