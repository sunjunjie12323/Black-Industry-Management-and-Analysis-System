import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from loguru import logger


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class PerformanceMonitor:
    def __init__(self, window_seconds: int = 300, max_samples: int = 10000):
        self._window_seconds = window_seconds
        self._max_samples = max_samples
        self._request_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_samples))
        self._error_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_samples))
        self._request_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_samples))
        self._start_time = time.time()
        self._total_requests = 0
        self._total_errors = 0
        self._active_requests = 0

    def record_request(self, endpoint: str, latency_ms: float, status_code: int):
        duration = latency_ms / 1000.0
        is_error = status_code >= 400
        now = time.time()
        self._request_times[endpoint].append((now, duration))
        self._request_counts[endpoint].append(now)
        if is_error:
            self._error_counts[endpoint].append(now)
            self._total_errors += 1
        self._total_requests += 1

    def start_request(self):
        self._active_requests += 1

    def end_request(self):
        self._active_requests = max(0, self._active_requests - 1)

    def _percentile(self, values: List[float], p: float) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        idx = max(0, int(len(sorted_vals) * p / 100.0) - 1)
        return sorted_vals[idx]

    def _get_recent(self, data: deque, window: float) -> List:
        cutoff = time.time() - window
        return [v for v in data if isinstance(v, tuple) and v[0] >= cutoff] if data and isinstance(data[0], tuple) else [v for v in data if v >= cutoff]

    def get_endpoint_metrics(self, endpoint: str) -> Dict[str, Any]:
        window = self._window_seconds
        cutoff = time.time() - window

        recent_times = [(ts, dur) for ts, dur in self._request_times.get(endpoint, []) if ts >= cutoff]
        durations = [dur for _, dur in recent_times]

        recent_reqs = [ts for ts in self._request_counts.get(endpoint, []) if ts >= cutoff]
        recent_errs = [ts for ts in self._error_counts.get(endpoint, []) if ts >= cutoff]

        qps = len(recent_reqs) / window if window > 0 else 0.0
        error_rate = len(recent_errs) / len(recent_reqs) if recent_reqs else 0.0

        return {
            "endpoint": endpoint,
            "request_count": len(recent_reqs),
            "error_count": len(recent_errs),
            "qps": round(qps, 2),
            "error_rate": round(error_rate, 4),
            "response_time_ms": {
                "p50": round(self._percentile(durations, 50) * 1000, 2) if durations else 0.0,
                "p95": round(self._percentile(durations, 95) * 1000, 2) if durations else 0.0,
                "p99": round(self._percentile(durations, 99) * 1000, 2) if durations else 0.0,
                "avg": round(sum(durations) / len(durations) * 1000, 2) if durations else 0.0,
                "max": round(max(durations) * 1000, 2) if durations else 0.0,
                "min": round(min(durations) * 1000, 2) if durations else 0.0,
            },
        }

    def get_all_metrics(self) -> Dict[str, Any]:
        endpoints = set(self._request_times.keys()) | set(self._request_counts.keys())
        endpoint_metrics = {ep: self.get_endpoint_metrics(ep) for ep in endpoints}

        all_durations = []
        total_requests = 0
        total_errors = 0
        for ep, metrics in endpoint_metrics.items():
            total_requests += metrics["request_count"]
            total_errors += metrics["error_count"]

        uptime = time.time() - self._start_time
        global_qps = total_requests / uptime if uptime > 0 else 0.0
        global_error_rate = total_errors / total_requests if total_requests > 0 else 0.0

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": round(uptime, 1),
            "total_requests": self._total_requests,
            "total_errors": self._total_errors,
            "active_requests": self._active_requests,
            "global_qps": round(global_qps, 2),
            "global_error_rate": round(global_error_rate, 4),
            "window_seconds": self._window_seconds,
            "endpoints": endpoint_metrics,
        }

    def get_summary(self) -> Dict[str, Any]:
        uptime = time.time() - self._start_time
        return {
            "uptime_seconds": round(uptime, 1),
            "total_requests": self._total_requests,
            "total_errors": self._total_errors,
            "active_requests": self._active_requests,
            "global_qps": round(self._total_requests / uptime, 2) if uptime > 0 else 0.0,
            "global_error_rate": round(self._total_errors / self._total_requests, 4) if self._total_requests > 0 else 0.0,
        }


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 3,
    ):
        self.name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._half_open_max_calls = half_open_max_calls
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_calls = 0

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if self._last_failure_time and time.time() - self._last_failure_time >= self._recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
        return self._state

    def record_success(self):
        if self._state == CircuitState.HALF_OPEN:
            self._half_open_calls += 1
            if self._half_open_calls >= self._half_open_max_calls:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
        else:
            self._failure_count = max(0, self._failure_count - 1)

    def record_failure(self):
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
        elif self._failure_count >= self._failure_threshold:
            self._state = CircuitState.OPEN

    def allow_request(self) -> bool:
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.HALF_OPEN:
            return self._half_open_calls < self._half_open_max_calls
        return False

    def get_status(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self._failure_threshold,
            "recovery_timeout": self._recovery_timeout,
            "last_failure_time": self._last_failure_time,
        }


class ReliabilityGuard:
    class CircuitBreaker:
        def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0):
            self._failure_threshold = failure_threshold
            self._recovery_timeout = recovery_timeout
            self._failure_count = 0
            self._state = "closed"
            self._last_failure_time: Optional[float] = None

        def can_execute(self) -> bool:
            if self._state == "open":
                if self._last_failure_time and time.time() - self._last_failure_time >= self._recovery_timeout:
                    self._state = "half_open"
                    return True
                return False
            return True

        def record_success(self):
            if self._state == "half_open":
                self._state = "closed"
            self._failure_count = max(0, self._failure_count - 1)

        def record_failure(self):
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._failure_count >= self._failure_threshold:
                self._state = "open"

    def __init__(self):
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._default_max_retries = 3
        self._default_base_delay = 1.0
        self._default_timeout = 30.0

    def get_or_create_circuit_breaker(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ) -> "ReliabilityGuard.CircuitBreaker":
        if name not in self._circuit_breakers:
            self._circuit_breakers[name] = self.CircuitBreaker(
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
            )
        return self._circuit_breakers[name]

    async def execute_with_retry(self, func, *args, max_retries: int = 3, **kwargs) -> Any:
        cb = None
        circuit_name = kwargs.pop("circuit_name", None)
        timeout_val = kwargs.pop("timeout", self._default_timeout)
        base_delay = kwargs.pop("base_delay", self._default_base_delay)

        if circuit_name:
            cb = self.get_or_create_circuit_breaker(circuit_name)
            if not cb.can_execute():
                raise RuntimeError(f"Circuit breaker '{circuit_name}' is OPEN, requests rejected")

        last_exception = None
        for attempt in range(max_retries + 1):
            try:
                result = await asyncio.wait_for(func(*args, **kwargs), timeout=timeout_val)
                if cb:
                    cb.record_success()
                return result
            except asyncio.TimeoutError:
                last_exception = TimeoutError(f"Operation timed out after {timeout_val}s")
                if cb:
                    cb.record_failure()
            except Exception as exc:
                last_exception = exc
                if cb:
                    cb.record_failure()

            if attempt < max_retries:
                wait = min(base_delay * (2 ** attempt), 60.0)
                logger.warning(f"Retry attempt {attempt + 1}/{max_retries}, waiting {wait:.1f}s")
                await asyncio.sleep(wait)

        raise last_exception or RuntimeError("Max retries exceeded")

    def get_all_circuit_breaker_status(self) -> Dict[str, Dict]:
        return {
            name: {
                "name": name,
                "state": cb._state,
                "failure_count": cb._failure_count,
                "failure_threshold": cb._failure_threshold,
                "recovery_timeout": cb._recovery_timeout,
            }
            for name, cb in self._circuit_breakers.items()
        }

    def reset_circuit_breaker(self, name: str) -> bool:
        if name in self._circuit_breakers:
            cb = self._circuit_breakers[name]
            cb._state = "closed"
            cb._failure_count = 0
            return True
        return False


SENSITIVE_OPERATIONS = {
    "user_created", "user_deactivated", "password_changed",
    "config_update", "rollback", "docker_deploy", "huawei_cloud_deploy",
    "delete_environment", "force_rollback",
}

SENSITIVE_PATTERNS = [
    "password", "secret", "token", "api_key", "credential",
    "admin", "root", "sudo", "privilege",
    "drop", "delete", "truncate", "remove",
    "deploy", "rollback", "config_update",
]


class SecurityAuditor:
    def __init__(self, max_audit_entries: int = 10000):
        self._max_entries = max_audit_entries
        self._recent_operations: deque = deque(maxlen=max_audit_entries)
        self._sensitive_operation_count = 0
        self._total_operations = 0
        self._operation_counts: Dict[str, int] = defaultdict(int)
        self._user_operation_counts: Dict[str, int] = defaultdict(int)
        self._ip_operation_counts: Dict[str, int] = defaultdict(int)
        self._anomaly_flags: List[Dict] = []

    def record_operation(self, operation: str, user: str, details: Dict = None, risk_level: str = "normal"):
        is_sensitive = risk_level in ("high", "critical") or operation in SENSITIVE_OPERATIONS
        detail_str = str(details)[:500] if details else None
        now = datetime.now(timezone.utc)
        entry = {
            "timestamp": now.isoformat(),
            "action": operation,
            "user_id": user,
            "username": user,
            "resource": None,
            "detail": detail_str,
            "ip_address": None,
            "is_sensitive": is_sensitive,
            "risk_level": risk_level,
        }
        self._recent_operations.append(entry)
        self._total_operations += 1
        self._operation_counts[operation] += 1
        if user:
            self._user_operation_counts[user] += 1
        if is_sensitive or operation in SENSITIVE_OPERATIONS:
            self._sensitive_operation_count += 1
        self._detect_anomalies(entry)

    def _detect_anomalies(self, entry: Dict):
        action = entry.get("action", "")
        user_id = entry.get("user_id", "")
        ip_address = entry.get("ip_address", "")

        for pattern in SENSITIVE_PATTERNS:
            if pattern in action.lower():
                self._anomaly_flags.append({
                    "timestamp": entry["timestamp"],
                    "type": "sensitive_operation",
                    "action": action,
                    "user_id": user_id,
                    "pattern_matched": pattern,
                })
                break

        if user_id and self._user_operation_counts.get(user_id, 0) > 100:
            self._anomaly_flags.append({
                "timestamp": entry["timestamp"],
                "type": "high_frequency_user",
                "user_id": user_id,
                "operation_count": self._user_operation_counts[user_id],
            })

        if ip_address and self._ip_operation_counts.get(ip_address, 0) > 200:
            self._anomaly_flags.append({
                "timestamp": entry["timestamp"],
                "type": "high_frequency_ip",
                "ip_address": ip_address,
                "operation_count": self._ip_operation_counts[ip_address],
            })

        if len(self._anomaly_flags) > 1000:
            self._anomaly_flags = self._anomaly_flags[-500:]

    def get_security_summary(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        recent_cutoff = now.timestamp() - 3600
        recent_ops = [
            op for op in self._recent_operations
            if op.get("timestamp") and datetime.fromisoformat(op["timestamp"]).timestamp() >= recent_cutoff
        ]

        recent_sensitive = [op for op in recent_ops if op.get("is_sensitive") or op.get("action") in SENSITIVE_OPERATIONS]
        recent_anomalies = [f for f in self._anomaly_flags if f.get("timestamp") and datetime.fromisoformat(f["timestamp"]).timestamp() >= recent_cutoff]

        return {
            "timestamp": now.isoformat(),
            "total_operations": self._total_operations,
            "sensitive_operation_count": self._sensitive_operation_count,
            "recent_hour_operations": len(recent_ops),
            "recent_hour_sensitive": len(recent_sensitive),
            "recent_hour_anomalies": len(recent_anomalies),
            "top_operations": dict(sorted(self._operation_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_users": dict(sorted(self._user_operation_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_ips": dict(sorted(self._ip_operation_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "recent_anomalies": recent_anomalies[-20:],
            "sensitive_operations_list": list(SENSITIVE_OPERATIONS),
        }

    def get_recent_operations(self, limit: int = 100, action: Optional[str] = None) -> List[Dict]:
        ops = list(self._recent_operations)
        if action:
            ops = [op for op in ops if op.get("action") == action]
        return ops[-limit:]

    def get_authenticated_operation_count(self) -> int:
        return sum(1 for op in self._recent_operations if op.get("user_id"))

    def get_summary(self, hours: int = 24) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - hours * 3600
        recent_ops = [
            op for op in self._recent_operations
            if op.get("timestamp") and datetime.fromisoformat(op["timestamp"]).timestamp() >= cutoff
        ]
        recent_sensitive = [op for op in recent_ops if op.get("is_sensitive") or op.get("action") in SENSITIVE_OPERATIONS]
        recent_anomalies = [f for f in self._anomaly_flags if f.get("timestamp") and datetime.fromisoformat(f["timestamp"]).timestamp() >= cutoff]
        return {
            "timestamp": now.isoformat(),
            "total_operations": self._total_operations,
            "sensitive_operation_count": self._sensitive_operation_count,
            f"recent_{hours}h_operations": len(recent_ops),
            f"recent_{hours}h_sensitive": len(recent_sensitive),
            f"recent_{hours}h_anomalies": len(recent_anomalies),
            "top_operations": dict(sorted(self._operation_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_users": dict(sorted(self._user_operation_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "recent_anomalies": recent_anomalies[-20:],
        }


class MetricsCollector:
    def __init__(self, performance_monitor: PerformanceMonitor, reliability_guard: ReliabilityGuard, security_auditor: SecurityAuditor):
        self._perf = performance_monitor
        self._reliability = reliability_guard
        self._security = security_auditor

    def generate_prometheus_metrics(self) -> str:
        lines = []
        perf_summary = self._perf.get_summary()
        lines.append("# HELP threat_intel_requests_total Total number of requests")
        lines.append("# TYPE threat_intel_requests_total counter")
        lines.append(f"threat_intel_requests_total {perf_summary['total_requests']}")

        lines.append("# HELP threat_intel_errors_total Total number of errors")
        lines.append("# TYPE threat_intel_errors_total counter")
        lines.append(f"threat_intel_errors_total {perf_summary['total_errors']}")

        lines.append("# HELP threat_intel_active_requests Current active requests")
        lines.append("# TYPE threat_intel_active_requests gauge")
        lines.append(f"threat_intel_active_requests {perf_summary['active_requests']}")

        lines.append("# HELP threat_intel_qps Queries per second")
        lines.append("# TYPE threat_intel_qps gauge")
        lines.append(f"threat_intel_qps {perf_summary['global_qps']}")

        lines.append("# HELP threat_intel_error_rate Global error rate")
        lines.append("# TYPE threat_intel_error_rate gauge")
        lines.append(f"threat_intel_error_rate {perf_summary['global_error_rate']}")

        lines.append("# HELP threat_intel_uptime_seconds Application uptime in seconds")
        lines.append("# TYPE threat_intel_uptime_seconds gauge")
        lines.append(f"threat_intel_uptime_seconds {perf_summary['uptime_seconds']}")

        all_metrics = self._perf.get_all_metrics()
        for endpoint, metrics in all_metrics.get("endpoints", {}).items():
            safe_ep = endpoint.replace("/", "_").replace("{", "").replace("}", "").replace(":", "_")
            rt = metrics.get("response_time_ms", {})
            lines.append(f'threat_intel_endpoint_request_count{{endpoint="{safe_ep}"}} {metrics["request_count"]}')
            lines.append(f'threat_intel_endpoint_error_count{{endpoint="{safe_ep}"}} {metrics["error_count"]}')
            lines.append(f'threat_intel_endpoint_qps{{endpoint="{safe_ep}"}} {metrics["qps"]}')
            lines.append(f'threat_intel_endpoint_error_rate{{endpoint="{safe_ep}"}} {metrics["error_rate"]}')
            lines.append(f'threat_intel_endpoint_response_p50_ms{{endpoint="{safe_ep}"}} {rt.get("p50", 0)}')
            lines.append(f'threat_intel_endpoint_response_p95_ms{{endpoint="{safe_ep}"}} {rt.get("p95", 0)}')
            lines.append(f'threat_intel_endpoint_response_p99_ms{{endpoint="{safe_ep}"}} {rt.get("p99", 0)}')
            lines.append(f'threat_intel_endpoint_response_avg_ms{{endpoint="{safe_ep}"}} {rt.get("avg", 0)}')

        cb_status = self._reliability.get_all_circuit_breaker_status()
        for name, status in cb_status.items():
            safe_name = name.replace("-", "_").replace(" ", "_")
            state_val = 1 if status["state"] == "open" else 0
            lines.append(f'threat_intel_circuit_breaker_open{{name="{safe_name}"}} {state_val}')
            lines.append(f'threat_intel_circuit_breaker_failures{{name="{safe_name}"}} {status["failure_count"]}')

        sec_summary = self._security.get_security_summary()
        lines.append("# HELP threat_intel_security_operations_total Total security-tracked operations")
        lines.append("# TYPE threat_intel_security_operations_total counter")
        lines.append(f"threat_intel_security_operations_total {sec_summary['total_operations']}")

        lines.append("# HELP threat_intel_security_sensitive_total Total sensitive operations")
        lines.append("# TYPE threat_intel_security_sensitive_total counter")
        lines.append(f"threat_intel_security_sensitive_total {sec_summary['sensitive_operation_count']}")

        lines.append("# HELP threat_intel_security_anomalies_hour Anomalies in last hour")
        lines.append("# TYPE threat_intel_security_anomalies_hour gauge")
        lines.append(f"threat_intel_security_anomalies_hour {sec_summary['recent_hour_anomalies']}")

        return "\n".join(lines) + "\n"

    def get_prometheus_metrics(self) -> str:
        return self.generate_prometheus_metrics()


performance_monitor = PerformanceMonitor()
reliability_guard = ReliabilityGuard()
security_auditor = SecurityAuditor()
metrics_collector = MetricsCollector(performance_monitor, reliability_guard, security_auditor)
