import csv
import io
import json
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.responses import Response

from app.middleware import request_id_ctx

_EXCLUDED_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})

_audit_request_logger = logger.bind(name="audit_request")

_SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"\.\./", re.IGNORECASE),
    re.compile(r"(\.\.\\)", re.IGNORECASE),
    re.compile(r"(%2e%2e%2f)", re.IGNORECASE),
    re.compile(r"(%2e%2e/)", re.IGNORECASE),
    re.compile(r"(\.\.%2f)", re.IGNORECASE),
    re.compile(r"(etc/passwd)", re.IGNORECASE),
    re.compile(r"(cmd\.exe)", re.IGNORECASE),
    re.compile(r"(<script)", re.IGNORECASE),
    re.compile(r"(javascript:)", re.IGNORECASE),
    re.compile(r"(union\s+select)", re.IGNORECASE),
    re.compile(r"(or\s+1\s*=\s*1)", re.IGNORECASE),
    re.compile(r"(drop\s+table)", re.IGNORECASE),
    re.compile(r"(exec\s*\()", re.IGNORECASE),
    re.compile(r"(eval\s*\()", re.IGNORECASE),
]

_BODY_LOG_METHODS = frozenset({"POST", "PUT", "PATCH"})

_SENSITIVE_BODY_FIELDS = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "private_key", "credit_card",
    "card_number", "cvv", "ssn",
})


class SecurityEventCorrelator:
    """安全事件关联器，摄入安全事件并基于时间窗口和阈值检测各类攻击模式。"""

    def __init__(self):
        self.logger = logger.bind(component="security_event_correlator")
        self._events: List[Dict[str, Any]] = []
        self._max_events = 50000
        self._active_threats: List[Dict[str, Any]] = []

    def ingest_event(self, event_type: str, source_ip: str, user_id: Optional[str] = None, details: Optional[Dict] = None) -> None:
        """摄入安全事件。

        Args:
            event_type: 事件类型（如login_failure, access_denied, data_export等）
            source_ip: 来源IP地址
            user_id: 关联用户ID，可选
            details: 事件详情字典，可选
        """
        event = {
            "id": len(self._events) + 1,
            "event_type": event_type,
            "source_ip": source_ip,
            "user_id": user_id,
            "details": details or {},
            "timestamp": datetime.now(timezone.utc),
        }
        self._events.append(event)
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]
        self._auto_correlate(event)

    def detect_brute_force(self, window_minutes: int = 15, threshold: int = 10) -> List[Dict[str, Any]]:
        """检测暴力破解模式，基于时间窗口内同一IP的登录失败次数。

        Args:
            window_minutes: 检测时间窗口（分钟），默认15分钟
            threshold: 触发阈值，默认10次

        Returns:
            检测到的暴力破解威胁列表
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        ip_failures: Dict[str, List[Dict]] = defaultdict(list)
        for event in self._events:
            if event["event_type"] == "login_failure" and event["timestamp"] >= cutoff:
                ip_failures[event["source_ip"]].append(event)
        threats = []
        for ip, events in ip_failures.items():
            if len(events) >= threshold:
                threat = {
                    "threat_type": "brute_force",
                    "source_ip": ip,
                    "event_count": len(events),
                    "window_minutes": window_minutes,
                    "first_seen": events[0]["timestamp"].isoformat(),
                    "last_seen": events[-1]["timestamp"].isoformat(),
                    "severity": "high" if len(events) >= threshold * 2 else "medium",
                }
                threats.append(threat)
        return threats

    def detect_credential_stuffing(self, window_minutes: int = 30, threshold: int = 5) -> List[Dict[str, Any]]:
        """检测撞库攻击，基于时间窗口内同一IP使用不同用户账号登录失败。

        Args:
            window_minutes: 检测时间窗口（分钟），默认30分钟
            threshold: 不同用户账号阈值，默认5个

        Returns:
            检测到的撞库攻击威胁列表
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        ip_users: Dict[str, set] = defaultdict(set)
        ip_events: Dict[str, List[Dict]] = defaultdict(list)
        for event in self._events:
            if event["event_type"] == "login_failure" and event["timestamp"] >= cutoff and event.get("user_id"):
                ip_users[event["source_ip"]].add(event["user_id"])
                ip_events[event["source_ip"]].append(event)
        threats = []
        for ip, users in ip_users.items():
            if len(users) >= threshold:
                threat = {
                    "threat_type": "credential_stuffing",
                    "source_ip": ip,
                    "unique_user_count": len(users),
                    "window_minutes": window_minutes,
                    "first_seen": ip_events[ip][0]["timestamp"].isoformat(),
                    "last_seen": ip_events[ip][-1]["timestamp"].isoformat(),
                    "severity": "critical" if len(users) >= threshold * 3 else "high",
                }
                threats.append(threat)
        return threats

    def detect_privilege_escalation(self, user_id: str) -> Optional[Dict[str, Any]]:
        """检测指定用户的权限提升行为。

        Args:
            user_id: 待检测的用户ID

        Returns:
            检测到的权限提升威胁，未检测到返回None
        """
        user_events = [
            e for e in self._events
            if e.get("user_id") == user_id and e["event_type"] in ("role_change", "permission_grant", "admin_action", "access_denied")
        ]
        if not user_events:
            return None
        role_changes = [e for e in user_events if e["event_type"] == "role_change"]
        permission_grants = [e for e in user_events if e["event_type"] == "permission_grant"]
        admin_actions = [e for e in user_events if e["event_type"] == "admin_action"]
        access_denied = [e for e in user_events if e["event_type"] == "access_denied"]
        risk_score = 0
        indicators: List[str] = []
        if role_changes:
            risk_score += len(role_changes) * 30
            indicators.append(f"{len(role_changes)} role change(s)")
        if permission_grants:
            risk_score += len(permission_grants) * 20
            indicators.append(f"{len(permission_grants)} permission grant(s)")
        if admin_actions:
            risk_score += len(admin_actions) * 15
            indicators.append(f"{len(admin_actions)} admin action(s)")
        if access_denied:
            risk_score += len(access_denied) * 10
            indicators.append(f"{len(access_denied)} access denied")
        if risk_score < 20:
            return None
        return {
            "threat_type": "privilege_escalation",
            "user_id": user_id,
            "risk_score": min(risk_score, 100),
            "indicators": indicators,
            "severity": "critical" if risk_score >= 60 else "high" if risk_score >= 40 else "medium",
        }

    def detect_data_exfiltration(self, user_id: str, window_minutes: int = 60) -> Optional[Dict[str, Any]]:
        """检测指定用户的数据外泄行为。

        Args:
            user_id: 待检测的用户ID
            window_minutes: 检测时间窗口（分钟），默认60分钟

        Returns:
            检测到的数据外泄威胁，未检测到返回None
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        user_events = [
            e for e in self._events
            if e.get("user_id") == user_id and e["timestamp"] >= cutoff
            and e["event_type"] in ("data_export", "bulk_download", "data_access", "api_call")
        ]
        if not user_events:
            return None
        exports = [e for e in user_events if e["event_type"] == "data_export"]
        bulk_downloads = [e for e in user_events if e["event_type"] == "bulk_download"]
        data_access = [e for e in user_events if e["event_type"] == "data_access"]
        risk_score = 0
        indicators: List[str] = []
        if exports:
            risk_score += len(exports) * 25
            indicators.append(f"{len(exports)} data export(s)")
        if bulk_downloads:
            risk_score += len(bulk_downloads) * 30
            indicators.append(f"{len(bulk_downloads)} bulk download(s)")
        if len(data_access) > 50:
            risk_score += 20
            indicators.append(f"{len(data_access)} data access (high volume)")
        if risk_score < 25:
            return None
        return {
            "threat_type": "data_exfiltration",
            "user_id": user_id,
            "risk_score": min(risk_score, 100),
            "indicators": indicators,
            "window_minutes": window_minutes,
            "severity": "critical" if risk_score >= 60 else "high" if risk_score >= 40 else "medium",
        }

    def detect_anomalous_access(self, user_id: str) -> Optional[Dict[str, Any]]:
        """检测指定用户的异常访问模式，包括非工作时间访问和异常IP切换。

        Args:
            user_id: 待检测的用户ID

        Returns:
            检测到的异常访问威胁，未检测到返回None
        """
        user_events = [
            e for e in self._events
            if e.get("user_id") == user_id and e["event_type"] in ("login_success", "api_call", "data_access")
        ]
        if not user_events:
            return None
        off_hours_count = 0
        unique_ips: set = set()
        for event in user_events[-100:]:
            unique_ips.add(event["source_ip"])
            hour = event["timestamp"].hour
            if hour < 6 or hour > 22:
                off_hours_count += 1
        risk_score = 0
        indicators: List[str] = []
        if off_hours_count > 5:
            risk_score += 25
            indicators.append(f"{off_hours_count} off-hours access events")
        if len(unique_ips) > 5:
            risk_score += 30
            indicators.append(f"{len(unique_ips)} unique source IPs")
        if risk_score < 20:
            return None
        return {
            "threat_type": "anomalous_access",
            "user_id": user_id,
            "risk_score": min(risk_score, 100),
            "indicators": indicators,
            "unique_ips": len(unique_ips),
            "severity": "high" if risk_score >= 40 else "medium",
        }

    def get_active_threats(self) -> List[Dict[str, Any]]:
        """获取当前活跃威胁列表。

        Returns:
            活跃威胁列表，包含各类检测的最新结果
        """
        threats: List[Dict[str, Any]] = []
        threats.extend(self.detect_brute_force())
        threats.extend(self.detect_credential_stuffing())
        self._active_threats = threats
        return list(self._active_threats)

    def generate_security_report(self, hours: int = 24) -> Dict[str, Any]:
        """生成安全报告，汇总指定时间范围内的安全事件和威胁。

        Args:
            hours: 报告时间范围（小时），默认24小时

        Returns:
            包含summary、threats、event_breakdown的安全报告字典
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        recent_events = [e for e in self._events if e["timestamp"] >= cutoff]
        event_type_counts: Dict[str, int] = defaultdict(int)
        ip_counts: Dict[str, int] = defaultdict(int)
        user_counts: Dict[str, int] = defaultdict(int)
        for event in recent_events:
            event_type_counts[event["event_type"]] += 1
            ip_counts[event["source_ip"]] += 1
            if event.get("user_id"):
                user_counts[event["user_id"]] += 1
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        threats = self.get_active_threats()
        severity_counts: Dict[str, int] = defaultdict(int)
        for t in threats:
            severity_counts[t.get("severity", "unknown")] += 1
        return {
            "report_period_hours": hours,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_events": len(recent_events),
                "total_threats": len(threats),
                "severity_breakdown": dict(severity_counts),
            },
            "threats": threats,
            "event_breakdown": dict(event_type_counts),
            "top_source_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
            "top_users": [{"user_id": uid, "count": count} for uid, count in top_users],
        }

    def _auto_correlate(self, event: Dict[str, Any]) -> None:
        """自动关联新摄入的事件，检测即时威胁。

        Args:
            event: 新摄入的安全事件
        """
        if event["event_type"] == "login_failure":
            recent = self.detect_brute_force(window_minutes=5, threshold=5)
            if recent:
                self.logger.warning(f"Brute force detected from IPs: {[t['source_ip'] for t in recent]}")
        if event["event_type"] in ("data_export", "bulk_download") and event.get("user_id"):
            exfil = self.detect_data_exfiltration(event["user_id"], window_minutes=30)
            if exfil:
                self.logger.warning(f"Potential data exfiltration by user {event['user_id']}: risk_score={exfil['risk_score']}")


class AuditLogPersistence:
    """审计日志持久化，支持将审计日志存储到数据库、查询和导出。"""

    _TABLE_NAME = "audit_logs"

    def __init__(self):
        self.logger = logger.bind(component="audit_log_persistence")

    async def persist_log(self, entry: Dict[str, Any], db_session: AsyncSession) -> bool:
        """持久化审计日志到数据库。

        Args:
            entry: 审计日志条目字典
            db_session: 异步数据库会话

        Returns:
            是否成功持久化
        """
        try:
            columns = ", ".join(entry.keys())
            placeholders = ", ".join(f":{k}" for k in entry.keys())
            sql = text(f"INSERT INTO {self._TABLE_NAME} ({columns}) VALUES ({placeholders})")
            await db_session.execute(sql, entry)
            await db_session.commit()
            self.logger.debug(f"Persisted audit log entry: {entry.get('request_id', 'unknown')}")
            return True
        except Exception as exc:
            self.logger.error(f"Failed to persist audit log: {exc}")
            try:
                await db_session.rollback()
            except Exception:
                pass
            return False

    async def query_logs(self, filters: Dict[str, Any], db_session: AsyncSession) -> List[Dict[str, Any]]:
        """查询审计日志。

        Args:
            filters: 查询过滤条件字典，支持user_id、method、path、status_code、start_time、end_time、limit
            db_session: 异步数据库会话

        Returns:
            匹配的审计日志列表
        """
        conditions: List[str] = []
        params: Dict[str, Any] = {}
        if "user_id" in filters:
            conditions.append("user_id = :user_id")
            params["user_id"] = filters["user_id"]
        if "method" in filters:
            conditions.append("method = :method")
            params["method"] = filters["method"]
        if "path" in filters:
            conditions.append("path LIKE :path")
            params["path"] = f"%{filters['path']}%"
        if "status_code" in filters:
            conditions.append("status_code = :status_code")
            params["status_code"] = filters["status_code"]
        if "start_time" in filters:
            conditions.append("timestamp >= :start_time")
            params["start_time"] = filters["start_time"]
        if "end_time" in filters:
            conditions.append("timestamp <= :end_time")
            params["end_time"] = filters["end_time"]
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        limit = filters.get("limit", 100)
        params["limit_val"] = limit
        sql = text(f"SELECT * FROM {self._TABLE_NAME} WHERE {where_clause} ORDER BY timestamp DESC LIMIT :limit_val")
        try:
            result = await db_session.execute(sql, params)
            rows = result.fetchall()
            columns = result.keys()
            return [dict(zip(columns, row)) for row in rows]
        except Exception as exc:
            self.logger.error(f"Failed to query audit logs: {exc}")
            return []

    async def export_logs(self, format: str, start_date: str, end_date: str, db_session: AsyncSession) -> str:
        """导出审计日志为指定格式。

        Args:
            format: 导出格式，支持"json"和"csv"
            start_date: 起始日期（ISO格式字符串）
            end_date: 结束日期（ISO格式字符串）
            db_session: 异步数据库会话

        Returns:
            导出的日志内容字符串
        """
        filters = {"start_time": start_date, "end_time": end_date, "limit": 100000}
        logs = await self.query_logs(filters, db_session)
        if format.lower() == "csv":
            if not logs:
                return ""
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=logs[0].keys())
            writer.writeheader()
            writer.writerows(logs)
            return output.getvalue()
        return json.dumps(logs, ensure_ascii=False, default=str, indent=2)

    async def get_log_statistics(self, db_session: AsyncSession) -> Dict[str, Any]:
        """获取日志统计信息。

        Args:
            db_session: 异步数据库会话

        Returns:
            包含total_count、by_method、by_status_code、by_path的统计字典
        """
        try:
            count_sql = text(f"SELECT COUNT(*) as total FROM {self._TABLE_NAME}")
            result = await db_session.execute(count_sql)
            row = result.fetchone()
            total = row[0] if row else 0

            method_sql = text(f"SELECT method, COUNT(*) as cnt FROM {self._TABLE_NAME} GROUP BY method ORDER BY cnt DESC")
            result = await db_session.execute(method_sql)
            by_method = {row[0]: row[1] for row in result.fetchall()}

            status_sql = text(f"SELECT status_code, COUNT(*) as cnt FROM {self._TABLE_NAME} GROUP BY status_code ORDER BY cnt DESC")
            result = await db_session.execute(status_sql)
            by_status_code = {str(row[0]): row[1] for row in result.fetchall()}

            path_sql = text(f"SELECT path, COUNT(*) as cnt FROM {self._TABLE_NAME} GROUP BY path ORDER BY cnt DESC LIMIT 20")
            result = await db_session.execute(path_sql)
            by_path = {row[0]: row[1] for row in result.fetchall()}

            return {
                "total_count": total,
                "by_method": by_method,
                "by_status_code": by_status_code,
                "by_path": by_path,
            }
        except Exception as exc:
            self.logger.error(f"Failed to get log statistics: {exc}")
            return {
                "total_count": 0,
                "by_method": {},
                "by_status_code": {},
                "by_path": {},
            }


security_event_correlator = SecurityEventCorrelator()
audit_log_persistence = AuditLogPersistence()


def _is_suspicious_path(path: str) -> Optional[str]:
    """检测请求路径是否可疑。

    Args:
        path: 请求路径

    Returns:
        匹配的可疑模式描述，无可疑返回None
    """
    for pattern in _SUSPICIOUS_PATH_PATTERNS:
        if pattern.search(path):
            return f"matched pattern: {pattern.pattern}"
    return None


def _mask_sensitive_body(body: Dict[str, Any]) -> Dict[str, Any]:
    """脱敏请求体中的敏感字段。

    Args:
        body: 原始请求体字典

    Returns:
            脱敏后的请求体字典
    """
    if not isinstance(body, dict):
        return body
    masked = {}
    for key, value in body.items():
        if key.lower() in _SENSITIVE_BODY_FIELDS:
            masked[key] = "***REDACTED***"
        elif isinstance(value, dict):
            masked[key] = _mask_sensitive_body(value)
        else:
            masked[key] = value
    return masked


async def audit_log_middleware(request: Request, call_next) -> Response:
    path = request.url.path
    if path in _EXCLUDED_PATHS:
        return await call_next(request)

    request_id = request_id_ctx.get() or request.headers.get("x-request-id", "-")
    method = request.method

    user_id = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            from jose import jwt
            from app.config import settings

            token = auth_header[7:]
            payload = jwt.decode(token, settings.secret_key_resolved, algorithms=[settings.ALGORITHM])
            user_id = payload.get("sub")
        except Exception:
            pass

    request_body = None
    if method in _BODY_LOG_METHODS:
        try:
            raw_body = await request.body()
            if raw_body:
                parsed = json.loads(raw_body)
                if isinstance(parsed, dict):
                    request_body = _mask_sensitive_body(parsed)
                else:
                    request_body = "[non-dict body]"
        except Exception:
            request_body = "[unreadable body]"

    suspicious = _is_suspicious_path(path)

    start_time = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    _audit_request_logger.info(
        "{timestamp} | request_id={request_id} | {method} {path} | status={status_code} | duration={duration_ms}ms | user_id={user_id}",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        request_id=request_id,
        method=method,
        path=path,
        status_code=response.status_code,
        duration_ms=duration_ms,
        user_id=user_id or "-",
    )

    if request_body:
        _audit_request_logger.debug(
            "request_body | request_id={request_id} | body={body}",
            request_id=request_id,
            body=json.dumps(request_body, ensure_ascii=False) if isinstance(request_body, dict) else request_body,
        )

    if suspicious:
        client_ip = request.client.host if request.client else "unknown"
        security_event_correlator.ingest_event(
            event_type="suspicious_request",
            source_ip=client_ip,
            user_id=user_id,
            details={
                "path": path,
                "method": method,
                "suspicious_pattern": suspicious,
                "request_id": request_id,
            },
        )
        _audit_request_logger.warning(
            "suspicious_request | request_id={request_id} | path={path} | pattern={pattern}",
            request_id=request_id,
            path=path,
            pattern=suspicious,
        )

    if response.status_code == 401:
        client_ip = request.client.host if request.client else "unknown"
        security_event_correlator.ingest_event(
            event_type="login_failure",
            source_ip=client_ip,
            user_id=user_id,
            details={"path": path, "method": method, "request_id": request_id},
        )
    elif response.status_code == 403:
        client_ip = request.client.host if request.client else "unknown"
        security_event_correlator.ingest_event(
            event_type="access_denied",
            source_ip=client_ip,
            user_id=user_id,
            details={"path": path, "method": method, "request_id": request_id},
        )

    return response
