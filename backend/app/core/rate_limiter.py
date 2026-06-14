import os
import re
import time
from collections import deque
from fnmatch import fnmatch
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Request, Response
from loguru import logger

from app.config import settings
from app.core.exceptions import RateLimitExceededException


class TokenBucket:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def retry_after(self) -> float:
        deficit = 1.0 - self.tokens
        if deficit <= 0:
            return 0.0
        return deficit / self.refill_rate


class SlidingWindowCounter:
    """滑动窗口计数器，基于collections.deque实现精确的滑动窗口请求统计。"""

    def __init__(self, window_seconds: int, max_requests: int):
        """初始化滑动窗口计数器。

        Args:
            window_seconds: 窗口时间长度（秒）。
            max_requests: 窗口内允许的最大请求数。
        """
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self._timestamps: deque = deque()

    def record(self, timestamp: float) -> None:
        """记录一次请求的时间戳。

        Args:
            timestamp: 请求发生的时间戳（time.monotonic()或time.time()）。
        """
        self._timestamps.append(timestamp)

    def count(self, window_seconds: Optional[int] = None) -> int:
        """统计指定窗口内的请求数量。

        自动清理过期时间戳后返回当前窗口内的请求数。

        Args:
            window_seconds: 窗口时间长度（秒），默认使用初始化时设定的值。

        Returns:
            窗口内的请求数量。
        """
        window = window_seconds or self.window_seconds
        cutoff = time.monotonic() - window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        return len(self._timestamps)

    def is_allowed(self) -> bool:
        """判断当前请求是否被允许。

        Returns:
            True表示窗口内请求数未超过限额，False表示已超限。
        """
        return self.count() < self.max_requests


class PathRateLimitRule:
    """路径级差异化限流规则，支持通配符路径匹配。"""

    def __init__(self, path_pattern: str, method: str, rpm: int, burst: int):
        """初始化路径级限流规则。

        Args:
            path_pattern: 路径匹配模式，支持通配符（如/api/v1/intel/*）。
            method: HTTP方法（GET/POST/PUT/DELETE等），*表示匹配所有方法。
            rpm: 每分钟允许的请求数。
            burst: 允许的突发请求数。
        """
        self.path_pattern = path_pattern
        self.method = method.upper()
        self.rpm = rpm
        self.burst = burst
        self.capacity = burst
        self.refill_rate = rpm / 60.0

    def matches(self, path: str, method: str) -> bool:
        """判断给定的路径和方法是否匹配此规则。

        Args:
            path: 请求路径。
            method: HTTP方法。

        Returns:
            True表示匹配，False表示不匹配。
        """
        if self.method != "*" and self.method != method.upper():
            return False
        return fnmatch(path, self.path_pattern)


class RateLimiter:
    TIER_LIMITS: Dict[str, int] = {
        "free": 60,
        "pro": 300,
        "enterprise": 1200,
    }
    ENDPOINT_TYPE_LIMITS: Dict[str, int] = {
        "read": 120,
        "write": 30,
        "analysis": 10,
        "export": 5,
        "auth": 20,
    }

    def __init__(self, requests_per_minute: int = 0):
        self.requests_per_minute = requests_per_minute or settings.RATE_LIMIT_PER_MINUTE
        self.capacity = self.requests_per_minute
        self.refill_rate = self.requests_per_minute / 60.0
        self._ip_buckets: Dict[str, TokenBucket] = {}
        self._user_buckets: Dict[str, TokenBucket] = {}
        self._api_key_buckets: Dict[str, TokenBucket] = {}
        self._last_cleanup = time.monotonic()
        self._cleanup_interval = 300.0
        self._redis = None
        self._path_rules: List[PathRateLimitRule] = []
        self._path_counters: Dict[str, Dict[str, SlidingWindowCounter]] = {}
        self._usage_stats: Dict[str, Dict[str, int]] = {}
        self._adaptive_base_rpm: Optional[int] = None
        self._adaptive_spike_threshold: Optional[float] = None
        self._adaptive_current_rpm: Optional[int] = None
        self._adaptive_last_check: float = 0.0
        self._last_result: Dict[str, Any] = {}

    def set_redis(self, redis_client):
        self._redis = redis_client
        logger.info("RateLimiter: Redis backend enabled (shared state across instances)")

    @property
    def is_redis(self) -> bool:
        return self._redis is not None

    @staticmethod
    def classify_endpoint(path: str, method: str) -> str:
        p = path.lower()
        m = method.upper()
        if p.startswith("/api/v1/auth"):
            return "auth"
        if "export" in p or "stix" in p:
            return "export"
        if any(s in p for s in ("/analyze", "/analysis", "/predict", "/attribution", "/deep-analysis", "/run-pipeline", "/agent")):
            return "analysis"
        if m in ("POST", "PUT", "PATCH", "DELETE"):
            return "write"
        return "read"

    def _get_api_key_bucket(self, key_id: str, rpm: int) -> TokenBucket:
        if key_id not in self._api_key_buckets:
            self._api_key_buckets[key_id] = TokenBucket(
                capacity=max(rpm, 1),
                refill_rate=max(rpm, 1) / 60.0,
            )
        return self._api_key_buckets[key_id]

    def get_tier_limit(self, tier: str) -> int:
        return self.TIER_LIMITS.get((tier or "free").lower(), self.TIER_LIMITS["free"])

    def get_endpoint_type_limit(self, endpoint_type: str) -> int:
        return self.ENDPOINT_TYPE_LIMITS.get(endpoint_type, self.ENDPOINT_TYPE_LIMITS["read"])

    async def check_granular(
        self,
        client_ip: str,
        user_id: Optional[str] = None,
        user_tier: Optional[str] = None,
        api_key_id: Optional[str] = None,
        api_key_rpm: Optional[int] = None,
        endpoint_type: str = "read",
    ) -> Tuple[bool, float, Dict[str, Any]]:
        info: Dict[str, Any] = {"scope": "none", "limit": 0, "remaining": 0, "reset": 0, "retry_after": 0.0}

        if self.is_redis:
            if api_key_id and api_key_rpm:
                ok, retry = await self._check_redis_rate_limit(f"apikey:{api_key_id}", 60)
                if not ok and api_key_rpm > 0:
                    count = await self._redis.get(f"ratelimit:apikey:{api_key_id}")
                    used = int(count) if count else 0
                    info.update({"scope": "api_key", "limit": api_key_rpm, "remaining": max(api_key_rpm - used, 0), "retry_after": retry})
                    self._last_result = info
                    return False, retry, info

            if user_id:
                tier_limit = self.get_tier_limit(user_tier)
                ep_limit = self.get_endpoint_type_limit(endpoint_type)
                effective = min(tier_limit, ep_limit) if ep_limit else tier_limit
                ok, retry = await self._check_redis_rate_limit(f"user:{user_id}:{endpoint_type}", 60)
                if not ok:
                    count = await self._redis.get(f"ratelimit:user:{user_id}:{endpoint_type}")
                    used = int(count) if count else 0
                    info.update({"scope": "user", "limit": effective, "remaining": max(effective - used, 0), "retry_after": retry})
                    self._last_result = info
                    return False, retry, info
                count = await self._redis.get(f"ratelimit:user:{user_id}:{endpoint_type}")
                used = int(count) if count else 0
                info.update({"scope": "user", "limit": effective, "remaining": max(effective - used, 0)})
                self._last_result = info
                return True, 0.0, info

            ok, retry = await self._check_redis_rate_limit(f"ip:{client_ip}", 60)
            if not ok:
                count = await self._redis.get(f"ratelimit:ip:{client_ip}")
                used = int(count) if count else 0
                info.update({"scope": "ip", "limit": self.requests_per_minute, "remaining": 0, "retry_after": retry})
                self._last_result = info
                return False, retry, info
            count = await self._redis.get(f"ratelimit:ip:{client_ip}")
            used = int(count) if count else 0
            info.update({"scope": "ip", "limit": self.requests_per_minute, "remaining": max(self.requests_per_minute - used, 0)})
            self._last_result = info
            return True, 0.0, info

        self._cleanup_stale_buckets()

        if api_key_id and api_key_rpm and api_key_rpm > 0:
            bucket = self._get_api_key_bucket(api_key_id, api_key_rpm)
            if not bucket.consume():
                retry = bucket.retry_after()
                info.update({"scope": "api_key", "limit": api_key_rpm, "remaining": 0, "retry_after": retry})
                self._last_result = info
                return False, retry, info
            info.update({"scope": "api_key", "limit": api_key_rpm, "remaining": max(int(bucket.tokens), 0)})
            self._last_result = info
            return True, 0.0, info

        if user_id:
            tier_limit = self.get_tier_limit(user_tier)
            ep_limit = self.get_endpoint_type_limit(endpoint_type)
            effective = max(min(tier_limit, ep_limit), 1) if ep_limit else max(tier_limit, 1)
            key = f"{user_id}:{endpoint_type}"
            if key not in self._user_buckets:
                self._user_buckets[key] = TokenBucket(capacity=effective, refill_rate=effective / 60.0)
            user_bucket = self._user_buckets[key]
            if not user_bucket.consume():
                retry = user_bucket.retry_after()
                info.update({"scope": "user", "limit": effective, "remaining": 0, "retry_after": retry})
                self._last_result = info
                return False, retry, info
            info.update({"scope": "user", "limit": effective, "remaining": max(int(user_bucket.tokens), 0)})
            self._last_result = info
            return True, 0.0, info

        ip_bucket = self._get_ip_bucket(client_ip)
        if not ip_bucket.consume():
            retry = ip_bucket.retry_after()
            info.update({"scope": "ip", "limit": self.requests_per_minute, "remaining": 0, "retry_after": retry})
            self._last_result = info
            return False, retry, info
        info.update({"scope": "ip", "limit": self.requests_per_minute, "remaining": max(int(ip_bucket.tokens), 0)})
        self._last_result = info
        return True, 0.0, info

    def get_last_info(self) -> Dict[str, Any]:
        return self._last_result

    def _get_ip_bucket(self, client_ip: str) -> TokenBucket:
        if client_ip not in self._ip_buckets:
            self._ip_buckets[client_ip] = TokenBucket(
                capacity=self.capacity,
                refill_rate=self.refill_rate,
            )
        return self._ip_buckets[client_ip]

    def _get_user_bucket(self, user_id: str) -> TokenBucket:
        if user_id not in self._user_buckets:
            self._user_buckets[user_id] = TokenBucket(
                capacity=self.capacity,
                refill_rate=self.refill_rate,
            )
        return self._user_buckets[user_id]

    def _cleanup_stale_buckets(self) -> None:
        now = time.monotonic()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        stale_threshold = now - 600.0
        stale_ips = [
            ip for ip, bucket in self._ip_buckets.items()
            if bucket.last_refill < stale_threshold
        ]
        for ip in stale_ips:
            del self._ip_buckets[ip]
        stale_users = [
            uid for uid, bucket in self._user_buckets.items()
            if bucket.last_refill < stale_threshold
        ]
        for uid in stale_users:
            del self._user_buckets[uid]
        self._last_cleanup = now
        if stale_ips or stale_users:
            logger.debug(
                f"Rate limiter cleanup: removed {len(stale_ips)} IP buckets, "
                f"{len(stale_users)} user buckets"
            )

    async def _check_redis_rate_limit(
        self, key: str, window_seconds: int = 60
    ) -> Tuple[bool, float]:
        if not self._redis:
            return True, 0.0
        try:
            now = time.time()
            pipe = self._redis.pipeline()
            redis_key = f"ratelimit:{key}"
            pipe.incr(redis_key)
            pipe.expire(redis_key, window_seconds)
            results = await pipe.execute()
            count = results[0]
            if count > self.capacity:
                ttl = await self._redis.ttl(redis_key)
                retry_after = max(ttl, 1) if ttl > 0 else window_seconds
                return False, float(retry_after)
            return True, 0.0
        except Exception as exc:
            logger.warning(f"Redis rate limit check failed, falling back to local: {exc}")
            return True, 0.0

    async def check_rate_limit(
        self, client_ip: str, user_id: Optional[str] = None
    ) -> Tuple[bool, float]:
        if self.is_redis:
            ip_allowed, ip_retry = await self._check_redis_rate_limit(f"ip:{client_ip}")
            if not ip_allowed:
                return False, ip_retry
            if user_id:
                user_allowed, user_retry = await self._check_redis_rate_limit(f"user:{user_id}")
                if not user_allowed:
                    return False, user_retry
            return True, 0.0

        self._cleanup_stale_buckets()
        ip_bucket = self._get_ip_bucket(client_ip)
        if not ip_bucket.consume():
            return False, ip_bucket.retry_after()
        if user_id is not None:
            user_bucket = self._get_user_bucket(user_id)
            if not user_bucket.consume():
                return False, user_bucket.retry_after()
        return True, 0.0

    def add_path_rule(self, rule: PathRateLimitRule) -> None:
        """添加路径级限流规则。

        Args:
            rule: PathRateLimitRule实例，定义路径匹配模式和限流参数。
        """
        self._path_rules.append(rule)
        logger.info(f"RateLimiter: Added path rule - pattern={rule.path_pattern}, method={rule.method}, rpm={rule.rpm}, burst={rule.burst}")

    def remove_path_rule(self, path_pattern: str) -> bool:
        """移除路径级限流规则。

        Args:
            path_pattern: 要移除的路径匹配模式。

        Returns:
            True表示成功移除，False表示未找到匹配规则。
        """
        original_count = len(self._path_rules)
        self._path_rules = [r for r in self._path_rules if r.path_pattern != path_pattern]
        removed = len(self._path_rules) < original_count
        if removed:
            logger.info(f"RateLimiter: Removed path rule - pattern={path_pattern}")
        return removed

    def get_path_rules(self) -> List[PathRateLimitRule]:
        """获取所有路径级限流规则。

        Returns:
            当前所有PathRateLimitRule规则的列表。
        """
        return list(self._path_rules)

    def _get_path_counter(self, path: str, client_ip: str, rule: PathRateLimitRule) -> SlidingWindowCounter:
        key = client_ip
        if path not in self._path_counters:
            self._path_counters[path] = {}
        if key not in self._path_counters[path]:
            self._path_counters[path][key] = SlidingWindowCounter(
                window_seconds=60,
                max_requests=rule.rpm,
            )
        return self._path_counters[path][key]

    async def check_path_rate_limit(
        self, path: str, method: str, client_ip: str, user_id: Optional[str] = None
    ) -> Tuple[bool, float]:
        """检查路径级限流。

        根据请求路径和方法匹配路径级限流规则，使用滑动窗口计数器判断是否超限。
        同时记录使用统计信息。

        Args:
            path: 请求路径。
            method: HTTP方法。
            client_ip: 客户端IP地址。
            user_id: 可选的用户ID。

        Returns:
            元组(是否允许, 重试等待秒数)。
        """
        self._record_usage(client_ip, user_id)

        matched_rules = [r for r in self._path_rules if r.matches(path, method)]
        if not matched_rules:
            return True, 0.0

        now = time.monotonic()
        for rule in matched_rules:
            counter = self._get_path_counter(path, client_ip, rule)
            counter.record(now)
            if not counter.is_allowed():
                retry_after = 60.0
                return False, retry_after
        return True, 0.0

    def _record_usage(self, client_ip: str, user_id: Optional[str] = None) -> None:
        """记录使用统计信息。

        Args:
            client_ip: 客户端IP地址。
            user_id: 可选的用户ID。
        """
        if client_ip not in self._usage_stats:
            self._usage_stats[client_ip] = {"ip_count": 0, "user_counts": {}}
        self._usage_stats[client_ip]["ip_count"] += 1
        if user_id:
            if user_id not in self._usage_stats[client_ip]["user_counts"]:
                self._usage_stats[client_ip]["user_counts"][user_id] = 0
            self._usage_stats[client_ip]["user_counts"][user_id] += 1

    def get_usage_stats(self) -> Dict[str, Dict[str, int]]:
        """获取使用统计信息。

        返回每个IP和用户的请求计数统计。

        Returns:
            字典，键为客户端IP，值包含ip_count（IP总请求数）和user_counts（各用户请求数）。
        """
        return dict(self._usage_stats)

    def get_top_consumers(self, limit: int = 10) -> List[Dict[str, int]]:
        """获取Top N高流量消费者。

        按IP请求计数降序排列，返回前N个高流量消费者。

        Args:
            limit: 返回的最大数量，默认10。

        Returns:
            列表，每个元素为包含ip和count键的字典。
        """
        sorted_consumers = sorted(
            self._usage_stats.items(),
            key=lambda x: x[1]["ip_count"],
            reverse=True,
        )
        return [
            {"ip": ip, "count": stats["ip_count"]}
            for ip, stats in sorted_consumers[:limit]
        ]

    def configure_adaptive_limit(self, base_rpm: int, spike_threshold: float) -> None:
        """配置自适应限流。

        当检测到流量突增时自动降低限额，以保护系统稳定性。

        Args:
            base_rpm: 基准每分钟请求数。
            spike_threshold: 突增检测阈值（0.0-1.0），当当前流量占基准限额的比例超过此值时触发降级。
        """
        self._adaptive_base_rpm = base_rpm
        self._adaptive_spike_threshold = spike_threshold
        self._adaptive_current_rpm = base_rpm
        self._adaptive_last_check = time.monotonic()
        logger.info(f"RateLimiter: Adaptive limit configured - base_rpm={base_rpm}, spike_threshold={spike_threshold}")

    def _check_adaptive_limit(self) -> None:
        """检查并调整自适应限流限额。

        根据当前流量与基准限额的比较，动态调整限流参数。
        流量超过阈值时将限额降至基准的50%，流量恢复后逐步回升。
        """
        if self._adaptive_base_rpm is None:
            return
        now = time.monotonic()
        if now - self._adaptive_last_check < 30.0:
            return
        self._adaptive_last_check = now

        total_recent = sum(
            stats["ip_count"] for stats in self._usage_stats.values()
        )
        current_load = total_recent / self._adaptive_base_rpm if self._adaptive_base_rpm > 0 else 0.0

        if current_load > self._adaptive_spike_threshold:
            new_rpm = max(int(self._adaptive_base_rpm * 0.5), 1)
            if self._adaptive_current_rpm != new_rpm:
                self._adaptive_current_rpm = new_rpm
                self.capacity = new_rpm
                self.refill_rate = new_rpm / 60.0
                logger.warning(f"RateLimiter: Adaptive limit triggered - rpm reduced to {new_rpm}")
        else:
            if self._adaptive_current_rpm != self._adaptive_base_rpm:
                self._adaptive_current_rpm = self._adaptive_base_rpm
                self.capacity = self._adaptive_base_rpm
                self.refill_rate = self._adaptive_base_rpm / 60.0
                logger.info(f"RateLimiter: Adaptive limit recovered - rpm restored to {self._adaptive_base_rpm}")

    def get_status(self) -> Dict:
        return {
            "active_ip_buckets": len(self._ip_buckets),
            "active_user_buckets": len(self._user_buckets),
            "requests_per_minute": self.requests_per_minute,
            "backend": "redis" if self.is_redis else "memory",
        }

    async def middleware(self, request: Request, call_next) -> Response:
        if request.url.path in ("/health", "/docs", "/redoc", "/openapi.json"):
            return await call_next(request)
        if request.method == "OPTIONS":
            return await call_next(request)
        client_ip = request.client.host if request.client else "unknown"
        user_id = None
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                from app.core.auth import decode_access_token, is_token_blacklisted
                token = auth_header[7:]
                if not is_token_blacklisted(token):
                    token_data = decode_access_token(token)
                    user_id = token_data.user_id
            except Exception:
                pass

        self._check_adaptive_limit()

        path_allowed, path_retry = await self.check_path_rate_limit(
            request.url.path, request.method, client_ip, user_id
        )
        if not path_allowed:
            raise RateLimitExceededException(
                detail=f"Path rate limit exceeded. Retry after {path_retry:.0f} seconds.",
                details={"retry_after_seconds": round(path_retry, 1)},
            )

        allowed, retry_after = await self.check_rate_limit(client_ip, user_id)
        if not allowed:
            raise RateLimitExceededException(
                detail=f"Rate limit exceeded. Retry after {retry_after:.0f} seconds.",
                details={"retry_after_seconds": round(retry_after, 1)},
            )
        response = await call_next(request)
        return response


class RequestValidator:
    """请求验证器，提供内容类型、请求体大小、Origin验证以及安全攻击检测功能。"""

    _SQL_INJECTION_PATTERNS = [
        re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b)", re.IGNORECASE),
        re.compile(r"(--|;|/\*|\*/|xp_|0x)", re.IGNORECASE),
        re.compile(r"(\b(OR|AND)\b\s+[\d'\"]+\s*=\s*[\d'\"]+)", re.IGNORECASE),
        re.compile(r"(\bCHAR\s*\(|\bCONCAT\s*\(|\bGROUP_CONCAT\s*\()", re.IGNORECASE),
        re.compile(r"(\bBENCHMARK\s*\(|\bSLEEP\s*\(|\bWAITFOR\s+DELAY)", re.IGNORECASE),
    ]

    _XSS_PATTERNS = [
        re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"on(error|load|click|mouseover|focus|blur|submit|change)\s*=", re.IGNORECASE),
        re.compile(r"<\s*(iframe|object|embed|form|input|textarea|button|link|meta|style|base|svg|math)\b", re.IGNORECASE),
        re.compile(r"(document\.(cookie|location|write|domain)|eval\s*\(|alert\s*\(|prompt\s*\()", re.IGNORECASE),
    ]

    def validate_content_type(self, request: Request) -> Tuple[bool, str]:
        """验证请求的Content-Type是否合法。

        Args:
            request: FastAPI请求对象。

        Returns:
            元组(是否合法, 错误信息)。合法时错误信息为空字符串。
        """
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True, ""
        content_type = request.headers.get("content-type", "")
        if not content_type:
            return True, ""
        allowed_prefixes = (
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
            "application/xml",
        )
        if not any(content_type.lower().startswith(prefix) for prefix in allowed_prefixes):
            return False, f"Unsupported Content-Type: {content_type}"
        return True, ""

    def validate_content_length(self, request: Request, max_bytes: int = 10 * 1024 * 1024) -> Tuple[bool, str]:
        """验证请求体大小是否在允许范围内。

        Args:
            request: FastAPI请求对象。
            max_bytes: 允许的最大字节数，默认10MB。

        Returns:
            元组(是否合法, 错误信息)。
        """
        content_length = request.headers.get("content-length")
        if content_length is None:
            return True, ""
        try:
            length = int(content_length)
            if length > max_bytes:
                return False, f"Content-Length {length} exceeds maximum allowed size {max_bytes} bytes"
            return True, ""
        except ValueError:
            return False, f"Invalid Content-Length header: {content_length}"

    def validate_origin(self, request: Request, allowed_origins: List[str]) -> Tuple[bool, str]:
        """验证请求的Origin头是否在允许列表中。

        Args:
            request: FastAPI请求对象。
            allowed_origins: 允许的Origin列表，"*"表示允许所有来源。

        Returns:
            元组(是否合法, 错误信息)。
        """
        origin = request.headers.get("origin")
        if not origin:
            return True, ""
        if "*" in allowed_origins:
            return True, ""
        if origin in allowed_origins:
            return True, ""
        return False, f"Origin {origin} is not allowed"

    def detect_path_traversal(self, path: str) -> Tuple[bool, str]:
        """检测路径穿越攻击。

        使用os.path.normpath规范化路径后检测是否包含上级目录引用。

        Args:
            path: 待检测的路径字符串。

        Returns:
            元组(是否检测到攻击, 攻击详情)。
        """
        if not path:
            return False, ""
        normalized = os.path.normpath(path)
        if ".." in normalized.split(os.sep):
            return True, f"Path traversal detected: {path}"
        if path != normalized and ".." in path:
            return True, f"Path traversal detected: {path}"
        return False, ""

    def detect_sql_injection(self, value: str) -> Tuple[bool, str]:
        """检测SQL注入攻击。

        使用正则模式匹配检测常见的SQL注入特征。

        Args:
            value: 待检测的字符串值。

        Returns:
            元组(是否检测到攻击, 匹配的模式描述)。
        """
        if not value:
            return False, ""
        for pattern in self._SQL_INJECTION_PATTERNS:
            if pattern.search(value):
                return True, f"SQL injection pattern detected in value"
        return False, ""

    def detect_xss(self, value: str) -> Tuple[bool, str]:
        """检测XSS攻击。

        使用正则模式匹配检测常见的XSS攻击特征。

        Args:
            value: 待检测的字符串值。

        Returns:
            元组(是否检测到攻击, 匹配的模式描述)。
        """
        if not value:
            return False, ""
        for pattern in self._XSS_PATTERNS:
            if pattern.search(value):
                return True, f"XSS pattern detected in value"
        return False, ""

    def sanitize_input(self, value: str) -> str:
        """输入消毒，移除或转义潜在的危险字符。

        Args:
            value: 待消毒的字符串值。

        Returns:
            消毒后的安全字符串。
        """
        if not value:
            return value
        sanitized = value.replace("<", "&lt;").replace(">", "&gt;")
        sanitized = sanitized.replace('"', "&quot;").replace("'", "&#x27;")
        sanitized = sanitized.replace("&", "&amp;")
        return sanitized

    async def validate_request(self, request: Request, config: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """综合请求验证，依次执行所有安全检查。

        Args:
            request: FastAPI请求对象。
            config: 可选配置字典，支持以下键：
                - max_content_length: 最大请求体字节数
                - allowed_origins: 允许的Origin列表
                - check_path_traversal: 是否检查路径穿越
                - check_query_injection: 是否检查查询参数注入

        Returns:
            元组(是否全部通过, 错误信息列表)。
        """
        config = config or {}
        errors: List[str] = []

        valid, msg = self.validate_content_type(request)
        if not valid:
            errors.append(msg)

        max_bytes = config.get("max_content_length", 10 * 1024 * 1024)
        valid, msg = self.validate_content_length(request, max_bytes)
        if not valid:
            errors.append(msg)

        allowed_origins = config.get("allowed_origins", [])
        if allowed_origins:
            valid, msg = self.validate_origin(request, allowed_origins)
            if not valid:
                errors.append(msg)

        if config.get("check_path_traversal", True):
            valid, msg = self.detect_path_traversal(request.url.path)
            if not valid:
                errors.append(msg)

        if config.get("check_query_injection", True):
            query_params = str(request.query_params)
            if query_params:
                valid, msg = self.detect_sql_injection(query_params)
                if not valid:
                    errors.append(msg)
                valid, msg = self.detect_xss(query_params)
                if not valid:
                    errors.append(msg)

        return len(errors) == 0, errors


class CORSSecurityMiddleware:
    """CORS安全中间件，支持动态Origin验证和预检请求缓存。"""

    def __init__(
        self,
        allowed_origins: List[str],
        allowed_methods: Optional[List[str]] = None,
        allowed_headers: Optional[List[str]] = None,
        max_age: int = 86400,
    ):
        """初始化CORS安全中间件。

        Args:
            allowed_origins: 允许的Origin列表，"*"表示允许所有来源。
            allowed_methods: 允许的HTTP方法列表，默认为常见方法。
            allowed_headers: 允许的请求头列表，默认为常见头。
            max_age: 预检请求缓存时间（秒），默认86400（24小时）。
        """
        self.allowed_origins = allowed_origins
        self.allowed_methods = allowed_methods or ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        self.allowed_headers = allowed_headers or [
            "Content-Type", "Authorization", "X-Requested-With",
            "Accept", "Origin", "Cache-Control",
        ]
        self.max_age = max_age
        self._preflight_cache: Dict[str, Tuple[float, Dict]] = {}
        self._cache_ttl = 300.0

    def _is_origin_allowed(self, origin: str) -> bool:
        """判断Origin是否被允许。

        Args:
            origin: 请求的Origin头值。

        Returns:
            True表示允许，False表示不允许。
        """
        if "*" in self.allowed_origins:
            return True
        if origin in self.allowed_origins:
            return True
        for pattern in self.allowed_origins:
            if fnmatch(origin, pattern):
                return True
        return False

    def _get_cached_preflight(self, origin: str) -> Optional[Dict]:
        """获取缓存的预检请求结果。

        Args:
            origin: 请求的Origin头值。

        Returns:
            缓存的CORS头字典，如无缓存或已过期则返回None。
        """
        if origin in self._preflight_cache:
            cached_at, headers = self._preflight_cache[origin]
            if time.monotonic() - cached_at < self._cache_ttl:
                return headers
            del self._preflight_cache[origin]
        return None

    def _cache_preflight(self, origin: str, headers: Dict) -> None:
        """缓存预检请求结果。

        Args:
            origin: 请求的Origin头值。
            headers: CORS响应头字典。
        """
        self._preflight_cache[origin] = (time.monotonic(), headers)

    def _build_cors_headers(self, origin: str) -> Dict[str, str]:
        """构建CORS响应头。

        Args:
            origin: 请求的Origin头值。

        Returns:
            CORS响应头字典。
        """
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": ", ".join(self.allowed_methods),
            "Access-Control-Allow-Headers": ", ".join(self.allowed_headers),
            "Access-Control-Max-Age": str(self.max_age),
            "Access-Control-Allow-Credentials": "true",
            "Vary": "Origin",
        }

    async def middleware(self, request: Request, call_next) -> Response:
        """CORS中间件逻辑。

        处理预检请求(OPTIONS)时返回CORS头，处理实际请求时添加CORS头。
        支持动态Origin验证和预检请求缓存。

        Args:
            request: FastAPI请求对象。
            call_next: 下一个中间件或路由处理函数。

        Returns:
            响应对象。
        """
        origin = request.headers.get("origin")

        if not origin:
            return await call_next(request)

        if not self._is_origin_allowed(origin):
            logger.warning(f"CORS: Blocked request from disallowed origin: {origin}")
            return await call_next(request)

        if request.method == "OPTIONS":
            cached = self._get_cached_preflight(origin)
            if cached:
                return Response(
                    status_code=204,
                    headers=cached,
                )
            headers = self._build_cors_headers(origin)
            self._cache_preflight(origin, headers)
            return Response(
                status_code=204,
                headers=headers,
            )

        response = await call_next(request)
        cors_headers = self._build_cors_headers(origin)
        for key, value in cors_headers.items():
            response.headers[key] = value
        return response


rate_limiter = RateLimiter()
