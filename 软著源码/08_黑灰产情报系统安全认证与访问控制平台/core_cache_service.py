"""
CacheService — 统一缓存服务
支持Redis（生产）和内存缓存（开发回退）
"""
import hashlib
import json
import time
from typing import Any, Dict, Optional
from loguru import logger
from app.config import settings


class MemoryCache:
    def __init__(self, default_ttl: int = 300):
        self._store: Dict[str, tuple[Any, float]] = {}
        self.default_ttl = default_ttl
        self._max_size = 10000

    async def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expire_at = entry
        if time.time() > expire_at:
            del self._store[key]
            return None
        return value

    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        if len(self._store) >= self._max_size:
            oldest_key = next(iter(self._store))
            del self._store[oldest_key]
        expire_at = time.time() + (ttl or self.default_ttl)
        self._store[key] = (value, expire_at)

    async def delete(self, key: str):
        self._store.pop(key, None)

    async def exists(self, key: str) -> bool:
        entry = self._store.get(key)
        if entry is None:
            return False
        _, expire_at = entry
        if time.time() > expire_at:
            del self._store[key]
            return False
        return True

    async def clear(self, prefix: str = ""):
        if prefix:
            keys_to_delete = [k for k in self._store if k.startswith(prefix)]
            for k in keys_to_delete:
                del self._store[k]
        else:
            self._store.clear()

    async def cleanup_expired(self):
        now = time.time()
        expired = [k for k, (_, exp) in self._store.items() if now > exp]
        for k in expired:
            del self._store[k]
        return len(expired)


class RedisCache:
    def __init__(self, redis_url: str, prefix: str = "cache:", default_ttl: int = 300):
        self._url = redis_url
        self._prefix = prefix
        self.default_ttl = default_ttl
        self._redis = None

    async def _get_redis(self):
        if self._redis is None:
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(self._url, decode_responses=True)
                await self._redis.ping()
                logger.info(f"Redis connected: {self._url[:30]}...")
            except Exception as exc:
                logger.error(f"Redis connection failed: {exc}")
                raise
        return self._redis

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> Optional[Any]:
        try:
            r = await self._get_redis()
            value = await r.get(self._key(key))
            if value is None:
                return None
            return json.loads(value)
        except Exception as exc:
            logger.warning(f"Redis get failed: {exc}")
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        try:
            r = await self._get_redis()
            serialized = json.dumps(value, ensure_ascii=False, default=str)
            await r.setex(self._key(key), ttl or self.default_ttl, serialized)
        except Exception as exc:
            logger.warning(f"Redis set failed: {exc}")

    async def delete(self, key: str):
        try:
            r = await self._get_redis()
            await r.delete(self._key(key))
        except Exception as exc:
            logger.warning(f"Redis delete failed: {exc}")

    async def exists(self, key: str) -> bool:
        try:
            r = await self._get_redis()
            return bool(await r.exists(self._key(key)))
        except Exception:
            return False

    async def clear(self, prefix: str = ""):
        try:
            r = await self._get_redis()
            pattern = f"{self._prefix}{prefix}*"
            keys = []
            async for key in r.scan_iter(match=pattern):
                keys.append(key)
            if keys:
                await r.delete(*keys)
        except Exception as exc:
            logger.warning(f"Redis clear failed: {exc}")

    async def close(self):
        if self._redis:
            await self._redis.close()
            self._redis = None


class CacheService:
    def __init__(self):
        self._cache: Optional[RedisCache | MemoryCache] = None
        self._is_redis = False

    async def initialize(self):
        if settings.redis_enabled:
            try:
                self._cache = RedisCache(
                    redis_url=settings.REDIS_URL,
                    prefix=settings.REDIS_CACHE_PREFIX,
                    default_ttl=settings.REDIS_CACHE_TTL,
                )
                await self._cache._get_redis()
                self._is_redis = True
                logger.info("CacheService: Redis mode")
            except Exception as exc:
                if settings.is_production:
                    logger.error(f"Redis init failed in production mode — cache is REQUIRED: {exc}")
                    raise RuntimeError(
                        "Redis is required in production environment. "
                        "Set REDIS_URL environment variable and ensure Redis is running."
                    ) from exc
                logger.warning(f"Redis init failed, falling back to memory cache: {exc}")
                self._cache = MemoryCache(default_ttl=settings.REDIS_CACHE_TTL)
                self._is_redis = False
        else:
            if settings.is_production:
                raise RuntimeError(
                    "Redis is required in production environment. "
                    "Set REDIS_ENABLED=true and REDIS_URL environment variables."
                )
            self._cache = MemoryCache(default_ttl=settings.REDIS_CACHE_TTL)
            self._is_redis = False
            logger.info("CacheService: Memory mode (no Redis configured)")

    @staticmethod
    def make_key(*parts: str) -> str:
        combined = ":".join(str(p) for p in parts)
        if len(combined) > 200:
            return hashlib.md5(combined.encode()).hexdigest()
        return combined

    async def get(self, key: str) -> Optional[Any]:
        return await self._cache.get(key)

    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        await self._cache.set(key, value, ttl)

    async def delete(self, key: str):
        await self._cache.delete(key)

    async def exists(self, key: str) -> bool:
        return await self._cache.exists(key)

    async def clear(self, prefix: str = ""):
        await self._cache.clear(prefix)

    async def get_or_set(self, key: str, factory, ttl: Optional[int] = None) -> Any:
        cached = await self.get(key)
        if cached is not None:
            return cached
        value = await factory() if callable(factory) else factory
        await self.set(key, value, ttl)
        return value

    async def close(self):
        if self._cache and isinstance(self._cache, RedisCache):
            await self._cache.close()

    @property
    def is_redis(self) -> bool:
        return self._is_redis


cache_service = CacheService()
