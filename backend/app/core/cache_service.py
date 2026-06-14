import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Set, Tuple
from loguru import logger
from app.config import settings


class CacheStats:
    def __init__(self) -> None:
        self.hits: int = 0
        self.misses: int = 0
        self.sets: int = 0
        self.evictions: int = 0
        self.expirations: int = 0
        self.stampede_protected: int = 0
        self.tag_invalidations: int = 0

    def record_hit(self) -> None:
        self.hits += 1

    def record_miss(self) -> None:
        self.misses += 1

    def record_set(self) -> None:
        self.sets += 1

    def record_eviction(self) -> None:
        self.evictions += 1

    def record_expiration(self) -> None:
        self.expirations += 1

    def record_stampede_protected(self) -> None:
        self.stampede_protected += 1

    def record_tag_invalidation(self, count: int) -> None:
        self.tag_invalidations += count

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "sets": self.sets,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "stampede_protected": self.stampede_protected,
            "tag_invalidations": self.tag_invalidations,
            "hit_rate": round(self.hit_rate, 4),
        }


class _CacheEntry:
    __slots__ = ("value", "expire_at", "tags", "last_access")

    def __init__(self, value: Any, expire_at: float, tags: Iterable[str]):
        self.value = value
        self.expire_at = expire_at
        self.tags: Set[str] = set(tags)
        self.last_access: float = time.time()


class MemoryCache:
    def __init__(self, default_ttl: int = 300, max_size: int = 10000):
        self._store: "OrderedDict[str, _CacheEntry]" = OrderedDict()
        self._tag_index: Dict[str, Set[str]] = {}
        self.default_ttl = default_ttl
        self._max_size = max_size
        self._access_count = 0
        self._cleanup_interval = 100
        self._lock = asyncio.Lock()
        self.stats = CacheStats()

    def _index_tags(self, key: str, tags: Iterable[str]) -> None:
        for tag in tags:
            self._tag_index.setdefault(tag, set()).add(key)

    def _deindex_tags(self, key: str, tags: Iterable[str]) -> None:
        for tag in tags:
            tag_set = self._tag_index.get(tag)
            if not tag_set:
                continue
            tag_set.discard(key)
            if not tag_set:
                self._tag_index.pop(tag, None)

    def _evict_one(self) -> None:
        if not self._store:
            return
        oldest_key, oldest_entry = next(iter(self._store.items()))
        self._deindex_tags(oldest_key, oldest_entry.tags)
        self._store.pop(oldest_key, None)
        self.stats.record_eviction()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            self._access_count += 1
            if self._access_count % self._cleanup_interval == 0:
                await self._cleanup_expired_unlocked()
            entry = self._store.get(key)
            if entry is None:
                self.stats.record_miss()
                return None
            if time.time() > entry.expire_at:
                self._deindex_tags(key, entry.tags)
                self._store.pop(key, None)
                self.stats.record_miss()
                self.stats.record_expiration()
                return None
            self._store.move_to_end(key)
            entry.last_access = time.time()
            self.stats.record_hit()
            return entry.value

    async def set(self, key: str, value: Any, ttl: Optional[int] = None, tags: Optional[Iterable[str]] = None):
        async with self._lock:
            existing = self._store.get(key)
            tags_set: Set[str] = set(tags) if tags else set()
            if existing is not None:
                self._deindex_tags(key, existing.tags - tags_set)
            else:
                if len(self._store) >= self._max_size:
                    self._evict_one()
            expire_at = time.time() + (ttl or self.default_ttl)
            entry = _CacheEntry(value=value, expire_at=expire_at, tags=tags_set)
            self._store[key] = entry
            self._index_tags(key, tags_set)
            self._store.move_to_end(key)
            self.stats.record_set()

    async def delete(self, key: str):
        async with self._lock:
            entry = self._store.pop(key, None)
            if entry is not None:
                self._deindex_tags(key, entry.tags)

    async def exists(self, key: str) -> bool:
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return False
            if time.time() > entry.expire_at:
                self._deindex_tags(key, entry.tags)
                self._store.pop(key, None)
                self.stats.record_expiration()
                return False
            return True

    async def clear(self, prefix: str = ""):
        async with self._lock:
            if not prefix:
                self._store.clear()
                self._tag_index.clear()
                return
            keys_to_delete = [k for k in self._store if k.startswith(prefix)]
            for k in keys_to_delete:
                entry = self._store.pop(k, None)
                if entry is not None:
                    self._deindex_tags(k, entry.tags)

    async def invalidate_tags(self, tags: Iterable[str]) -> int:
        async with self._lock:
            keys: Set[str] = set()
            for tag in tags:
                keys.update(self._tag_index.get(tag, set()))
            for key in keys:
                entry = self._store.pop(key, None)
                if entry is not None:
                    self._deindex_tags(key, entry.tags)
            self.stats.record_tag_invalidation(len(keys))
            return len(keys)

    async def cleanup_expired(self) -> int:
        async with self._lock:
            return await self._cleanup_expired_unlocked()

    async def _cleanup_expired_unlocked(self) -> int:
        now = time.time()
        expired = [k for k, e in self._store.items() if now > e.expire_at]
        for k in expired:
            entry = self._store.pop(k, None)
            if entry is not None:
                self._deindex_tags(k, entry.tags)
                self.stats.record_expiration()
        return len(expired)

    def memory_usage(self) -> int:
        try:
            import sys
            return sum(sys.getsizeof(k) + sys.getsizeof(e) for k, e in self._store.items())
        except Exception:
            return 0

    def snapshot_stats(self) -> Dict[str, Any]:
        return {
            "size": len(self._store),
            "max_size": self._max_size,
            "tag_count": len(self._tag_index),
            "memory_bytes": self.memory_usage(),
            **self.stats.to_dict(),
        }


class RedisCache:
    def __init__(self, redis_url: str, prefix: str = "cache:", default_ttl: int = 300):
        self._url = redis_url
        self._prefix = prefix
        self._tag_prefix = f"{prefix}tag:"
        self.default_ttl = default_ttl
        self._redis = None
        self.stats = CacheStats()
        self._lock = asyncio.Lock()

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
        else:
            try:
                await self._redis.ping()
            except Exception:
                logger.warning("Redis connection lost, reconnecting...")
                try:
                    await self._redis.close()
                except Exception:
                    pass
                self._redis = None
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(self._url, decode_responses=True)
                await self._redis.ping()
                logger.info("Redis reconnected")
        return self._redis

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def _tag_key(self, tag: str) -> str:
        return f"{self._tag_prefix}{tag}"

    async def get(self, key: str) -> Optional[Any]:
        try:
            r = await self._get_redis()
            value = await r.get(self._key(key))
            if value is None:
                self.stats.record_miss()
                return None
            self.stats.record_hit()
            return json.loads(value)
        except Exception as exc:
            logger.warning(f"Redis get failed: {exc}")
            self.stats.record_miss()
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None, tags: Optional[Iterable[str]] = None):
        try:
            r = await self._get_redis()
            serialized = json.dumps(value, ensure_ascii=False, default=str)
            effective_ttl = ttl or self.default_ttl
            async with self._lock:
                async with r.pipeline(transaction=True) as pipe:
                    pipe.setex(self._key(key), effective_ttl, serialized)
                    if tags:
                        tag_list = list(set(tags))
                        for tag in tag_list:
                            pipe.sadd(self._tag_key(tag), key)
                            pipe.expire(self._tag_key(tag), max(effective_ttl * 2, 600))
                    await pipe.execute()
            self.stats.record_set()
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
        except Exception as exc:
            logger.warning(f"Redis exists failed: {exc}")
            return False

    async def clear(self, prefix: str = ""):
        try:
            r = await self._get_redis()
            pattern = f"{self._prefix}{prefix}*"
            keys: List[str] = []
            async for key in r.scan_iter(match=pattern):
                keys.append(key)
            if keys:
                await r.delete(*keys)
        except Exception as exc:
            logger.warning(f"Redis clear failed: {exc}")

    async def invalidate_tags(self, tags: Iterable[str]) -> int:
        try:
            r = await self._get_redis()
            invalidated = 0
            for tag in tags:
                tag_set_key = self._tag_key(tag)
                members = await r.smembers(tag_set_key)
                if not members:
                    await r.delete(tag_set_key)
                    continue
                keys_to_delete = [self._key(k) for k in members]
                await r.delete(*keys_to_delete, tag_set_key)
                invalidated += len(keys_to_delete)
            self.stats.record_tag_invalidation(invalidated)
            return invalidated
        except Exception as exc:
            logger.warning(f"Redis tag invalidation failed: {exc}")
            return 0

    async def cleanup_expired(self) -> int:
        return 0

    def memory_usage(self) -> int:
        return 0

    def snapshot_stats(self) -> Dict[str, Any]:
        return {"backend": "redis", **self.stats.to_dict()}

    async def close(self):
        if self._redis:
            await self._redis.close()
            self._redis = None


class CacheService:
    def __init__(self):
        self._cache: Optional[RedisCache | MemoryCache] = None
        self._is_redis = False
        self._locks: Dict[str, asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()
        self._warm_tasks: List[Tuple[str, int, Callable[[], Awaitable[Any]], List[str]]] = []

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

    def register_warm(self, key: str, ttl: int, compute_fn: Callable[[], Awaitable[Any]], tags: Optional[List[str]] = None):
        self._warm_tasks.append((key, ttl, compute_fn, list(tags or [])))

    async def warm_critical(self):
        if not self._warm_tasks:
            return
        logger.info(f"CacheService: warming {len(self._warm_tasks)} critical cache entries")
        for key, ttl, compute_fn, tags in self._warm_tasks:
            try:
                await self.get_or_compute(key=key, ttl=ttl, compute_fn=compute_fn, tags=tags)
            except Exception as exc:
                logger.warning(f"Cache warm failed for {key}: {exc}")

    @staticmethod
    def make_key(*parts: str) -> str:
        combined = ":".join(str(p) for p in parts)
        if len(combined) > 200:
            return hashlib.md5(combined.encode()).hexdigest()
        return combined

    async def _get_key_lock(self, key: str) -> asyncio.Lock:
        async with self._locks_guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[key] = lock
            return lock

    async def get(self, key: str) -> Optional[Any]:
        return await self._cache.get(key)

    async def set(self, key: str, value: Any, ttl: Optional[int] = None, tags: Optional[List[str]] = None):
        if isinstance(self._cache, MemoryCache):
            await self._cache.set(key, value, ttl=ttl, tags=tags)
        else:
            await self._cache.set(key, value, ttl=ttl, tags=tags)

    async def delete(self, key: str):
        await self._cache.delete(key)

    async def exists(self, key: str) -> bool:
        return await self._cache.exists(key)

    async def clear(self, prefix: str = ""):
        await self._cache.clear(prefix)

    async def invalidate_tags(self, tags: Iterable[str]) -> int:
        if isinstance(self._cache, (MemoryCache, RedisCache)):
            return await self._cache.invalidate_tags(tags)
        return 0

    async def get_or_set(self, key: str, factory, ttl: Optional[int] = None, tags: Optional[List[str]] = None) -> Any:
        return await self.get_or_compute(key=key, ttl=ttl or 0, compute_fn=factory, tags=tags)

    async def get_or_compute(
        self,
        key: str,
        ttl: int,
        compute_fn: Callable[[], Awaitable[Any]],
        tags: Optional[List[str]] = None,
    ) -> Any:
        cached = await self._cache.get(key)
        if cached is not None:
            return cached
        lock = await self._get_key_lock(key)
        if lock.locked():
            for _ in range(50):
                await asyncio.sleep(0.02)
                cached = await self._cache.get(key)
                if cached is not None:
                    return cached
            if isinstance(self._cache, MemoryCache):
                self._cache.stats.record_stampede_protected()
            elif isinstance(self._cache, RedisCache):
                self._cache.stats.record_stampede_protected()
        async with lock:
            cached = await self._cache.get(key)
            if cached is not None:
                return cached
            value = await compute_fn()
            await self.set(key, value, ttl=ttl, tags=tags)
            return value

    def stats(self) -> Dict[str, Any]:
        if isinstance(self._cache, MemoryCache):
            snap = self._cache.snapshot_stats()
            snap["backend"] = "memory"
            return snap
        if isinstance(self._cache, RedisCache):
            return self._cache.snapshot_stats()
        return {"backend": "uninitialized"}

    async def close(self):
        if self._cache and isinstance(self._cache, RedisCache):
            await self._cache.close()


cache_service = CacheService()
