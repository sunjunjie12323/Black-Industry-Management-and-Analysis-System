import asyncio
import json
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, Coroutine, Dict, List, Optional
from loguru import logger


TOPIC_INTELLIGENCE_COLLECTED = "intelligence.collected"
TOPIC_INTELLIGENCE_CLEANED = "intelligence.cleaned"
TOPIC_INTELLIGENCE_ANALYZED = "intelligence.analyzed"
TOPIC_ALERT_TRIGGERED = "alert.triggered"
TOPIC_ENTITY_DISCOVERED = "entity.discovered"


class MessageQueue(ABC):
    @abstractmethod
    async def publish(self, topic: str, message: Any) -> None:
        pass

    @abstractmethod
    async def subscribe(self, topic: str, handler: Callable[..., Coroutine]) -> None:
        pass

    @abstractmethod
    async def close(self) -> None:
        pass


class RedisMessageQueue(MessageQueue):
    def __init__(self, redis_url: str, consumer_group: str = "tia-workers",
                 handler_timeout: float = 120.0, max_stream_length: int = 10000,
                 max_dlq_length: int = 5000):
        self._url = redis_url
        self._consumer_group = consumer_group
        self._consumer_name = f"worker-{int(time.time())}"
        self._redis = None
        self._handlers: Dict[str, List[Callable[..., Coroutine]]] = {}
        self._tasks: List[asyncio.Task] = []
        self._running = False
        self._handler_timeout = handler_timeout
        self._max_stream_length = max_stream_length
        self._max_dlq_length = max_dlq_length

    async def _get_redis(self):
        if self._redis is None:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(self._url, decode_responses=True)
            await self._redis.ping()
            logger.info(f"RedisMessageQueue connected: {self._url[:30]}...")
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
                logger.info("RedisMessageQueue reconnected")
        return self._redis

    def _stream_key(self, topic: str) -> str:
        return f"mq:{topic}"

    def _dead_letter_key(self, topic: str) -> str:
        return f"mq:dlq:{topic}"

    async def publish(self, topic: str, message: Any) -> None:
        r = await self._get_redis()
        payload = json.dumps(message, ensure_ascii=False, default=str)
        await r.xadd(self._stream_key(topic), {"data": payload}, maxlen=self._max_stream_length)
        logger.debug(f"Published to {topic}")

    async def subscribe(self, topic: str, handler: Callable[..., Coroutine]) -> None:
        r = await self._get_redis()
        stream_key = self._stream_key(topic)
        try:
            await r.xgroup_create(stream_key, self._consumer_group, id="0", mkstream=True)
        except Exception:
            pass
        if topic not in self._handlers:
            self._handlers[topic] = []
        self._handlers[topic].append(handler)
        if not self._running:
            self._running = True
            task = asyncio.create_task(self._consume_loop(topic))
            self._tasks.append(task)
        logger.info(f"Subscribed to {topic}")

    async def _consume_loop(self, topic: str) -> None:
        r = await self._get_redis()
        stream_key = self._stream_key(topic)
        handlers = self._handlers.get(topic, [])
        while self._running:
            try:
                results = await r.xreadgroup(
                    self._consumer_group,
                    self._consumer_name,
                    {stream_key: ">"},
                    count=10,
                    block=2000,
                )
                if results:
                    for stream_name, messages in results:
                        for msg_id, fields in messages:
                            await self._process_message(topic, msg_id, fields, handlers, r, stream_key)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"Consume error on {topic}: {exc}")
                await asyncio.sleep(1)

    async def _process_message(
        self,
        topic: str,
        msg_id: str,
        fields: Dict,
        handlers: List[Callable[..., Coroutine]],
        r,
        stream_key: str,
    ) -> None:
        raw_data = fields.get("data", "{}")
        try:
            message = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            message = raw_data
        for handler in handlers:
            try:
                await asyncio.wait_for(handler(message), timeout=self._handler_timeout)
            except asyncio.TimeoutError:
                logger.error(f"Handler timed out after {self._handler_timeout}s on {topic} msg={msg_id}")
                await self._send_to_dead_letter(r, topic, msg_id, raw_data, "handler_timeout")
            except Exception as exc:
                logger.error(f"Handler error on {topic} msg={msg_id}: {exc}")
                await self._send_to_dead_letter(r, topic, msg_id, raw_data, "消息队列操作失败")
        try:
            await r.xack(stream_key, self._consumer_group, msg_id)
        except Exception as exc:
            logger.warning(f"ACK failed for {msg_id}: {exc}")

    async def _send_to_dead_letter(self, r, topic: str, msg_id: str, raw_data: str, error: str) -> None:
        dlq_key = self._dead_letter_key(topic)
        try:
            await r.xadd(dlq_key, {"original_id": msg_id, "data": raw_data, "error": error}, maxlen=self._max_dlq_length)
            logger.warning(f"Message {msg_id} sent to dead letter queue for {topic}")
        except Exception as exc:
            logger.error(f"Failed to send to DLQ: {exc}")

    async def close(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        if self._redis:
            await self._redis.close()
            self._redis = None
        logger.info("RedisMessageQueue closed")


class MemoryMessageQueue(MessageQueue):
    def __init__(self, handler_timeout: float = 120.0, max_queue_size: int = 10000):
        self._queues: Dict[str, asyncio.Queue] = {}
        self._handlers: Dict[str, List[Callable[..., Coroutine]]] = {}
        self._tasks: List[asyncio.Task] = []
        self._running = False
        self._handler_timeout = handler_timeout
        self._max_queue_size = max_queue_size

    def _get_queue(self, topic: str) -> asyncio.Queue:
        if topic not in self._queues:
            self._queues[topic] = asyncio.Queue(maxsize=self._max_queue_size)
        return self._queues[topic]

    async def publish(self, topic: str, message: Any) -> None:
        queue = self._get_queue(topic)
        await queue.put(message)

    async def subscribe(self, topic: str, handler: Callable[..., Coroutine]) -> None:
        if topic not in self._handlers:
            self._handlers[topic] = []
        self._handlers[topic].append(handler)
        self._get_queue(topic)
        if not self._running:
            self._running = True
        task = asyncio.create_task(self._consume_loop(topic))
        self._tasks.append(task)
        logger.info(f"MemoryMessageQueue subscribed to {topic}")

    async def _consume_loop(self, topic: str) -> None:
        queue = self._get_queue(topic)
        handlers = self._handlers.get(topic, [])
        while self._running:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=1.0)
                for handler in handlers:
                    try:
                        await asyncio.wait_for(handler(message), timeout=self._handler_timeout)
                    except asyncio.TimeoutError:
                        logger.error(f"Handler timed out after {self._handler_timeout}s on {topic}")
                    except Exception as exc:
                        logger.error(f"Handler error on {topic}: {exc}")
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def close(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        logger.info("MemoryMessageQueue closed")


class MessageQueueFactory:
    @staticmethod
    async def create(url: Optional[str] = None) -> MessageQueue:
        if url and url.startswith("redis"):
            mq = RedisMessageQueue(url)
            await mq._get_redis()
            logger.info("MessageQueueFactory: RedisMessageQueue created")
            return mq
        mq = MemoryMessageQueue()
        logger.info("MessageQueueFactory: MemoryMessageQueue created")
        return mq
