import asyncio
from typing import Any, Callable, Coroutine, List, Optional
from loguru import logger


class WorkerPool:
    def __init__(
        self,
        num_workers: int = 4,
        task_timeout: float = 300.0,
        max_retries: int = 3,
        max_queue_size: int = 1000,
    ):
        self._num_workers = num_workers
        self._task_timeout = task_timeout
        self._max_retries = max_retries
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)
        self._workers: List[asyncio.Task] = []
        self._running = False

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        for i in range(self._num_workers):
            worker = asyncio.create_task(self._worker_loop(i))
            self._workers.append(worker)
        logger.info(f"WorkerPool started with {self._num_workers} workers")

    async def submit(self, task_fn: Callable[..., Coroutine], *args, **kwargs) -> asyncio.Future:
        if not self._running:
            await self.start()
        future = asyncio.get_running_loop().create_future()
        await self._queue.put((task_fn, args, kwargs, future, 0))
        return future

    async def submit_batch(self, tasks: List[tuple]) -> List[asyncio.Future]:
        futures = []
        for task_fn, args, kwargs in tasks:
            future = await self.submit(task_fn, *args, **kwargs)
            futures.append(future)
        return futures

    async def _worker_loop(self, worker_id: int) -> None:
        logger.debug(f"Worker-{worker_id} started")
        while self._running:
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            if item is None:
                break
            task_fn, args, kwargs, future, retry_count = item
            if future.done():
                continue
            try:
                result = await asyncio.wait_for(
                    task_fn(*args, **kwargs),
                    timeout=self._task_timeout,
                )
                if not future.done():
                    future.set_result(result)
            except asyncio.TimeoutError:
                if retry_count < self._max_retries:
                    logger.warning(f"Worker-{worker_id}: task timed out, retry {retry_count + 1}/{self._max_retries}")
                    await self._queue.put((task_fn, args, kwargs, future, retry_count + 1))
                else:
                    if not future.done():
                        future.set_exception(TimeoutError(f"Task timed out after {self._max_retries} retries"))
            except asyncio.CancelledError:
                if not future.done():
                    future.cancel()
                break
            except Exception as exc:
                if retry_count < self._max_retries:
                    logger.warning(f"Worker-{worker_id}: task failed, retry {retry_count + 1}/{self._max_retries}: {exc}")
                    await self._queue.put((task_fn, args, kwargs, future, retry_count + 1))
                else:
                    if not future.done():
                        future.set_exception(exc)
                    logger.error(f"Worker-{worker_id}: task failed after {self._max_retries} retries: {exc}")
        logger.debug(f"Worker-{worker_id} stopped")

    async def close(self) -> None:
        self._running = False
        for _ in self._workers:
            await self._queue.put(None)
        for worker in self._workers:
            try:
                await asyncio.wait_for(worker, timeout=10.0)
            except asyncio.TimeoutError:
                worker.cancel()
                try:
                    await worker
                except asyncio.CancelledError:
                    pass
            except asyncio.CancelledError:
                pass
        self._workers.clear()
        logger.info("WorkerPool closed")

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()


class CollectionWorkerPool(WorkerPool):
    def __init__(
        self,
        num_workers: int = 4,
        task_timeout: float = 600.0,
        max_retries: int = 2,
    ):
        super().__init__(num_workers=num_workers, task_timeout=task_timeout, max_retries=max_retries)
        self._message_queue = None

    def set_message_queue(self, mq) -> None:
        self._message_queue = mq

    async def submit_collection(self, collector_fn: Callable[..., Coroutine], collector_name: str, *args, **kwargs) -> asyncio.Future:
        async def wrapped():
            result = await collector_fn(*args, **kwargs)
            if self._message_queue and result:
                from app.core.message_queue import TOPIC_INTELLIGENCE_COLLECTED
                try:
                    await self._message_queue.publish(TOPIC_INTELLIGENCE_COLLECTED, {
                        "collector": collector_name,
                        "result": result,
                    })
                except Exception as exc:
                    logger.error(f"Failed to publish collection result for {collector_name}: {exc}")
            return result
        return await self.submit(wrapped)
