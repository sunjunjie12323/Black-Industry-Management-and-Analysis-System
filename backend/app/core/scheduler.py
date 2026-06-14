import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Deque, Dict, List, Optional

from loguru import logger


_MAX_HISTORY_PER_TASK: int = 100
_CONSECUTIVE_FAILURE_DISABLE_THRESHOLD: int = 10
_CONSECUTIVE_FAILURE_ALERT_THRESHOLD: int = 3


class _CronExpression:
    def __init__(self, expression: str):
        parts = expression.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {expression}, expected 5 fields (min hour day month weekday)")
        self.minute = self._parse_field(parts[0], 0, 59)
        self.hour = self._parse_field(parts[1], 0, 23)
        self.day = self._parse_field(parts[2], 1, 31)
        self.month = self._parse_field(parts[3], 1, 12)
        self.weekday = self._parse_field(parts[4], 0, 6)

    def _parse_field(self, field: str, min_val: int, max_val: int) -> set:
        if field == "*":
            return set(range(min_val, max_val + 1))
        values = set()
        for part in field.split(","):
            if "-" in part:
                start, end = part.split("-", 1)
                values.update(range(int(start), int(end) + 1))
            elif "/" in part:
                base, step = part.split("/", 1)
                start = min_val if base == "*" else int(base)
                step = int(step)
                values.update(range(start, max_val + 1, step))
            else:
                values.add(int(part))
        return values

    def matches(self, dt: datetime) -> bool:
        return (
            dt.minute in self.minute
            and dt.hour in self.hour
            and dt.day in self.day
            and dt.month in self.month
            and dt.weekday() in self.weekday
        )


class _TaskRunRecord:
    __slots__ = ("started_at", "finished_at", "status", "duration_ms", "error")

    def __init__(self, started_at: datetime, finished_at: datetime, status: str, duration_ms: float, error: Optional[str] = None):
        self.started_at = started_at
        self.finished_at = finished_at
        self.status = status
        self.duration_ms = duration_ms
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "status": self.status,
            "duration_ms": round(self.duration_ms, 2),
            "error": self.error,
        }


class _ScheduledTask:
    def __init__(self, name: str, cron: _CronExpression, task_fn: Callable[..., Coroutine]):
        self.name = name
        self.cron = cron
        self.task_fn = task_fn
        self.async_task: Optional[asyncio.Task] = None
        self.last_run: Optional[datetime] = None
        self.last_status: str = "pending"
        self.last_error: Optional[str] = None
        self.run_count: int = 0
        self.success_count: int = 0
        self.error_count: int = 0
        self.consecutive_failures: int = 0
        self.disabled_due_to_failures: bool = False
        self._last_matched_minute: Optional[str] = None
        self._history: Deque[_TaskRunRecord] = deque(maxlen=_MAX_HISTORY_PER_TASK)

    def should_run(self, dt: datetime) -> bool:
        minute_key = dt.strftime("%Y%m%d%H%M")
        if minute_key == self._last_matched_minute:
            return False
        if self.cron.matches(dt):
            self._last_matched_minute = minute_key
            return True
        return False

    def record_run(self, record: _TaskRunRecord) -> None:
        self._history.append(record)

    def history_snapshot(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._history]

    def success_rate(self) -> float:
        total = self.run_count
        if total == 0:
            return 1.0
        return self.success_count / total

    def status_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "last_status": self.last_status,
            "last_error": self.last_error,
            "run_count": self.run_count,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "consecutive_failures": self.consecutive_failures,
            "success_rate": round(self.success_rate(), 4),
            "disabled": self.disabled_due_to_failures,
            "history_size": len(self._history),
        }


class TaskScheduler:
    def __init__(
        self,
        task_timeout: float = 600.0,
        consecutive_failure_disable_threshold: int = _CONSECUTIVE_FAILURE_DISABLE_THRESHOLD,
        consecutive_failure_alert_threshold: int = _CONSECUTIVE_FAILURE_ALERT_THRESHOLD,
    ):
        self._tasks: Dict[str, _ScheduledTask] = {}
        self._running = False
        self._main_task: Optional[asyncio.Task] = None
        self._task_timeout = task_timeout
        self._disable_threshold = consecutive_failure_disable_threshold
        self._alert_threshold = consecutive_failure_alert_threshold
        self._queue_depth: int = 0
        self._peak_queue_depth: int = 0

    def add_task(self, name: str, cron_expression: str, task_fn: Callable[..., Coroutine]) -> None:
        cron = _CronExpression(cron_expression)
        scheduled = _ScheduledTask(name=name, cron=cron, task_fn=task_fn)
        self._tasks[name] = scheduled
        logger.info(f"Scheduled task added: {name} (cron: {cron_expression})")

    def remove_task(self, name: str) -> bool:
        task = self._tasks.pop(name, None)
        if task is None:
            return False
        if task.async_task and not task.async_task.done():
            task.async_task.cancel()
        logger.info(f"Scheduled task removed: {name}")
        return True

    def re_enable_task(self, name: str) -> bool:
        task = self._tasks.get(name)
        if task is None:
            return False
        task.disabled_due_to_failures = False
        task.consecutive_failures = 0
        logger.info(f"Scheduled task re-enabled: {name}")
        return True

    def start(self) -> None:
        if self._running:
            logger.warning("TaskScheduler is already running")
            return
        self._running = True
        self._main_task = asyncio.create_task(self._run_loop())
        logger.info(f"TaskScheduler started with {len(self._tasks)} tasks")

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        for task in self._tasks.values():
            if task.async_task and not task.async_task.done():
                task.async_task.cancel()
                try:
                    await task.async_task
                except asyncio.CancelledError:
                    pass
        if self._main_task and not self._main_task.done():
            self._main_task.cancel()
            try:
                await self._main_task
            except asyncio.CancelledError:
                pass
        logger.info("TaskScheduler stopped")

    def get_task_status(self) -> List[Dict]:
        return [task.status_dict() for task in self._tasks.values()]

    def get_task_history(self, name: str) -> List[Dict[str, Any]]:
        task = self._tasks.get(name)
        if task is None:
            return []
        return task.history_snapshot()

    def get_queue_metrics(self) -> Dict[str, int]:
        return {
            "current_depth": self._queue_depth,
            "peak_depth": self._peak_queue_depth,
            "registered_tasks": len(self._tasks),
            "running_tasks": sum(
                1 for t in self._tasks.values()
                if t.async_task is not None and not t.async_task.done()
            ),
            "disabled_tasks": sum(1 for t in self._tasks.values() if t.disabled_due_to_failures),
        }

    async def _run_loop(self) -> None:
        logger.info("TaskScheduler main loop started")
        while self._running:
            try:
                now = datetime.now(timezone.utc)
                due_tasks = []
                for task in self._tasks.values():
                    if task.disabled_due_to_failures:
                        continue
                    if task.should_run(now):
                        due_tasks.append(task)
                self._queue_depth = len(due_tasks)
                if self._queue_depth > self._peak_queue_depth:
                    self._peak_queue_depth = self._queue_depth
                for task in due_tasks:
                    if task.async_task and not task.async_task.done():
                        logger.warning(f"Scheduled task {task.name} still running, skipping this cycle")
                        continue
                    task.async_task = asyncio.create_task(self._execute_task(task))
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"TaskScheduler loop error: {exc}")
                await asyncio.sleep(30)
        logger.info("TaskScheduler main loop exited")

    async def _execute_task(self, task: _ScheduledTask) -> None:
        started_at = datetime.now(timezone.utc)
        record_status = "completed"
        record_error: Optional[str] = None
        try:
            task.run_count += 1
            task.last_run = started_at
            task.last_status = "running"
            task.last_error = None
            logger.info(f"Scheduled task executing: {task.name}")
            await asyncio.wait_for(task.task_fn(), timeout=self._task_timeout)
            task.last_status = "completed"
            task.success_count += 1
            task.consecutive_failures = 0
            logger.info(f"Scheduled task completed: {task.name}")
        except asyncio.TimeoutError:
            record_status = "timeout"
            record_error = f"timeout after {self._task_timeout}s"
            task.error_count += 1
            task.consecutive_failures += 1
            task.last_status = "timeout"
            task.last_error = record_error
            logger.error(f"Scheduled task timed out after {self._task_timeout}s: {task.name}")
            self._maybe_disable(task)
        except asyncio.CancelledError:
            record_status = "cancelled"
            task.last_status = "cancelled"
            raise
        except Exception as exc:
            record_status = "failed"
            record_error = str(exc)[:200]
            task.error_count += 1
            task.consecutive_failures += 1
            task.last_status = "failed"
            task.last_error = record_error
            logger.error(f"Scheduled task failed: {task.name}, error: {exc}")
            self._maybe_disable(task)
        finally:
            finished_at = datetime.now(timezone.utc)
            duration_ms = (finished_at - started_at).total_seconds() * 1000.0
            task.record_run(_TaskRunRecord(
                started_at=started_at,
                finished_at=finished_at,
                status=record_status,
                duration_ms=duration_ms,
                error=record_error,
            ))

    def _maybe_disable(self, task: _ScheduledTask) -> None:
        if task.consecutive_failures >= self._disable_threshold and not task.disabled_due_to_failures:
            task.disabled_due_to_failures = True
            logger.error(
                f"Scheduled task auto-disabled after {task.consecutive_failures} "
                f"consecutive failures: {task.name}"
            )
        elif task.consecutive_failures >= self._alert_threshold:
            logger.error(
                f"Scheduled task {task.name} has {task.consecutive_failures} consecutive failures "
                f"(threshold={self._alert_threshold})"
            )
