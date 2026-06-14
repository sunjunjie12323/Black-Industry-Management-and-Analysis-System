import os
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from loguru import logger


@dataclass
class SchedulerConfig:
    schedule_interval_hours: float = 6.0
    max_concurrent_llm_calls: int = 5
    batch_size: int = 100
    analysis_timeout_seconds: int = 60
    retry_max_attempts: int = 3
    enabled_analysis_types: List[str] = field(default_factory=lambda: ["zero_day", "attribution", "provenance", "decay", "attack_prediction"])


@dataclass
class SchedulerStatus:
    is_running: bool = False
    last_run_time: Optional[datetime] = None
    next_run_time: Optional[datetime] = None
    total_runs: int = 0
    last_run_duration_seconds: Optional[float] = None
    last_run_items_processed: int = 0


class AnalysisScheduler:
    def __init__(self, engine, config: Optional[SchedulerConfig] = None):
        self.engine = engine
        self.config = config or SchedulerConfig()
        self._scheduler = AsyncIOScheduler()
        self._status = SchedulerStatus()
        self._job_id = "analysis_cycle_job"

    def start(self):
        if self._scheduler.running:
            logger.warning("Scheduler already running")
            return
        interval = self.config.schedule_interval_hours
        self._scheduler.add_job(
            self._run_analysis_cycle,
            "interval",
            hours=interval,
            id=self._job_id,
            replace_existing=True,
            max_instances=1,
        )
        self._scheduler.start()
        self._status.is_running = True
        self._status.next_run_time = datetime.now(timezone.utc) + timedelta(hours=interval)
        logger.info(f"AnalysisScheduler started (interval: {interval}h, types: {self.config.enabled_analysis_types})")

    def stop(self):
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            self._status.is_running = False
            logger.info("AnalysisScheduler stopped")

    async def trigger_now(self) -> Dict[str, Any]:
        logger.info("Manual analysis trigger received")
        try:
            result = await self._run_analysis_cycle()
            return {"status": "completed", "result": result}
        except Exception as exc:
            logger.error(f"Manual trigger failed: {exc}")
            return {"status": "failed", "error": str(exc)}

    def get_status(self) -> Dict[str, Any]:
        jobs = self._scheduler.get_jobs()
        next_run = None
        for job in jobs:
            if job.id == self._job_id and job.next_run_time:
                next_run = job.next_run_time
        return {
            "is_running": self._status.is_running,
            "last_run_time": self._status.last_run_time,
            "next_run_time": next_run or self._status.next_run_time,
            "total_runs": self._status.total_runs,
            "last_run_duration_seconds": self._status.last_run_duration_seconds,
            "last_run_items_processed": self._status.last_run_items_processed,
            "enabled_analysis_types": self.config.enabled_analysis_types,
            "schedule_interval_hours": self.config.schedule_interval_hours,
        }

    async def _run_analysis_cycle(self):
        start = datetime.now(timezone.utc)
        try:
            result = await self.engine.run_analysis_cycle(self.config.enabled_analysis_types)
            self._status.last_run_time = datetime.now(timezone.utc)
            self._status.total_runs += 1
            self._status.last_run_duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
            self._status.last_run_items_processed = result.get("targets_processed", 0)
            logger.info(f"Analysis cycle completed: {result}")
        except Exception as exc:
            logger.error(f"Analysis cycle failed: {exc}")
            self._status.last_run_time = datetime.now(timezone.utc)
            self._status.total_runs += 1


def _build_scheduler_config() -> SchedulerConfig:
    interval = float(os.environ.get("ANALYSIS_SCHEDULE_INTERVAL_HOURS", "6"))
    max_concurrent = int(os.environ.get("ANALYSIS_MAX_CONCURRENT", "5"))
    batch_size = int(os.environ.get("ANALYSIS_BATCH_SIZE", "100"))
    types_str = os.environ.get("ANALYSIS_ENABLED_TYPES", "zero_day,attribution,provenance,decay,attack_prediction")
    enabled_types = [t.strip() for t in types_str.split(",") if t.strip()]
    return SchedulerConfig(
        schedule_interval_hours=interval,
        max_concurrent_llm_calls=max_concurrent,
        batch_size=batch_size,
        enabled_analysis_types=enabled_types,
    )
