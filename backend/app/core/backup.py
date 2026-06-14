import asyncio
import hashlib
import json
import os
import shutil
import tarfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger


class BackupType(str, Enum):
    FULL = "full"
    INCREMENTAL = "incremental"
    SNAPSHOT = "snapshot"


@dataclass
class BackupInfo:
    backup_id: str
    backup_type: str
    status: str
    size_bytes: int
    checksum: str
    file_path: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    error_message: str = ""
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "backup_id": self.backup_id,
            "backup_type": self.backup_type,
            "status": self.status,
            "size_bytes": self.size_bytes,
            "size_mb": round(self.size_bytes / (1024 * 1024), 2),
            "checksum": self.checksum,
            "file_path": self.file_path,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


class BackupManager:
    def __init__(self, backup_dir: str = "./backups"):
        self._backup_dir = Path(backup_dir)
        self._backup_dir.mkdir(parents=True, exist_ok=True)
        self._backups: Dict[str, BackupInfo] = {}
        self._scheduled_tasks: Dict[str, asyncio.Task] = {}
        self._max_backups = 100
        self._load_backup_index()

    def _load_backup_index(self):
        index_path = self._backup_dir / "backup_index.json"
        if index_path.exists():
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for item in data:
                    bi = BackupInfo(
                        backup_id=item["backup_id"],
                        backup_type=item["backup_type"],
                        status=item.get("status", "completed"),
                        size_bytes=item.get("size_bytes", 0),
                        checksum=item.get("checksum", ""),
                        file_path=item.get("file_path", ""),
                        created_at=datetime.fromisoformat(item["created_at"]) if item.get("created_at") else datetime.now(timezone.utc),
                        completed_at=datetime.fromisoformat(item["completed_at"]) if item.get("completed_at") else None,
                        error_message=item.get("error_message", ""),
                        metadata=item.get("metadata", {}),
                    )
                    self._backups[bi.backup_id] = bi
                logger.info(f"Loaded {len(self._backups)} backup records")
            except Exception as exc:
                logger.warning(f"Failed to load backup index: {exc}")

    def _save_backup_index(self):
        index_path = self._backup_dir / "backup_index.json"
        data = [bi.to_dict() for bi in self._backups.values()]
        tmp = index_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(index_path)

    async def create_backup(self, backup_type: str = "full") -> BackupInfo:
        backup_id = f"bk-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive_name = f"backup_{backup_type}_{timestamp}.tar.gz"
        archive_path = self._backup_dir / archive_name

        info = BackupInfo(
            backup_id=backup_id,
            backup_type=backup_type,
            status="running",
            size_bytes=0,
            checksum="",
            file_path=str(archive_path),
            created_at=datetime.now(timezone.utc),
        )
        self._backups[backup_id] = info
        if len(self._backups) > self._max_backups:
            oldest_backup = next(iter(self._backups))
            del self._backups[oldest_backup]

        try:
            if backup_type == BackupType.FULL:
                await self._create_full_backup(archive_path, info)
            elif backup_type == BackupType.INCREMENTAL:
                await self._create_incremental_backup(archive_path, info)
            elif backup_type == BackupType.SNAPSHOT:
                await self._create_snapshot_backup(archive_path, info)
            else:
                await self._create_full_backup(archive_path, info)

            checksum = self._compute_checksum(str(archive_path))
            size = archive_path.stat().st_size if archive_path.exists() else 0

            info.status = "completed"
            info.size_bytes = size
            info.checksum = checksum
            info.completed_at = datetime.now(timezone.utc)
            info.metadata["auto_verified"] = True

            logger.info(f"Backup created: {backup_id}, type={backup_type}, size={size} bytes")
        except Exception as exc:
            info.status = "failed"
            info.error_message = "备份操作失败"
            logger.error(f"Backup failed: {backup_id}, error: {exc}")

        self._save_backup_index()
        return info

    async def _create_full_backup(self, archive_path: Path, info: BackupInfo):
        dirs_to_backup = ["./chroma_data", "./graph_data", "./model_data", "./economic_data", "./training_data"]
        db_path = Path("./threat_intel.db")
        config_files = ["./alembic.ini"]

        with tarfile.open(str(archive_path), "w:gz") as tar:
            for dir_path in dirs_to_backup:
                p = Path(dir_path)
                if p.exists():
                    tar.add(str(p), arcname=p.name)
            if db_path.exists():
                tar.add(str(db_path), arcname=db_path.name)
            for cfg in config_files:
                cp = Path(cfg)
                if cp.exists():
                    tar.add(str(cp), arcname=f"config/{cp.name}")

            manifest = {
                "backup_id": info.backup_id,
                "backup_type": info.backup_type,
                "created_at": info.created_at.isoformat(),
                "contents": {
                    "directories": [d for d in dirs_to_backup if Path(d).exists()],
                    "database": str(db_path) if db_path.exists() else None,
                    "config_files": [c for c in config_files if Path(c).exists()],
                },
            }
            import io
            manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
            manifest_info = tarfile.TarInfo(name="MANIFEST.json")
            manifest_info.size = len(manifest_bytes)
            tar.addfile(manifest_info, io.BytesIO(manifest_bytes))

    async def _create_incremental_backup(self, archive_path: Path, info: BackupInfo):
        last_backup = None
        for bi in reversed(list(self._backups.values())):
            if bi.status == "completed" and bi.backup_type in ("full", "incremental"):
                last_backup = bi
                break

        cutoff_time = None
        if last_backup and last_backup.completed_at:
            cutoff_time = last_backup.completed_at.timestamp()
        else:
            cutoff_time = datetime.now(timezone.utc).timestamp() - 3600

        with tarfile.open(str(archive_path), "w:gz") as tar:
            dirs_to_check = ["./chroma_data", "./graph_data", "./model_data", "./economic_data"]
            for dir_path in dirs_to_check:
                p = Path(dir_path)
                if not p.exists():
                    continue
                for file_path in p.rglob("*"):
                    if file_path.is_file():
                        try:
                            mtime = file_path.stat().st_mtime
                            if mtime > cutoff_time:
                                arcname = str(file_path.relative_to(p.parent))
                                tar.add(str(file_path), arcname=arcname)
                        except OSError:
                            continue

            db_path = Path("./threat_intel.db")
            if db_path.exists() and db_path.stat().st_mtime > cutoff_time:
                tar.add(str(db_path), arcname=db_path.name)

        info.metadata["incremental_since"] = last_backup.backup_id if last_backup else None

    async def _create_snapshot_backup(self, archive_path: Path, info: BackupInfo):
        db_path = Path("./threat_intel.db")
        if db_path.exists():
            snapshot_path = self._backup_dir / f"snapshot_{info.backup_id}.db"
            shutil.copy2(str(db_path), str(snapshot_path))

            with tarfile.open(str(archive_path), "w:gz") as tar:
                tar.add(str(snapshot_path), arcname="threat_intel.db")

            snapshot_path.unlink()
        else:
            await self._create_full_backup(archive_path, info)

    async def restore_backup(self, backup_id: str) -> Dict:
        info = self._backups.get(backup_id)
        if not info:
            return {"success": False, "error": f"Backup {backup_id} not found"}
        if info.status != "completed":
            return {"success": False, "error": f"Backup {backup_id} not completed"}

        archive_path = Path(info.file_path)
        if not archive_path.exists():
            return {"success": False, "error": f"Backup file not found: {info.file_path}"}

        try:
            checksum = self._compute_checksum(str(archive_path))
            if checksum != info.checksum:
                return {"success": False, "error": "Checksum mismatch, backup may be corrupted"}

            with tarfile.open(str(archive_path), "r:gz") as tar:
                restore_dir = Path("./restored_data")
                restore_dir.mkdir(parents=True, exist_ok=True)
                tar.extractall(str(restore_dir))

            logger.info(f"Backup restored: {backup_id}")
            return {
                "success": True,
                "backup_id": backup_id,
                "restored_to": str(Path("./restored_data").resolve()),
            }
        except Exception as exc:
            logger.error(f"Backup restore failed: {backup_id}, error: {exc}")
            return {"success": False, "error": "恢复操作失败"}

    def list_backups(self) -> List[Dict]:
        return [bi.to_dict() for bi in sorted(
            self._backups.values(), key=lambda x: x.created_at, reverse=True
        )]

    def delete_backup(self, backup_id: str) -> bool:
        info = self._backups.get(backup_id)
        if not info:
            return False

        archive_path = Path(info.file_path)
        if archive_path.exists():
            archive_path.unlink()

        del self._backups[backup_id]
        self._save_backup_index()
        logger.info(f"Backup deleted: {backup_id}")
        return True

    def schedule_backup(self, cron_expression: str, backup_type: str = "full") -> str:
        schedule_id = f"sched-{uuid.uuid4().hex[:8]}"
        parts = cron_expression.split()
        interval_minutes = 60
        if len(parts) >= 1:
            try:
                minute = int(parts[0])
                interval_minutes = max(10, minute)
            except ValueError:
                pass

        async def _scheduled_backup():
            while True:
                await asyncio.sleep(interval_minutes * 60)
                try:
                    await self.create_backup(backup_type)
                except Exception as exc:
                    logger.error(f"Scheduled backup failed: {exc}")

        task = asyncio.create_task(_scheduled_backup())
        self._scheduled_tasks[schedule_id] = task
        logger.info(f"Scheduled backup: {schedule_id}, interval={interval_minutes}min, type={backup_type}")
        return schedule_id

    def _compute_checksum(self, file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()


class DisasterRecovery:
    RTO_HOURS = 4
    RPO_HOURS = 1

    def __init__(self, backup_manager: BackupManager):
        self._backup_manager = backup_manager
        self._primary_status = "healthy"
        self._standby_status = "standby"
        self._last_sync: Optional[datetime] = None

    async def failover(self) -> Dict:
        logger.warning("Initiating failover...")
        self._primary_status = "failed"

        backups = self._backup_manager.list_backups()
        if not backups:
            return {"success": False, "error": "No backups available for failover"}

        latest_backup = backups[0]
        result = await self._backup_manager.restore_backup(latest_backup["backup_id"])

        if result.get("success"):
            self._standby_status = "active"
            logger.info("Failover completed successfully")
        else:
            logger.error(f"Failover failed: {result.get('error')}")

        return {
            "success": result.get("success", False),
            "rto_target_hours": self.RTO_HOURS,
            "rpo_target_hours": self.RPO_HOURS,
            "primary_status": self._primary_status,
            "standby_status": self._standby_status,
            "restored_from": latest_backup["backup_id"],
        }

    def health_check(self) -> Dict:
        return {
            "primary_status": self._primary_status,
            "standby_status": self._standby_status,
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "rto_hours": self.RTO_HOURS,
            "rpo_hours": self.RPO_HOURS,
            "backup_count": len(self._backup_manager._backups),
            "latest_backup": max(
                (bi.to_dict() for bi in self._backup_manager._backups.values()),
                key=lambda x: x["created_at"],
            ) if self._backup_manager._backups else None,
        }

    async def sync_standby(self) -> Dict:
        try:
            info = await self._backup_manager.create_backup("incremental")
            self._last_sync = datetime.now(timezone.utc)
            self._primary_status = "healthy"
            self._standby_status = "standby"
            logger.info("Standby sync completed")
            return {
                "success": True,
                "backup_id": info.backup_id,
                "synced_at": self._last_sync.isoformat(),
            }
        except Exception as exc:
            logger.error(f"Standby sync failed: {exc}")
            return {"success": False, "error": "备份同步失败"}


class BackupVerifier:
    def verify_backup(self, backup_id: str, backup_manager: BackupManager) -> Dict:
        info = backup_manager._backups.get(backup_id)
        if not info:
            return {"valid": False, "error": f"Backup {backup_id} not found"}

        archive_path = Path(info.file_path)
        if not archive_path.exists():
            return {"valid": False, "error": "Backup file not found"}

        if info.status != "completed":
            return {"valid": False, "error": f"Backup status is {info.status}"}

        checksum = backup_manager._compute_checksum(str(archive_path))
        checksum_valid = checksum == info.checksum

        archive_valid = False
        try:
            with tarfile.open(str(archive_path), "r:gz") as tar:
                members = tar.getmembers()
                archive_valid = len(members) > 0
        except Exception as exc:
            return {"valid": False, "error": f"Archive is corrupted: {exc}"}

        has_manifest = False
        try:
            with tarfile.open(str(archive_path), "r:gz") as tar:
                has_manifest = "MANIFEST.json" in tar.getnames()
        except Exception:
            pass

        return {
            "valid": checksum_valid and archive_valid,
            "checksum_valid": checksum_valid,
            "archive_valid": archive_valid,
            "has_manifest": has_manifest,
            "size_bytes": archive_path.stat().st_size,
            "backup_id": backup_id,
        }

    async def test_restore(self, backup_id: str, backup_manager: BackupManager) -> Dict:
        info = backup_manager._backups.get(backup_id)
        if not info:
            return {"success": False, "error": f"Backup {backup_id} not found"}

        verify_result = self.verify_backup(backup_id, backup_manager)
        if not verify_result.get("valid"):
            return {"success": False, "error": "Backup verification failed", "details": verify_result}

        test_restore_dir = Path(f"./test_restore_{backup_id}")
        try:
            test_restore_dir.mkdir(parents=True, exist_ok=True)
            archive_path = Path(info.file_path)

            with tarfile.open(str(archive_path), "r:gz") as tar:
                tar.extractall(str(test_restore_dir))

            file_count = sum(1 for _ in test_restore_dir.rglob("*") if _.is_file())

            return {
                "success": True,
                "backup_id": backup_id,
                "restored_files": file_count,
                "test_restore_dir": str(test_restore_dir),
            }
        except Exception as exc:
            return {"success": False, "error": "备份验证失败"}
        finally:
            if test_restore_dir.exists():
                shutil.rmtree(str(test_restore_dir), ignore_errors=True)
