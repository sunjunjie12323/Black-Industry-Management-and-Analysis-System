from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field

from app.core.auth import User, get_current_user

router = APIRouter(prefix="/backup", tags=["备份恢复"])


class BackupCreateRequest(BaseModel):
    backup_type: str = Field("full", pattern="^(full|incremental|snapshot)$")


class BackupScheduleRequest(BaseModel):
    cron_expression: str = Field(..., min_length=1)
    backup_type: str = Field("full", pattern="^(full|incremental|snapshot)$")


def _get_backup_manager(request: Request):
    mgr = getattr(request.app.state, "backup_manager", None)
    if mgr is None:
        from app.core.backup import BackupManager
        mgr = BackupManager()
        request.app.state.backup_manager = mgr
    return mgr


def _get_disaster_recovery(request: Request):
    dr = getattr(request.app.state, "disaster_recovery", None)
    if dr is None:
        from app.core.backup import DisasterRecovery, BackupManager
        mgr = _get_backup_manager(request)
        dr = DisasterRecovery(backup_manager=mgr)
        request.app.state.disaster_recovery = dr
    return dr


def _get_backup_verifier(request: Request):
    verifier = getattr(request.app.state, "backup_verifier", None)
    if verifier is None:
        from app.core.backup import BackupVerifier
        verifier = BackupVerifier()
        request.app.state.backup_verifier = verifier
    return verifier


@router.post("/create")
async def create_backup(
    req: BackupCreateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_backup_manager(request)
    info = await mgr.create_backup(req.backup_type)
    return {"success": True, "data": info.to_dict()}


@router.post("/{backup_id}/restore")
async def restore_backup(
    backup_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_backup_manager(request)
    result = await mgr.restore_backup(backup_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail="恢复失败")
    return {"success": True, "data": result}


@router.get("/list")
async def list_backups(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_backup_manager(request)
    return {"success": True, "data": mgr.list_backups()}


@router.delete("/{backup_id}")
async def delete_backup(
    backup_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_backup_manager(request)
    deleted = mgr.delete_backup(backup_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Backup not found")
    return {"success": True}


@router.post("/schedule")
async def schedule_backup(
    req: BackupScheduleRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_backup_manager(request)
    schedule_id = mgr.schedule_backup(req.cron_expression, req.backup_type)
    return {"success": True, "data": {"schedule_id": schedule_id}}


@router.get("/{backup_id}/verify")
async def verify_backup(
    backup_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_backup_manager(request)
    verifier = _get_backup_verifier(request)
    result = verifier.verify_backup(backup_id, mgr)
    return {"success": True, "data": result}


@router.post("/{backup_id}/test-restore")
async def test_restore(
    backup_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_backup_manager(request)
    verifier = _get_backup_verifier(request)
    result = await verifier.test_restore(backup_id, mgr)
    return {"success": True, "data": result}


@router.post("/disaster-recovery/failover")
async def failover(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    dr = _get_disaster_recovery(request)
    result = await dr.failover()
    return {"success": True, "data": result}


@router.get("/disaster-recovery/health")
async def disaster_recovery_health(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    dr = _get_disaster_recovery(request)
    return {"success": True, "data": dr.health_check()}


@router.post("/disaster-recovery/sync")
async def sync_standby(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    dr = _get_disaster_recovery(request)
    result = await dr.sync_standby()
    return {"success": True, "data": result}
