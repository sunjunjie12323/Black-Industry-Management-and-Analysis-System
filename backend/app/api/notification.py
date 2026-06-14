from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional

from app.core.auth import User, get_current_user, Permission, require_permission
from app.core.notification_service import notification_service


router = APIRouter(prefix="/notifications", tags=["notifications"])


class SendNotificationRequest(BaseModel):
    user_id: str = Field(..., min_length=1)
    type: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1, max_length=256)
    content: Optional[str] = None
    link: Optional[str] = None
    severity: str = Field(default="info", pattern="^(info|low|medium|high|critical)$")


class BroadcastRequest(BaseModel):
    type: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1, max_length=256)
    content: Optional[str] = None
    link: Optional[str] = None
    severity: str = Field(default="info", pattern="^(info|low|medium|high|critical)$")


class WebhookConfigRequest(BaseModel):
    urls: list[str] = Field(default_factory=list)


@router.get("")
async def list_notifications(
    unread_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
):
    items = await notification_service.get_user_notifications(
        user_id=current_user.id,
        unread_only=unread_only,
        limit=limit,
        offset=offset,
    )
    unread_count = await notification_service.get_unread_count(current_user.id)
    return {"items": items, "total": len(items), "unread_count": unread_count}


@router.get("/unread-count")
async def get_unread_count(current_user: User = Depends(get_current_user)):
    count = await notification_service.get_unread_count(current_user.id)
    return {"unread_count": count}


@router.put("/{notification_id}/read")
async def mark_read(
    notification_id: str,
    current_user: User = Depends(get_current_user),
):
    ok = await notification_service.mark_as_read(notification_id, current_user.id)
    if not ok:
        from app.core.exceptions import NotFoundException
        raise NotFoundException(detail="通知不存在")
    return {"message": "已标记为已读"}


@router.put("/read-all")
async def mark_all_read(current_user: User = Depends(get_current_user)):
    count = await notification_service.mark_all_as_read(current_user.id)
    return {"message": f"已标记{count}条通知为已读", "count": count}


@router.delete("/{notification_id}")
async def delete_notification(
    notification_id: str,
    current_user: User = Depends(get_current_user),
):
    ok = await notification_service.delete_notification(notification_id, current_user.id)
    if not ok:
        from app.core.exceptions import NotFoundException
        raise NotFoundException(detail="通知不存在")
    return {"message": "已删除"}


@router.post("/send")
async def send_notification(
    data: SendNotificationRequest,
    current_user: User = Depends(require_permission(Permission.SYSTEM_ADMIN)),
):
    nid = await notification_service.send_notification(
        user_id=data.user_id,
        notification_type=data.type,
        title=data.title,
        content=data.content,
        link=data.link,
        severity=data.severity,
    )
    return {"id": nid, "message": "通知已发送"}


@router.post("/broadcast")
async def broadcast_notification(
    data: BroadcastRequest,
    current_user: User = Depends(require_permission(Permission.SYSTEM_ADMIN)),
):
    count = await notification_service.send_broadcast(
        notification_type=data.type,
        title=data.title,
        content=data.content,
        link=data.link,
        severity=data.severity,
    )
    return {"message": f"已向{count}个用户发送通知", "count": count}


@router.put("/webhook-config")
async def configure_webhooks(
    data: WebhookConfigRequest,
    current_user: User = Depends(require_permission(Permission.SYSTEM_ADMIN)),
):
    notification_service.configure_webhooks(data.urls)
    return {"message": f"已配置{len(data.urls)}个Webhook地址"}
