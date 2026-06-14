import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from loguru import logger


class NotificationService:
    def __init__(self):
        self._webhook_urls: List[str] = []
        self._email_config: Dict = {}
        self._http_session = None
        self._templates: Dict[str, str] = {
            "threat_alert": "【威胁告警】{title}\n严重级别: {severity}\n详情: {content}\n时间: {timestamp}",
            "task_complete": "【任务完成】{title}\n类型: {task_type}\n结果: {content}\n时间: {timestamp}",
            "review_required": "【审核待办】{title}\n内容类型: {content_type}\n提交人: {submitter}\n时间: {timestamp}",
            "system_alert": "【系统通知】{title}\n详情: {content}\n时间: {timestamp}",
            "finetune_complete": "【微调完成】模型 {model_name} 训练完成\n指标: {metrics}\n时间: {timestamp}",
            "pipeline_complete": "【流水线完成】任务 {task_name} 执行完毕\n状态: {status}\n时间: {timestamp}",
            "security_warning": "【安全警告】{title}\n详情: {content}\n请立即处理！\n时间: {timestamp}",
        }

    @staticmethod
    def _validate_webhook_url(url: str) -> bool:
        if not url or len(url) < 10:
            return False
        if not url.startswith(("http://", "https://")):
            return False
        return True

    def configure_webhooks(self, urls: List[str]):
        validated = []
        for u in urls:
            if self._validate_webhook_url(u):
                validated.append(u)
            else:
                logger.warning(f"无效的Webhook URL已跳过: {u}")
        self._webhook_urls = validated
        logger.info(f"Configured {len(self._webhook_urls)} webhook URLs")

    def configure_email(self, smtp_host: str, smtp_port: int, sender: str, password: str = ""):
        self._email_config = {
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "sender": sender,
            "password": password,
        }

    async def send_notification(
        self,
        user_id: str,
        notification_type: str,
        title: str,
        content: Optional[str] = None,
        link: Optional[str] = None,
        severity: str = "info",
    ) -> str:
        from app.db.database import async_session_factory
        from app.db.tables import NotificationTable

        notification_id = uuid4().hex
        now = datetime.now(timezone.utc)

        async with async_session_factory() as session:
            entry = NotificationTable(
                id=notification_id,
                user_id=user_id,
                type=notification_type,
                title=title,
                content=content,
                link=link,
                is_read=False,
                created_at=now,
            )
            session.add(entry)
            await session.commit()

        template = self._templates.get(notification_type, self._templates["system_alert"])
        formatted = template.format(
            title=title,
            content=content or "",
            severity=severity,
            timestamp=now.isoformat(),
            task_type=notification_type,
            content_type=notification_type,
            submitter="system",
            model_name=title,
            metrics=content or "",
            task_name=title,
            status=content or "",
        )

        if severity in ("high", "critical") and self._webhook_urls:
            await self._dispatch_webhook(notification_id, notification_type, title, content, severity)

        logger.info(f"Notification sent: id={notification_id[:8]}, type={notification_type}, user={user_id[:8]}")
        return notification_id

    async def send_broadcast(
        self,
        notification_type: str,
        title: str,
        content: Optional[str] = None,
        link: Optional[str] = None,
        severity: str = "info",
    ) -> int:
        from app.db.database import async_session_factory
        from app.db.tables import UserTable
        from sqlalchemy import select

        async with async_session_factory() as session:
            result = await session.execute(select(UserTable).where(UserTable.is_active == True))
            users = result.scalars().all()

        count = 0
        for user in users:
            try:
                await self.send_notification(
                    user_id=user.id,
                    notification_type=notification_type,
                    title=title,
                    content=content,
                    link=link,
                    severity=severity,
                )
                count += 1
            except Exception as exc:
                logger.warning(f"Broadcast failed for user {user.id[:8]}: {exc}")

        logger.info(f"Broadcast sent to {count} users: type={notification_type}")
        return count

    async def get_user_notifications(
        self,
        user_id: str,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict]:
        from app.db.database import async_session_factory
        from app.db.tables import NotificationTable
        from sqlalchemy import select

        async with async_session_factory() as session:
            query = select(NotificationTable).where(NotificationTable.user_id == user_id)
            if unread_only:
                query = query.where(NotificationTable.is_read == False)
            query = query.order_by(NotificationTable.created_at.desc()).offset(offset).limit(limit)
            result = await session.execute(query)
            rows = result.scalars().all()

        return [
            {
                "id": row.id,
                "type": row.type,
                "title": row.title,
                "content": row.content,
                "link": row.link,
                "is_read": row.is_read,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]

    async def mark_as_read(self, notification_id: str, user_id: str) -> bool:
        from app.db.database import async_session_factory
        from app.db.tables import NotificationTable
        from sqlalchemy import select

        try:
            async with async_session_factory() as session:
                result = await session.execute(
                    select(NotificationTable).where(
                        NotificationTable.id == notification_id,
                        NotificationTable.user_id == user_id,
                    )
                )
                entry = result.scalar_one_or_none()
                if entry is None:
                    return False
                entry.is_read = True
                await session.commit()
            return True
        except Exception as exc:
            logger.error(f"标记已读失败: notification_id={notification_id}, error={exc}")
            return False

    async def mark_all_as_read(self, user_id: str) -> int:
        from app.db.database import async_session_factory
        from app.db.tables import NotificationTable
        from sqlalchemy import select, update

        async with async_session_factory() as session:
            result = await session.execute(
                update(NotificationTable)
                .where(NotificationTable.user_id == user_id, NotificationTable.is_read == False)
                .values(is_read=True)
            )
            count = result.rowcount
            await session.commit()
        return count

    async def get_unread_count(self, user_id: str) -> int:
        from app.db.database import async_session_factory
        from app.db.tables import NotificationTable
        from sqlalchemy import select, func

        async with async_session_factory() as session:
            result = await session.execute(
                select(func.count(NotificationTable.id)).where(
                    NotificationTable.user_id == user_id,
                    NotificationTable.is_read == False,
                )
            )
            return result.scalar() or 0

    async def delete_notification(self, notification_id: str, user_id: str) -> bool:
        from app.db.database import async_session_factory
        from app.db.tables import NotificationTable
        from sqlalchemy import select

        async with async_session_factory() as session:
            result = await session.execute(
                select(NotificationTable).where(
                    NotificationTable.id == notification_id,
                    NotificationTable.user_id == user_id,
                )
            )
            entry = result.scalar_one_or_none()
            if entry is None:
                return False
            await session.delete(entry)
            await session.commit()
        return True

    async def _send_email(self, to_address: str, subject: str, body: str):
        if not self._email_config:
            return
        try:
            import aiosmtplib
            from email.mime.text import MIMEText
            message = MIMEText(body, "plain", "utf-8")
            message["From"] = self._email_config["sender"]
            message["To"] = to_address
            message["Subject"] = subject
            await aiosmtplib.send(
                message,
                hostname=self._email_config["smtp_host"],
                port=self._email_config["smtp_port"],
                username=self._email_config.get("sender"),
                password=self._email_config.get("password", ""),
                use_tls=True,
            )
            logger.info(f"Email sent to {to_address}")
        except ImportError:
            logger.warning("aiosmtplib not installed, email sending disabled")
        except Exception as exc:
            logger.warning(f"Email send failed: {exc}")

    def _get_http_session(self):
        if self._http_session is None or self._http_session.closed:
            import aiohttp
            self._http_session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
        return self._http_session

    async def close(self):
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
            self._http_session = None

    async def _dispatch_webhook(
        self,
        notification_id: str,
        notification_type: str,
        title: str,
        content: Optional[str],
        severity: str,
    ):
        import asyncio

        session = self._get_http_session()
        payload = {
            "event": notification_type,
            "notification_id": notification_id,
            "title": title,
            "content": content,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        for url in self._webhook_urls:
            max_retries = 2
            for attempt in range(1, max_retries + 1):
                try:
                    async with session.post(url, json=payload) as resp:
                        if resp.status >= 400:
                            logger.warning(f"Webhook dispatch failed (attempt {attempt}): {url} -> {resp.status}")
                            if attempt < max_retries:
                                await asyncio.sleep(1)
                                continue
                        else:
                            logger.debug(f"Webhook dispatched: {url}")
                            break
                except Exception as exc:
                    logger.warning(f"Webhook dispatch error (attempt {attempt}): {url} -> {exc}")
                    if attempt < max_retries:
                        await asyncio.sleep(1)
                    else:
                        logger.error(f"Webhook dispatch最终失败: {url}")


    async def get_user_stats(self, user_id: str) -> Dict:
        from app.db.database import async_session_factory
        from app.db.tables import NotificationTable
        from sqlalchemy import select, func
        async with async_session_factory() as session:
            total_result = await session.execute(
                select(func.count(NotificationTable.id)).where(NotificationTable.user_id == user_id)
            )
            total = total_result.scalar() or 0
            unread_result = await session.execute(
                select(func.count(NotificationTable.id)).where(
                    NotificationTable.user_id == user_id, NotificationTable.is_read == False
                )
            )
            unread = unread_result.scalar() or 0
            type_result = await session.execute(
                select(NotificationTable.type, func.count(NotificationTable.id))
                .where(NotificationTable.user_id == user_id)
                .group_by(NotificationTable.type)
            )
            by_type = {row[0]: row[1] for row in type_result}
        return {"total": total, "unread": unread, "by_type": by_type}


notification_service = NotificationService()
