import aiohttp
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from loguru import logger

from app.config import settings

LEGAL_NOTICE = (
    "⚠️ 法律合规声明：本采集器仅用于采集Telegram公开频道（public channels）的公开信息。"
    "禁止采集私聊（private chats）和私密群组（private groups）中的内容。"
    "采集行为需遵守：1) 《网络安全法》；2) 《个人信息保护法》；3) 《数据安全法》；"
    "4) Telegram服务条款；5) 当地相关法律法规。"
    "违规使用可能导致法律责任，包括但不限于行政处罚和刑事追诉。"
)


class TelegramCollector:
    API_BASE = "https://api.telegram.org/bot{token}"

    def __init__(self):
        self.logger = logger.bind(collector="telegram")
        self._session: Optional[aiohttp.ClientSession] = None
        self._bot_token = settings.TELEGRAM_BOT_TOKEN

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _is_configured(self) -> bool:
        return bool(self._bot_token and ":" in self._bot_token and len(self._bot_token) > 20)

    def _is_public_channel(self, chat: Dict) -> bool:
        chat_type = chat.get("type", "")
        return chat_type == "channel"

    async def collect(
        self,
        keywords: List[str],
        max_results: int = 50,
        time_range: Optional[Dict] = None,
        **kwargs: Any,
    ) -> List[Dict]:
        self.logger.info(f"Collecting from Telegram: keywords={keywords}, max_results={max_results}")
        self.logger.info(LEGAL_NOTICE)

        if not self._is_configured():
            self.logger.error(
                "Telegram Bot Token not configured. "
                "Set TELEGRAM_BOT_TOKEN in .env. "
                "Get one from @BotFather on Telegram, then add the bot to target channels/groups."
            )
            return []

        session = await self._get_session()
        api_url = self.API_BASE.format(token=self._bot_token)
        items: List[Dict] = []

        try:
            async with session.get(f"{api_url}/getUpdates", params={"limit": 100}) as resp:
                if resp.status != 200:
                    self.logger.error(f"Telegram API returned {resp.status}")
                    return items
                data = await resp.json(content_type=None)
                if not data.get("ok"):
                    self.logger.error(f"Telegram API error: {data.get('description', 'unknown')}")
                    return items

                for update in data.get("result", []):
                    message = update.get("message") or update.get("channel_post")
                    if not message:
                        continue

                    text = message.get("text", "")
                    if not text:
                        continue

                    chat = message.get("chat", {})

                    if not self._is_public_channel(chat):
                        self.logger.debug(f"Skipping non-public chat: type={chat.get('type')}, title={chat.get('title')}")
                        continue

                    keyword_match = not keywords or any(kw.lower() in text.lower() for kw in keywords)
                    if not keyword_match:
                        continue

                    from_user = message.get("from", {})
                    chat_id = chat.get("id", "")
                    chat_title = chat.get("title", chat.get("username", "unknown"))
                    msg_id = message.get("message_id", "")
                    date_ts = message.get("date", 0)

                    items.append({
                        "content": text,
                        "source_url": f"https://t.me/c/{abs(chat_id)}/{msg_id}" if chat_id else "",
                        "metadata": {
                            "source": "telegram",
                            "chat_id": str(chat_id),
                            "chat_title": chat_title,
                            "chat_type": chat.get("type", ""),
                            "author": from_user.get("username", from_user.get("first_name", "unknown")),
                            "message_id": str(msg_id),
                            "date": datetime.fromtimestamp(date_ts, tz=timezone.utc).isoformat() if date_ts else "",
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                            "acquisition_mode": "public_channel",
                        },
                    })

                    if len(items) >= max_results:
                        break

        except Exception as exc:
            self.logger.error(f"Telegram API request failed: {exc}")

        if not items:
            self.logger.warning("Telegram Bot API returned no matching messages. Ensure the bot is added to public channels and has received messages.")
        else:
            self.logger.info(f"Collected {len(items)} real items from Telegram (public channels only)")

        return items
