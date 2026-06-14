import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import logging

logger = logging.getLogger(__name__)
ws_router = APIRouter()

CONNECTION_TIMEOUT = 60
MAX_CONNECTIONS_PER_USER = 5
ALLOWED_CHANNELS = {"alerts", "pipeline", "system", "intelligence"}


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, user_id: str) -> bool:
        await websocket.accept()
        async with self._lock:
            conns = self.active_connections.setdefault(user_id, set())
            if len(conns) >= MAX_CONNECTIONS_PER_USER:
                await websocket.close(code=4029, reason="Too many connections")
                logger.warning(
                    f"WebSocket connection rejected: user={user_id}, "
                    f"limit={MAX_CONNECTIONS_PER_USER} reached"
                )
                return False
            conns.add(websocket)
        logger.info(
            f"WebSocket connected: user={user_id}, "
            f"user_conns={len(conns)}, "
            f"total_users={len(self.active_connections)}, "
            f"total_conns={self.connection_count}"
        )
        return True

    async def disconnect(self, user_id: str, websocket: WebSocket):
        async with self._lock:
            conns = self.active_connections.get(user_id)
            if conns:
                conns.discard(websocket)
                if not conns:
                    del self.active_connections[user_id]
        remaining = len(self.active_connections.get(user_id, set()))
        logger.info(
            f"WebSocket disconnected: user={user_id}, "
            f"remaining_user_conns={remaining}, "
            f"total_users={len(self.active_connections)}, "
            f"total_conns={self.connection_count}"
        )

    async def send_personal(self, user_id: str, message: dict):
        conns = list(self.active_connections.get(user_id, set()))
        dead = []
        for ws in conns:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(user_id, ws)

    async def broadcast(self, message: dict):
        dead = []
        for uid, conns in list(self.active_connections.items()):
            for ws in list(conns):
                try:
                    await ws.send_json(message)
                except Exception:
                    logger.debug("Failed to send to a websocket connection, removing")
                    dead.append((uid, ws))
        for uid, ws in dead:
            await self.disconnect(uid, ws)

    @property
    def connection_count(self) -> int:
        return sum(len(conns) for conns in self.active_connections.values())


manager = ConnectionManager()


@ws_router.websocket("/ws/realtime")
async def websocket_realtime(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Authentication required")
        return
    try:
        from app.core.auth import decode_access_token
        payload = decode_access_token(token)
        user_id = payload.user_id
        if not user_id:
            await websocket.close(code=4001, reason="Invalid token payload")
            return
    except Exception:
        logger.warning("WebSocket auth failed: invalid token")
        await websocket.close(code=4001, reason="Invalid token")
        return

    connected = await manager.connect(websocket, user_id)
    if not connected:
        return

    try:
        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(), timeout=CONNECTION_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.warning(
                    f"WebSocket timeout: user={user_id}, "
                    f"no message received in {CONNECTION_TIMEOUT}s"
                )
                await websocket.close(code=4002, reason="Connection timeout")
                break
            try:
                msg = json.loads(data)
                _MAX_MESSAGE_SIZE = 10240
                if len(data) > _MAX_MESSAGE_SIZE:
                    await websocket.send_json(
                        {"type": "error", "message": "消息过大", "ts": datetime.now(timezone.utc).isoformat()}
                    )
                    continue
                msg_type = msg.get("type", "ping")
                if msg_type == "ping":
                    await websocket.send_json(
                        {"type": "pong", "ts": datetime.now(timezone.utc).isoformat()}
                    )
                elif msg_type == "subscribe":
                    requested = msg.get("channels", [])
                    valid_channels = [ch for ch in requested if ch in ALLOWED_CHANNELS]
                    if valid_channels != requested:
                        invalid = set(requested) - ALLOWED_CHANNELS
                        logger.warning(f"WebSocket rejected channels: {invalid}")
                    await websocket.send_json(
                        {
                            "type": "subscribed",
                            "channels": valid_channels,
                        }
                    )
            except json.JSONDecodeError as e:
                await websocket.send_json(
                    {
                        "type": "error",
                        "message": "无效的消息格式",
                        "ts": datetime.now(timezone.utc).isoformat(),
                    }
                )
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected: user={user_id}")
    finally:
        await manager.disconnect(user_id, websocket)


async def push_alert(alert_data: dict):
    await manager.broadcast(
        {"type": "alert", "data": alert_data, "ts": datetime.now(timezone.utc).isoformat()}
    )


async def push_pipeline_update(stage: str, status: str, detail: str = ""):
    await manager.broadcast(
        {
            "type": "pipeline",
            "stage": stage,
            "status": status,
            "detail": detail,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
    )
