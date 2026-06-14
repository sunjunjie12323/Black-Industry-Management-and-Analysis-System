import asyncio
import json
import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field, asdict
from loguru import logger

from app.config import settings
from app.core.message_queue import TOPIC_ALERT_TRIGGERED
from app.core.metrics import INTELLIGENCE_COLLECTED


_SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@dataclass
class AlertRule:
    rule_id: str
    name: str
    description: str
    conditions: Dict
    severity: str = "high"
    enabled: bool = True
    cooldown_minutes: int = 60
    last_triggered: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str
    intelligence_id: str
    entity_value: str
    entity_type: str
    threat_level: str
    timestamp: str
    acknowledged: bool = False
    notification_sent: Dict[str, bool] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


class AlertEngine:
    def __init__(self, persist_dir: str = "./alert_data", notification_service=None, max_history: int = 1000, message_queue=None):
        self.persist_dir = persist_dir
        self.max_history = max_history
        self.rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.notification_channels: Dict[str, Callable] = {}
        self._llm = None
        self._notification_service = notification_service
        self.message_queue = message_queue
        self._lock = asyncio.Lock()
        self._load()
        self._init_default_rules()

    def set_llm(self, llm):
        self._llm = llm

    def set_notification_service(self, service):
        self._notification_service = service

    def _init_default_rules(self):
        from app.config import settings
        if settings.ALERT_RULES_JSON:
            try:
                custom_rules = json.loads(settings.ALERT_RULES_JSON)
                for rule_data in custom_rules:
                    rule = AlertRule(**rule_data)
                    if rule.rule_id not in self.rules:
                        self.rules[rule.rule_id] = rule
                if self.rules:
                    return
            except (json.JSONDecodeError, TypeError):
                pass
        # Reference defaults - override via ALERT_RULES_JSON env var
        defaults = [
            AlertRule("rule-critical-threat", "高危威胁检测", "检测到critical级别威胁情报",
                      {"threat_level": "critical"}, "critical", True, 30),
            AlertRule("rule-zero-day", "零日漏洞检测", "检测到零日漏洞相关情报",
                      {"keyword": "0day,zero-day,零日,CVE-2024,CVE-2025,CVE-2026"}, "critical", True, 60),
            AlertRule("rule-ransomware", "勒索软件检测", "检测到勒索软件相关情报",
                      {"keyword": "ransomware,勒索,LockBit,BlackCat,ALPHV"}, "high", True, 120),
            AlertRule("rule-apt", "APT攻击检测", "检测到APT组织活动",
                      {"keyword": "APT,advanced persistent threat,国家级攻击"}, "high", True, 240),
            AlertRule("rule-supply-chain", "供应链攻击检测", "检测到供应链攻击",
                      {"keyword": "supply chain,供应链,dependency"}, "high", True, 120),
            AlertRule("rule-darkweb-sale", "暗网交易检测", "检测到暗网数据/工具出售",
                      {"keyword": "暗网,darknet,sale,出售,贩卖"}, "medium", True, 180),
            AlertRule("rule-data-breach", "数据泄露检测", "检测到数据泄露事件",
                      {"keyword": "data breach,数据泄露,信息泄露"}, "high", True, 60),
            AlertRule("rule-botnet", "僵尸网络检测", "检测到僵尸网络活动",
                      {"keyword": "botnet,僵尸网络,C2,command and control"}, "medium", True, 240),
            AlertRule("rule-high-confidence", "高置信度威胁", "置信度超过0.9的威胁情报",
                      {"min_confidence": 0.9}, "high", True, 60),
            AlertRule("rule-multi-entity", "多实体关联威胁", "包含3个以上实体的威胁情报",
                      {"min_entity_count": 3}, "medium", True, 120),
        ]
        for rule in defaults:
            if rule.rule_id not in self.rules:
                self.rules[rule.rule_id] = rule

    def register_notification_channel(self, name: str, handler: Callable):
        self.notification_channels[name] = handler

    async def evaluate_intelligence(self, intelligence_data: dict, skip_cooldown: bool = False) -> list[dict]:
        async with self._lock:
            triggered = []

            rule_alerts = await self._rule_based_evaluate(intelligence_data, skip_cooldown)
            triggered.extend(rule_alerts)

            if self._llm:
                try:
                    llm_alerts = await self._llm_evaluate(intelligence_data, rule_alerts)
                    triggered.extend(llm_alerts)
                except Exception as e:
                    logger.warning(f"LLM alert evaluation failed, degrading to rule-based fallback: {e}")
                    fallback_alerts = await self._rule_based_fallback_evaluate(intelligence_data, rule_alerts)
                    triggered.extend(fallback_alerts)

            seen_ids = set()
            deduped = []
            for a in triggered:
                if a["alert_id"] not in seen_ids:
                    seen_ids.add(a["alert_id"])
                    deduped.append(a)

            self._trim_history()

            if deduped:
                self._save()

            return deduped

    async def _rule_based_evaluate(self, intel_data: dict, skip_cooldown: bool = False) -> list[dict]:
        triggered_alerts = []
        content = intel_data.get("content", "")
        threat_level = intel_data.get("threat_level", "info")
        entity_type = intel_data.get("entity_type", "")
        intel_id = intel_data.get("id", "")
        entity_value = intel_data.get("value", intel_data.get("title", ""))
        confidence = intel_data.get("confidence", 0.5)
        entity_count = intel_data.get("entity_count", 0)

        for rule in self.rules.values():
            if not rule.enabled:
                continue
            if not skip_cooldown and self._is_in_cooldown(rule):
                continue
            if self._matches_rule(rule, content, threat_level, entity_type, confidence, entity_count):
                alert = Alert(
                    alert_id=hashlib.md5(f"{rule.rule_id}:{intel_id}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:16],
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    title=f"[{rule.name}] {entity_value[:50]}",
                    description=f"规则'{rule.name}'触发: {content[:100]}",
                    intelligence_id=intel_id,
                    entity_value=entity_value,
                    entity_type=entity_type,
                    threat_level=threat_level,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
                self.active_alerts[alert.alert_id] = alert
                self.alert_history.append(alert)
                rule.last_triggered = datetime.now(timezone.utc).isoformat()
                triggered_alerts.append(alert.to_dict())
                await self._dispatch_notifications(alert)
                await self._publish_alert(alert)
                try:
                    INTELLIGENCE_COLLECTED.labels(source=intel_data.get("source", "unknown"), status="alerted").inc()
                except Exception:
                    pass

        return triggered_alerts

    async def _llm_evaluate(self, intel_data: dict, existing_alerts: list[dict]) -> list[dict]:
        content = intel_data.get("content", "")
        threat_level = intel_data.get("threat_level", "info")
        intel_id = intel_data.get("id", "")

        existing_rules = [a.get("rule_name", "") for a in existing_alerts]

        prompt = (
            f"请分析以下威胁情报，判断是否需要生成额外的安全告警。\n\n"
            f"情报内容: {content[:1000]}\n"
            f"威胁等级: {threat_level}\n"
            f"已触发的规则: {', '.join(existing_rules) if existing_rules else '无'}\n\n"
            f"请判断是否存在以下情况需要额外告警:\n"
            f"1. 跨平台协同攻击迹象\n"
            f"2. 针对特定行业或地区的定向攻击\n"
            f"3. 新型攻击手法或未知威胁模式\n"
            f"4. 大规模数据泄露或供应链风险\n\n"
            f"如果需要额外告警，请以JSON数组格式返回:\n"
            f'[{{"severity": "critical/high/medium/low/info", "title": "告警标题", "description": "告警描述", "reasoning": "判断依据"}}]\n'
            f"如果不需要额外告警，返回空数组: []"
        )

        result = await self._llm.generate(
            prompt=prompt,
            system_prompt="你是威胁情报告警分析专家，负责判断情报是否需要生成安全告警。只返回JSON，不要其他内容。",
            temperature=settings.LLM_TEMPERATURE_CREATIVE,
            max_tokens=settings.LLM_MAX_TOKENS_MEDIUM,
        )

        llm_alerts = []
        try:
            json_str = result.strip()
            if json_str.startswith("```"):
                import re
                json_str = re.sub(r'^```\w*\n?', '', json_str)
                json_str = re.sub(r'\n?```$', '', json_str)
            parsed = json.loads(json_str)
            if isinstance(parsed, list):
                for item in parsed[:5]:
                    if not isinstance(item, dict):
                        continue
                    severity = item.get("severity", "medium")
                    if severity not in _SEVERITY_ORDER:
                        severity = "medium"
                    alert = Alert(
                        alert_id=hashlib.md5(f"llm:{intel_id}:{item.get('title', '')}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:16],
                        rule_id="llm-evaluated",
                        rule_name="LLM智能评估",
                        severity=severity,
                        title=item.get("title", "LLM评估告警"),
                        description=item.get("description", ""),
                        intelligence_id=intel_id,
                        entity_value=intel_data.get("value", ""),
                        entity_type=intel_data.get("entity_type", ""),
                        threat_level=threat_level,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    )
                    self.active_alerts[alert.alert_id] = alert
                    self.alert_history.append(alert)
                    llm_alerts.append(alert.to_dict())
                    await self._dispatch_notifications(alert)
                    await self._publish_alert(alert)
        except (json.JSONDecodeError, TypeError) as e:
            logger.debug(f"LLM alert evaluation response parse failed: {e}")

        return llm_alerts

    def _trim_history(self):
        if len(self.alert_history) > self.max_history:
            excess = len(self.alert_history) - self.max_history
            self.alert_history = self.alert_history[excess:]

    async def _rule_based_fallback_evaluate(self, intel_data: dict, existing_alerts: list[dict]) -> list[dict]:
        content = intel_data.get("content", "")
        threat_level = intel_data.get("threat_level", "info")
        intel_id = intel_data.get("id", "")
        entity_value = intel_data.get("value", intel_data.get("title", ""))

        existing_rule_ids = {a.get("rule_id", "") for a in existing_alerts}
        fallback_alerts = []

        fallback_patterns = [
            {
                "id": "fallback-cross-platform",
                "keywords": ["跨平台", "多平台", "cross-platform", "协同攻击", "coordinated attack"],
                "severity": "high",
                "title": "跨平台协同攻击迹象",
            },
            {
                "id": "fallback-targeted-attack",
                "keywords": ["定向攻击", "targeted", "针对性", "特定行业", "特定地区", "APT"],
                "severity": "high",
                "title": "定向攻击迹象",
            },
            {
                "id": "fallback-novel-attack",
                "keywords": ["新型攻击", "novel attack", "未知漏洞", "0day", "零日", "新型手法", "新变种"],
                "severity": "critical",
                "title": "新型攻击手法检测",
            },
            {
                "id": "fallback-mass-breach",
                "keywords": ["大规模泄露", "mass breach", "供应链风险", "supply chain risk", "千万级", "百万级"],
                "severity": "critical",
                "title": "大规模数据泄露/供应链风险",
            },
        ]

        content_lower = content.lower()
        for pattern in fallback_patterns:
            if pattern["id"] in existing_rule_ids:
                continue
            if any(kw.lower() in content_lower for kw in pattern["keywords"]):
                alert = Alert(
                    alert_id=hashlib.md5(f"{pattern['id']}:{intel_id}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:16],
                    rule_id=pattern["id"],
                    rule_name="规则降级评估",
                    severity=pattern["severity"],
                    title=f"[降级评估] {pattern['title']}: {entity_value[:50]}",
                    description=f"LLM评估不可用，规则降级检测: {content[:100]}",
                    intelligence_id=intel_id,
                    entity_value=entity_value,
                    entity_type=intel_data.get("entity_type", ""),
                    threat_level=threat_level,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
                self.active_alerts[alert.alert_id] = alert
                self.alert_history.append(alert)
                fallback_alerts.append(alert.to_dict())
                await self._dispatch_notifications(alert)
                await self._publish_alert(alert)

        return fallback_alerts

    def check_threshold_rules(self, threat_level: str, category: str, confidence: float) -> list[dict]:
        triggered = []
        threat_rank = _SEVERITY_ORDER.get(threat_level, 0)

        for rule in self.rules.values():
            if not rule.enabled:
                continue
            conditions = rule.conditions

            if "threat_level" in conditions:
                required_rank = _SEVERITY_ORDER.get(conditions["threat_level"], 0)
                if threat_rank < required_rank:
                    continue

            if "min_confidence" in conditions:
                if confidence < conditions["min_confidence"]:
                    continue

            if "category" in conditions:
                if category != conditions["category"]:
                    continue

            triggered.append({
                "rule_id": rule.rule_id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "conditions_met": {
                    "threat_level": threat_level,
                    "category": category,
                    "confidence": confidence,
                },
            })

        return triggered

    async def create_alert(self, alert_data: dict, db_session=None) -> dict:
        alert_id = alert_data.get("alert_id") or hashlib.md5(
            f"manual:{alert_data.get('title', '')}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

        severity = alert_data.get("severity", "medium")
        if severity not in _SEVERITY_ORDER:
            severity = "medium"

        alert = Alert(
            alert_id=alert_id,
            rule_id=alert_data.get("rule_id", "manual"),
            rule_name=alert_data.get("rule_name", "手动创建"),
            severity=severity,
            title=alert_data.get("title", "未命名告警"),
            description=alert_data.get("description", ""),
            intelligence_id=alert_data.get("intelligence_id", ""),
            entity_value=alert_data.get("entity_value", ""),
            entity_type=alert_data.get("entity_type", ""),
            threat_level=alert_data.get("threat_level", "info"),
            timestamp=alert_data.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        )

        self.active_alerts[alert.alert_id] = alert
        self.alert_history.append(alert)
        self._trim_history()
        self._save()

        await self._dispatch_notifications(alert)
        await self._publish_alert(alert)

        if self._notification_service:
            try:
                await self._notification_service.send_broadcast(
                    notification_type="threat_alert",
                    title=alert.title,
                    content=alert.description,
                    severity=alert.severity,
                )
            except Exception as e:
                logger.warning(f"Broadcast notification failed: {e}")

        try:
            from app.db.tables import NotificationTable
            from uuid import uuid4

            entry = NotificationTable(
                id=uuid4().hex,
                user_id="system",
                type="threat_alert",
                title=alert.title,
                content=alert.description,
                link=f"/alerts/{alert.alert_id}",
                is_read=False,
                created_at=datetime.now(timezone.utc),
            )
            if db_session is not None:
                db_session.add(entry)
                await db_session.commit()
            else:
                from app.db.database import async_session_factory
                async with async_session_factory() as session:
                    session.add(entry)
                    await session.commit()
        except Exception as e:
            logger.debug(f"DB notification storage failed: {e}")

        return alert.to_dict()

    async def get_active_alerts(self, user_id: str, limit: int = 50, db_session=None) -> list[dict]:
        alerts = list(self.active_alerts.values())
        alerts.sort(key=lambda a: (_SEVERITY_ORDER.get(a.severity, 0), a.timestamp), reverse=True)
        result = [a.to_dict() for a in alerts[:limit]]

        try:
            from app.db.tables import NotificationTable
            from sqlalchemy import select

            if db_session is not None:
                db_query = select(NotificationTable).where(
                    NotificationTable.user_id == user_id,
                    NotificationTable.type == "threat_alert",
                    NotificationTable.is_read == False,
                ).order_by(NotificationTable.created_at.desc()).limit(limit)
                db_result = await db_session.execute(db_query)
                db_rows = db_result.scalars().all()
            else:
                from app.db.database import async_session_factory
                async with async_session_factory() as session:
                    db_query = select(NotificationTable).where(
                        NotificationTable.user_id == user_id,
                        NotificationTable.type == "threat_alert",
                        NotificationTable.is_read == False,
                    ).order_by(NotificationTable.created_at.desc()).limit(limit)
                    db_result = await session.execute(db_query)
                    db_rows = db_result.scalars().all()

            for row in db_rows:
                db_alert = {
                    "alert_id": f"db-{row.id}",
                    "rule_id": "notification",
                    "rule_name": "系统通知",
                    "severity": "medium",
                    "title": row.title,
                    "description": row.content or "",
                    "intelligence_id": "",
                    "entity_value": "",
                    "entity_type": "",
                    "threat_level": "info",
                    "timestamp": row.created_at.isoformat() if row.created_at else "",
                    "acknowledged": row.is_read,
                    "source": "database",
                }
                existing_ids = {a["alert_id"] for a in result}
                if db_alert["alert_id"] not in existing_ids:
                    result.append(db_alert)
        except Exception as e:
            logger.debug(f"DB alert fetch failed: {e}")

        return result[:limit]

    async def acknowledge_alert(self, alert_id: str, db_session=None) -> bool:
        async with self._lock:
            if alert_id in self.active_alerts:
                self.active_alerts[alert_id].acknowledged = True
                self._save()
                return True

        if alert_id.startswith("db-"):
            db_id = alert_id[3:]
            try:
                from app.db.tables import NotificationTable
                from sqlalchemy import select

                if db_session is not None:
                    result = await db_session.execute(
                        select(NotificationTable).where(NotificationTable.id == db_id)
                    )
                    entry = result.scalar_one_or_none()
                    if entry:
                        entry.is_read = True
                        await db_session.commit()
                        return True
                else:
                    from app.db.database import async_session_factory
                    async with async_session_factory() as session:
                        result = await session.execute(
                            select(NotificationTable).where(NotificationTable.id == db_id)
                        )
                        entry = result.scalar_one_or_none()
                        if entry:
                            entry.is_read = True
                            await session.commit()
                            return True
            except Exception as e:
                logger.debug(f"DB alert acknowledge failed: {e}")

        return False

    def _is_in_cooldown(self, rule: AlertRule) -> bool:
        if not rule.last_triggered:
            return False
        try:
            last = datetime.fromisoformat(rule.last_triggered)
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - last).total_seconds() / 60
            return elapsed < rule.cooldown_minutes
        except Exception:
            return False

    def _matches_rule(self, rule: AlertRule, content: str, threat_level: str, entity_type: str, confidence: float = 0.5, entity_count: int = 0) -> bool:
        conditions = rule.conditions
        if "threat_level" in conditions:
            required_rank = _SEVERITY_ORDER.get(conditions["threat_level"], 0)
            actual_rank = _SEVERITY_ORDER.get(threat_level, 0)
            if actual_rank < required_rank:
                return False
        if "entity_type" in conditions:
            if entity_type != conditions["entity_type"]:
                return False
        if "min_confidence" in conditions:
            if confidence < conditions["min_confidence"]:
                return False
        if "min_entity_count" in conditions:
            if entity_count < conditions["min_entity_count"]:
                return False
        if "keyword" in conditions:
            keywords = [k.strip() for k in conditions["keyword"].split(",")]
            content_lower = content.lower()
            if not any(kw.lower() in content_lower for kw in keywords):
                return False
        return True

    async def _dispatch_notifications(self, alert: Alert):
        for channel_name, handler in self.notification_channels.items():
            try:
                result = handler(alert)
                if hasattr(result, '__await__'):
                    result = await result
                alert.notification_sent[channel_name] = True
                logger.info(f"Alert notification sent via {channel_name}: {alert.title}")
            except Exception as e:
                alert.notification_sent[channel_name] = False
                logger.warning(f"Failed to send notification via {channel_name}: {e}")

        if self._notification_service:
            try:
                await self._notification_service.send_broadcast(
                    notification_type="threat_alert",
                    title=alert.title,
                    content=alert.description,
                    severity=alert.severity,
                )
            except Exception as e:
                logger.debug(f"Notification service broadcast failed: {e}")

    async def _publish_alert(self, alert: Alert):
        if self.message_queue:
            try:
                await self.message_queue.publish(
                    TOPIC_ALERT_TRIGGERED,
                    alert.to_dict(),
                )
            except Exception as exc:
                logger.warning(f"Failed to publish alert to message queue: {exc}")

    def get_alert_stats(self) -> Dict:
        active = list(self.active_alerts.values())
        return {
            "total_alerts": len(self.alert_history),
            "active_alerts": len(active),
            "acknowledged": sum(1 for a in active if a.acknowledged),
            "by_severity": {
                "critical": sum(1 for a in active if a.severity == "critical"),
                "high": sum(1 for a in active if a.severity == "high"),
                "medium": sum(1 for a in active if a.severity == "medium"),
                "low": sum(1 for a in active if a.severity == "low"),
                "info": sum(1 for a in active if a.severity == "info"),
            },
            "rules_total": len(self.rules),
            "rules_enabled": sum(1 for r in self.rules.values() if r.enabled),
        }

    def get_stats(self) -> Dict:
        return {
            "active_alerts_count": len(self.active_alerts),
            "history_count": len(self.alert_history),
            "max_history": self.max_history,
            "history_utilization": round(len(self.alert_history) / self.max_history, 4) if self.max_history > 0 else 0,
            "rules_count": len(self.rules),
            "rules_enabled": sum(1 for r in self.rules.values() if r.enabled),
            "notification_channels": list(self.notification_channels.keys()),
            "llm_configured": self._llm is not None,
        }

    def _save(self):
        os.makedirs(self.persist_dir, exist_ok=True)
        data = {
            "rules": {k: v.to_dict() for k, v in self.rules.items()},
            "active_alerts": {k: v.to_dict() for k, v in self.active_alerts.items()},
            "alert_history": [a.to_dict() for a in self.alert_history[-500:]],
        }
        with open(os.path.join(self.persist_dir, "alerts.json"), "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _load(self):
        path = os.path.join(self.persist_dir, "alerts.json")
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                for k, v in data.get("rules", {}).items():
                    self.rules[k] = AlertRule(**v)
                for k, v in data.get("active_alerts", {}).items():
                    self.active_alerts[k] = Alert(**v)
                self.alert_history = [Alert(**a) for a in data.get("alert_history", [])]
                self._trim_history()
                logger.info(f"AlertEngine loaded: {len(self.rules)} rules, {len(self.active_alerts)} active alerts")
            except Exception as e:
                logger.warning(f"Failed to load alert data: {e}")
