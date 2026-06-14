import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from loguru import logger

from app.config import settings


class ClassificationLevel(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


@dataclass
class ClassificationResult:
    level: ClassificationLevel
    basis: str
    detected_patterns: List[str] = field(default_factory=list)


ROLE_ACCESS_MAP: Dict[str, List[ClassificationLevel]] = {
    "admin": [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL, ClassificationLevel.CONFIDENTIAL, ClassificationLevel.RESTRICTED],
    "analyst": [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL, ClassificationLevel.CONFIDENTIAL],
    "viewer": [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL],
}


def _build_retention_days() -> Dict[ClassificationLevel, int]:
    cfg = settings.retention_days_map
    return {
        ClassificationLevel.PUBLIC: cfg.get("PUBLIC", 90),
        ClassificationLevel.INTERNAL: cfg.get("INTERNAL", 180),
        ClassificationLevel.CONFIDENTIAL: cfg.get("CONFIDENTIAL", 365),
        ClassificationLevel.RESTRICTED: cfg.get("RESTRICTED", 365),
    }


RETENTION_DAYS: Dict[ClassificationLevel, int] = _build_retention_days()

_PII_PATTERNS = {
    "id_card": re.compile(r"\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"),
    "phone": re.compile(r"\b1[3-9]\d{9}\b"),
    "bank_card": re.compile(r"\b\d{16,19}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
}

_IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
}

_ATTACK_PATTERN_KEYWORDS = [
    "攻击手法", "attack pattern", "TTP", "战术", "技术", "程序",
    "钓鱼", "phishing", "勒索", "ransomware", "后门", "backdoor",
    "提权", "privilege escalation", "横向移动", "lateral movement",
    "持久化", "persistence", "规避", "evasion", "渗透", "exploit",
]


class DataClassification:
    def __init__(self):
        self.logger = logger.bind(component="data_classification")

    def classify(self, content: str, metadata: Optional[Dict] = None) -> ClassificationResult:
        detected: List[str] = []
        metadata = metadata or {}

        for name, pattern in _PII_PATTERNS.items():
            if pattern.search(content):
                detected.append(f"PII:{name}")

        if detected:
            return ClassificationResult(
                level=ClassificationLevel.RESTRICTED,
                basis=f"包含个人信息: {', '.join(detected)}",
                detected_patterns=detected,
            )

        ioc_detected: List[str] = []
        for name, pattern in _IOC_PATTERNS.items():
            if pattern.search(content):
                ioc_detected.append(f"IoC:{name}")

        if ioc_detected:
            return ClassificationResult(
                level=ClassificationLevel.CONFIDENTIAL,
                basis=f"包含IoC指标: {', '.join(ioc_detected)}",
                detected_patterns=ioc_detected,
            )

        attack_detected: List[str] = []
        content_lower = content.lower()
        for keyword in _ATTACK_PATTERN_KEYWORDS:
            if keyword.lower() in content_lower:
                attack_detected.append(keyword)

        if attack_detected:
            return ClassificationResult(
                level=ClassificationLevel.INTERNAL,
                basis=f"包含攻击手法描述: {', '.join(attack_detected[:5])}",
                detected_patterns=attack_detected[:5],
            )

        return ClassificationResult(
            level=ClassificationLevel.PUBLIC,
            basis="通用安全情报，无敏感标识",
            detected_patterns=[],
        )

    def check_access_allowed(self, user_role: str, classification: ClassificationLevel) -> bool:
        allowed = ROLE_ACCESS_MAP.get(user_role, [ClassificationLevel.PUBLIC])
        return classification in allowed


class DataMinimizer:
    def __init__(self):
        self.logger = logger.bind(component="data_minimizer")

    def minimize_pii(self, content: str, classification: ClassificationLevel) -> str:
        result = content

        if classification == ClassificationLevel.RESTRICTED:
            result = _PII_PATTERNS["phone"].sub(
                lambda m: m.group()[:3] + "****" + m.group()[-4:], result
            )
            result = _PII_PATTERNS["id_card"].sub(
                lambda m: m.group()[:3] + "***********" + m.group()[-4:], result
            )
            result = _PII_PATTERNS["bank_card"].sub(
                lambda m: m.group()[:6] + "******" + m.group()[-4:], result
            )
            result = _PII_PATTERNS["email"].sub(
                lambda m: m.group()[:2] + "***@" + m.group().split("@")[-1], result
            )
        elif classification == ClassificationLevel.CONFIDENTIAL:
            result = _PII_PATTERNS["phone"].sub(
                lambda m: m.group()[:2] + "****" + m.group()[-2:], result
            )
            result = _PII_PATTERNS["id_card"].sub(
                lambda m: m.group()[:2] + "*************" + m.group()[-2:], result
            )
            result = _PII_PATTERNS["bank_card"].sub(
                lambda m: m.group()[:2] + "************" + m.group()[-2:], result
            )
            result = _PII_PATTERNS["email"].sub(
                lambda m: m.group()[0] + "***@" + m.group().split("@")[-1], result
            )
        else:
            for name, pattern in _PII_PATTERNS.items():
                result = pattern.sub(f"[REDACTED_{name.upper()}]", result)

        return result

    def should_store(self, field_name: str, classification: ClassificationLevel) -> bool:
        restricted_no_store = {"bank_card", "password", "credit_card", "cvv", "pin"}
        if classification == ClassificationLevel.RESTRICTED and field_name.lower() in restricted_no_store:
            return False
        return True

    def hash_identifier(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


class RetentionManager:
    def __init__(self):
        self.logger = logger.bind(component="retention_manager")

    def get_expiry_date(self, classification: ClassificationLevel, created_at: datetime) -> datetime:
        days = RETENTION_DAYS[classification]
        return created_at + timedelta(days=days)

    def check_expiry(self, intelligence: Dict) -> bool:
        expires_at_str = intelligence.get("retention_expires_at")
        if not expires_at_str:
            return False
        try:
            if isinstance(expires_at_str, datetime):
                expires_at = expires_at_str
            else:
                expires_at = datetime.fromisoformat(expires_at_str)
            return datetime.now(timezone.utc) > expires_at.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return False

    def apply_retention(self, intelligence: Dict) -> Dict:
        if not self.check_expiry(intelligence):
            return intelligence

        classification_str = intelligence.get("classification_level", "PUBLIC")
        try:
            classification = ClassificationLevel(classification_str)
        except ValueError:
            classification = ClassificationLevel.PUBLIC

        if classification == ClassificationLevel.RESTRICTED:
            minimizer = DataMinimizer()
            content = intelligence.get("content", "")
            intelligence["content"] = minimizer.minimize_pii(content, ClassificationLevel.PUBLIC)
            intelligence["classification_level"] = ClassificationLevel.PUBLIC.value
            intelligence["retention_action"] = "masked"
            self.logger.info(f"RESTRICTED data expired, applied masking: {intelligence.get('id', 'unknown')}")
        else:
            intelligence["content"] = "[DATA_EXPIRED]"
            intelligence["retention_action"] = "expired"
            self.logger.info(f"Data expired, marked as expired: {intelligence.get('id', 'unknown')}")

        return intelligence

    async def run_retention_sweep(self, db_session=None) -> Dict[str, int]:
        result = {"checked": 0, "masked": 0, "expired": 0, "errors": 0}

        if db_session is None:
            self.logger.warning("No db_session provided for retention sweep")
            return result

        try:
            from sqlalchemy import select, update
            from app.db.tables import RawIntelligenceTable

            stmt = select(RawIntelligenceTable).where(
                RawIntelligenceTable.retention_expires_at.isnot(None),
                RawIntelligenceTable.retention_expires_at < datetime.now(timezone.utc),
            )
            db_result = await db_session.execute(stmt)
            records = db_result.scalars().all()

            for record in records:
                result["checked"] += 1
                try:
                    intelligence = {
                        "id": record.id,
                        "content": record.content or "",
                        "classification_level": record.classification_level or "PUBLIC",
                        "retention_expires_at": record.retention_expires_at.isoformat() if record.retention_expires_at else None,
                    }
                    processed = self.apply_retention(intelligence)
                    action = processed.get("retention_action", "expired")

                    update_data = {"content": processed["content"]}
                    if "classification_level" in processed:
                        update_data["classification_level"] = processed["classification_level"]

                    await db_session.execute(
                        update(RawIntelligenceTable)
                        .where(RawIntelligenceTable.id == record.id)
                        .values(**update_data)
                    )

                    if action == "masked":
                        result["masked"] += 1
                    else:
                        result["expired"] += 1
                except Exception as exc:
                    result["errors"] += 1
                    self.logger.error(f"Retention sweep error for {record.id}: {exc}")

            await db_session.commit()
            self.logger.info(f"Retention sweep completed: {result}")
        except Exception as exc:
            self.logger.error(f"Retention sweep failed: {exc}")
            result["errors"] += 1

        return result


class DataSubjectRights:
    def __init__(self):
        self.logger = logger.bind(component="data_subject_rights")
        self._audit_logs: List[Dict] = []

    async def handle_access_request(self, subject_identifier: str, db_session=None) -> Dict:
        request_id = uuid.uuid4().hex[:16]
        self._log_request("access", subject_identifier, "processing")

        try:
            from sqlalchemy import select
            from app.db.tables import RawIntelligenceTable

            records = []
            if db_session is not None:
                stmt = select(RawIntelligenceTable).where(
                    RawIntelligenceTable.content.contains(subject_identifier)
                )
                result = await db_session.execute(stmt)
                rows = result.scalars().all()
            else:
                from app.db.database import async_session_factory
                async with async_session_factory() as session:
                    stmt = select(RawIntelligenceTable).where(
                        RawIntelligenceTable.content.contains(subject_identifier)
                    )
                    result = await session.execute(stmt)
                    rows = result.scalars().all()

            for row in rows:
                if row.classification_level in (ClassificationLevel.RESTRICTED.value, ClassificationLevel.CONFIDENTIAL.value):
                    minimizer = DataMinimizer()
                    content = minimizer.minimize_pii(row.content or "", ClassificationLevel(row.classification_level))
                else:
                    content = row.content or ""

                records.append({
                    "id": row.id,
                    "source": row.source,
                    "content": content,
                    "classification_level": row.classification_level,
                    "collected_at": row.collected_at.isoformat() if row.collected_at else None,
                })

            self._log_request("access", subject_identifier, "completed", request_id)
            return {
                "request_id": request_id,
                "subject_identifier": subject_identifier,
                "records_found": len(records),
                "records": records,
            }
        except Exception as exc:
            self._log_request("access", subject_identifier, f"failed: {exc}", request_id)
            return {"request_id": request_id, "error": "数据治理操作失败"}

    async def handle_deletion_request(self, subject_identifier: str, db_session=None) -> Dict:
        request_id = uuid.uuid4().hex[:16]
        self._log_request("deletion", subject_identifier, "processing")

        try:
            from sqlalchemy import select, update
            from app.db.tables import RawIntelligenceTable

            masked_count = 0
            if db_session is not None:
                stmt = select(RawIntelligenceTable).where(
                    RawIntelligenceTable.content.contains(subject_identifier)
                )
                result = await db_session.execute(stmt)
                rows = result.scalars().all()

                for row in rows:
                    minimizer = DataMinimizer()
                    masked_content = minimizer.minimize_pii(row.content or "", ClassificationLevel.PUBLIC)
                    await db_session.execute(
                        update(RawIntelligenceTable)
                        .where(RawIntelligenceTable.id == row.id)
                        .values(
                            content=masked_content,
                            classification_level=ClassificationLevel.PUBLIC.value,
                        )
                    )
                    masked_count += 1

                await db_session.commit()
            else:
                from app.db.database import async_session_factory
                async with async_session_factory() as session:
                    stmt = select(RawIntelligenceTable).where(
                        RawIntelligenceTable.content.contains(subject_identifier)
                    )
                    result = await session.execute(stmt)
                    rows = result.scalars().all()

                    for row in rows:
                        minimizer = DataMinimizer()
                        masked_content = minimizer.minimize_pii(row.content or "", ClassificationLevel.PUBLIC)
                        await session.execute(
                            update(RawIntelligenceTable)
                            .where(RawIntelligenceTable.id == row.id)
                            .values(
                                content=masked_content,
                                classification_level=ClassificationLevel.PUBLIC.value,
                            )
                        )
                        masked_count += 1

                    await session.commit()

            self._log_request("deletion", subject_identifier, "completed", request_id)
            return {
                "request_id": request_id,
                "subject_identifier": subject_identifier,
                "records_masked": masked_count,
                "note": "数据已脱敏处理而非物理删除，保留分析价值",
            }
        except Exception as exc:
            self._log_request("deletion", subject_identifier, f"failed: {exc}", request_id)
            return {"request_id": request_id, "error": "数据治理操作失败"}

    async def handle_correction_request(self, subject_identifier: str, corrections: Dict, db_session=None) -> Dict:
        request_id = uuid.uuid4().hex[:16]
        self._log_request("correction", subject_identifier, "processing")

        try:
            from sqlalchemy import select, update
            from app.db.tables import RawIntelligenceTable

            corrected_count = 0
            if db_session is not None:
                stmt = select(RawIntelligenceTable).where(
                    RawIntelligenceTable.content.contains(subject_identifier)
                )
                result = await db_session.execute(stmt)
                rows = result.scalars().all()

                for row in rows:
                    new_content = row.content or ""
                    for old_val, new_val in corrections.items():
                        new_content = new_content.replace(old_val, new_val)

                    await db_session.execute(
                        update(RawIntelligenceTable)
                        .where(RawIntelligenceTable.id == row.id)
                        .values(content=new_content)
                    )
                    corrected_count += 1

                await db_session.commit()
            else:
                from app.db.database import async_session_factory
                async with async_session_factory() as session:
                    stmt = select(RawIntelligenceTable).where(
                        RawIntelligenceTable.content.contains(subject_identifier)
                    )
                    result = await session.execute(stmt)
                    rows = result.scalars().all()

                    for row in rows:
                        new_content = row.content or ""
                        for old_val, new_val in corrections.items():
                            new_content = new_content.replace(old_val, new_val)

                        await session.execute(
                            update(RawIntelligenceTable)
                            .where(RawIntelligenceTable.id == row.id)
                            .values(content=new_content)
                        )
                        corrected_count += 1

                    await session.commit()

            self._log_request("correction", subject_identifier, "completed", request_id)
            return {
                "request_id": request_id,
                "subject_identifier": subject_identifier,
                "records_corrected": corrected_count,
            }
        except Exception as exc:
            self._log_request("correction", subject_identifier, f"failed: {exc}", request_id)
            return {"request_id": request_id, "error": "数据治理操作失败"}

    async def handle_export_request(self, subject_identifier: str, db_session=None) -> Dict:
        request_id = uuid.uuid4().hex[:16]
        self._log_request("export", subject_identifier, "processing")

        try:
            from sqlalchemy import select
            from app.db.tables import RawIntelligenceTable

            export_data = []
            if db_session is not None:
                stmt = select(RawIntelligenceTable).where(
                    RawIntelligenceTable.content.contains(subject_identifier)
                )
                result = await db_session.execute(stmt)
                rows = result.scalars().all()
            else:
                from app.db.database import async_session_factory
                async with async_session_factory() as session:
                    stmt = select(RawIntelligenceTable).where(
                        RawIntelligenceTable.content.contains(subject_identifier)
                    )
                    result = await session.execute(stmt)
                    rows = result.scalars().all()

            for row in rows:
                export_data.append({
                    "id": row.id,
                    "source": row.source,
                    "content": row.content,
                    "classification_level": row.classification_level,
                    "collected_at": row.collected_at.isoformat() if row.collected_at else None,
                    "metadata_json": row.metadata_json,
                })

            self._log_request("export", subject_identifier, "completed", request_id)
            return {
                "request_id": request_id,
                "subject_identifier": subject_identifier,
                "export_format": "json",
                "records_exported": len(export_data),
                "data": export_data,
            }
        except Exception as exc:
            self._log_request("export", subject_identifier, f"failed: {exc}", request_id)
            return {"request_id": request_id, "error": "数据治理操作失败"}

    def _log_request(self, request_type: str, subject_id: str, result: str, request_id: str = ""):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "request_type": request_type,
            "subject_id": subject_id,
            "result": result,
        }
        self._audit_logs.append(log_entry)
        self.logger.info(f"Data subject request: type={request_type}, subject={subject_id}, result={result}")


class ComplianceAuditor:
    def __init__(self):
        self.logger = logger.bind(component="compliance_auditor")
        self._access_logs: List[Dict] = []
        self._classification_changes: List[Dict] = []
        self._retention_actions: List[Dict] = []
        self._subject_requests: List[Dict] = []

    def log_data_access(self, user_id: str, intelligence_id: str, action: str):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "intelligence_id": intelligence_id,
            "action": action,
        }
        self._access_logs.append(entry)
        self.logger.info(f"Data access: user={user_id}, intel={intelligence_id}, action={action}")

    def log_classification_change(self, intelligence_id: str, old_level: str, new_level: str):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "intelligence_id": intelligence_id,
            "old_level": old_level,
            "new_level": new_level,
        }
        self._classification_changes.append(entry)
        self.logger.info(f"Classification change: intel={intelligence_id}, {old_level} -> {new_level}")

    def log_retention_action(self, intelligence_id: str, action: str):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "intelligence_id": intelligence_id,
            "action": action,
        }
        self._retention_actions.append(entry)
        self.logger.info(f"Retention action: intel={intelligence_id}, action={action}")

    def log_subject_request(self, request_type: str, subject_id: str, result: str):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_type": request_type,
            "subject_id": subject_id,
            "result": result,
        }
        self._subject_requests.append(entry)
        self.logger.info(f"Subject request: type={request_type}, subject={subject_id}, result={result}")

    def generate_compliance_report(self, start_date: datetime, end_date: datetime) -> Dict:
        start_str = start_date.isoformat()
        end_str = end_date.isoformat()

        filtered_access = [
            e for e in self._access_logs
            if start_str <= e["timestamp"] <= end_str
        ]
        filtered_classification = [
            e for e in self._classification_changes
            if start_str <= e["timestamp"] <= end_str
        ]
        filtered_retention = [
            e for e in self._retention_actions
            if start_str <= e["timestamp"] <= end_str
        ]
        filtered_subject = [
            e for e in self._subject_requests
            if start_str <= e["timestamp"] <= end_str
        ]

        access_by_action: Dict[str, int] = {}
        for entry in filtered_access:
            action = entry["action"]
            access_by_action[action] = access_by_action.get(action, 0) + 1

        subject_by_type: Dict[str, int] = {}
        for entry in filtered_subject:
            rt = entry["request_type"]
            subject_by_type[rt] = subject_by_type.get(rt, 0) + 1

        return {
            "report_period": {"start": start_str, "end": end_str},
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_data_accesses": len(filtered_access),
                "total_classification_changes": len(filtered_classification),
                "total_retention_actions": len(filtered_retention),
                "total_subject_requests": len(filtered_subject),
            },
            "access_by_action": access_by_action,
            "subject_requests_by_type": subject_by_type,
            "classification_changes": filtered_classification,
            "retention_actions_summary": {
                "total": len(filtered_retention),
                "actions": [e["action"] for e in filtered_retention],
            },
            "subject_requests": filtered_subject,
        }


data_classification = DataClassification()
data_minimizer = DataMinimizer()
retention_manager = RetentionManager()
data_subject_rights = DataSubjectRights()
compliance_auditor = ComplianceAuditor()
