from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user, require_role
from app.core.data_governance import (
    ClassificationLevel,
    DataClassification,
    DataMinimizer,
    DataSubjectRights,
    ComplianceAuditor,
    RetentionManager,
    data_classification,
    data_minimizer,
    data_subject_rights,
    compliance_auditor,
    retention_manager,
)
from app.core.data_masking import PIIDetector, MaskingStrategy, pii_detector
from app.core.exceptions import ValidationException
from app.db.database import get_db

router = APIRouter(prefix="/compliance", tags=["compliance"])
_bearer = HTTPBearer()


class ClassifyRequest(BaseModel):
    content: str = Field(..., min_length=1)
    metadata: Optional[Dict] = None


class ClassifyResponse(BaseModel):
    level: str
    basis: str
    detected_patterns: List[str]


class MaskRequest(BaseModel):
    content: str = Field(..., min_length=1)
    strategy: str = Field(default="PARTIAL")


class MaskResponse(BaseModel):
    masked_content: str
    pii_count: int
    pii_types: List[str]


class SubjectRequest(BaseModel):
    request_type: str = Field(..., pattern="^(access|deletion|correction|export)$")
    subject_identifier: str = Field(..., min_length=1)
    corrections: Optional[Dict] = None


class SubjectRequestResponse(BaseModel):
    request_id: str
    status: str
    data: Optional[Dict] = None


class ComplianceReportRequest(BaseModel):
    start_date: str = Field(..., description="ISO format datetime")
    end_date: str = Field(..., description="ISO format datetime")


class RetentionSweepResponse(BaseModel):
    checked: int
    masked: int
    expired: int
    errors: int


@router.post("/classify", response_model=ClassifyResponse)
async def classify_intelligence(
    req: ClassifyRequest,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    current_user: User = Depends(get_current_user),
):
    result = data_classification.classify(req.content, req.metadata)
    compliance_auditor.log_data_access(
        current_user.id, "classify_request", "classify"
    )
    return ClassifyResponse(
        level=result.level.value,
        basis=result.basis,
        detected_patterns=result.detected_patterns,
    )


@router.post("/mask", response_model=MaskResponse)
async def mask_content(
    req: MaskRequest,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    current_user: User = Depends(get_current_user),
):
    try:
        strategy = MaskingStrategy(req.strategy)
    except ValueError:
        raise ValidationException(detail=f"不支持的脱敏策略: {req.strategy}，支持: PARTIAL, HASH, REDACT, TOKENIZE")

    pii_matches = pii_detector.detect_pii(req.content)
    masked = pii_detector.mask_pii(req.content, strategy)

    compliance_auditor.log_data_access(
        current_user.id, "mask_request", "mask"
    )

    return MaskResponse(
        masked_content=masked,
        pii_count=len(pii_matches),
        pii_types=list(set(m.pii_type.value for m in pii_matches)),
    )


@router.post("/subject-request", response_model=SubjectRequestResponse)
async def handle_subject_request(
    req: SubjectRequest,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    current_user: User = Depends(get_current_user),
):
    compliance_auditor.log_subject_request(
        req.request_type, req.subject_identifier, "processing"
    )

    if req.request_type == "access":
        result = await data_subject_rights.handle_access_request(req.subject_identifier)
    elif req.request_type == "deletion":
        result = await data_subject_rights.handle_deletion_request(req.subject_identifier)
    elif req.request_type == "correction":
        if not req.corrections:
            raise ValidationException(detail="更正请求必须提供corrections字段")
        result = await data_subject_rights.handle_correction_request(
            req.subject_identifier, req.corrections
        )
    elif req.request_type == "export":
        result = await data_subject_rights.handle_export_request(req.subject_identifier)
    else:
        raise ValidationException(detail=f"不支持的请求类型: {req.request_type}")

    compliance_auditor.log_subject_request(
        req.request_type, req.subject_identifier, "completed"
    )

    return SubjectRequestResponse(
        request_id=result.get("request_id", ""),
        status="completed" if "error" not in result else "failed",
        data=result,
    )


@router.get("/report")
async def get_compliance_report(
    start_date: str,
    end_date: str,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    current_user: User = Depends(get_current_user),
):
    try:
        start = datetime.fromisoformat(start_date)
        end = datetime.fromisoformat(end_date)
    except ValueError:
        raise ValidationException(detail="日期格式无效，请使用ISO格式")

    report = compliance_auditor.generate_compliance_report(start, end)
    compliance_auditor.log_data_access(
        current_user.id, "compliance_report", "read"
    )
    return {"success": True, "data": report}


@router.post("/retention-sweep", response_model=RetentionSweepResponse)
async def run_retention_sweep(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await retention_manager.run_retention_sweep(db)
    compliance_auditor.log_retention_action("batch", "retention_sweep")
    return RetentionSweepResponse(**result)
