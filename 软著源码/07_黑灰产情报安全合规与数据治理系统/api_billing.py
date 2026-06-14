from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field

from app.core.auth import User, get_current_user

router = APIRouter(prefix="/billing", tags=["SLA与计费"])


class SLACheckRequest(BaseModel):
    start_date: str = Field(..., min_length=1)
    end_date: str = Field(..., min_length=1)
    metrics: Optional[Dict] = None


class UsageRecordRequest(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=64)
    resource_type: str = Field(..., min_length=1, max_length=32)
    amount: float = Field(..., ge=0)
    metadata: Optional[Dict] = None


class TenantPlanRequest(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=64)
    plan_name: str = Field(..., pattern="^(free|pro|enterprise)$")


class BillRequest(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=64)
    period: str = Field(..., min_length=1, max_length=16)


def _get_billing_engine(request: Request):
    engine = getattr(request.app.state, "billing_engine", None)
    if engine is None:
        from app.core.billing import BillingEngine
        engine = BillingEngine()
        request.app.state.billing_engine = engine
    return engine


def _get_sla_definition(request: Request):
    sla = getattr(request.app.state, "sla_definition", None)
    if sla is None:
        from app.core.billing import SLADefinition
        sla = SLADefinition()
        request.app.state.sla_definition = sla
    return sla


@router.post("/sla/check")
async def check_sla_compliance(
    req: SLACheckRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    sla = _get_sla_definition(request)
    report = sla.check_sla_compliance(req.start_date, req.end_date, req.metrics)
    return {"success": True, "data": report.to_dict()}


@router.get("/plans")
async def list_plans(
    current_user: User = Depends(get_current_user),
):
    from app.core.billing import compare_plans
    return {"success": True, "data": compare_plans()}


@router.get("/plans/{plan_name}")
async def get_plan(
    plan_name: str,
    current_user: User = Depends(get_current_user),
):
    from app.core.billing import get_plan
    plan = get_plan(plan_name)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    return {"success": True, "data": plan.to_dict()}


@router.post("/tenant/plan")
async def set_tenant_plan(
    req: TenantPlanRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = _get_billing_engine(request)
    engine.set_tenant_plan(req.tenant_id, req.plan_name)
    return {"success": True}


@router.get("/tenant/{tenant_id}/plan")
async def get_tenant_plan(
    tenant_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = _get_billing_engine(request)
    plan_name = engine.get_tenant_plan(tenant_id)
    return {"success": True, "data": {"tenant_id": tenant_id, "plan_name": plan_name}}


@router.post("/usage/record")
async def record_usage(
    req: UsageRecordRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = _get_billing_engine(request)
    engine.record_usage(req.tenant_id, req.resource_type, req.amount, req.metadata)
    return {"success": True}


@router.post("/bill/calculate")
async def calculate_bill(
    req: BillRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = _get_billing_engine(request)
    bill = engine.calculate_bill(req.tenant_id, req.period)
    if not bill:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"success": True, "data": bill.to_dict()}


@router.get("/usage/{tenant_id}")
async def get_usage_summary(
    tenant_id: str,
    period: str = Query(..., min_length=1),
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    engine = _get_billing_engine(request)
    summary = engine.get_usage_summary(tenant_id, period)
    return {"success": True, "data": summary.to_dict()}
