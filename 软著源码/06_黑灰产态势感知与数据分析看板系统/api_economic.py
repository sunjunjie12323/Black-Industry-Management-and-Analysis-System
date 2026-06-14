from fastapi import APIRouter, Depends, Request
from app.core.auth import get_current_user, User

router = APIRouter(prefix="/economic", tags=["economic"])


@router.get("/dashboard")
async def get_dashboard(
    current_user: User = Depends(get_current_user),
):
    return {"message": "经济系统已移除，请使用情报分析相关功能", "status": "deprecated"}


@router.get("/data-sources")
async def get_data_sources(
    current_user: User = Depends(get_current_user),
):
    return {
        "sources": [
            {"sector": "威胁情报", "provider": "CISA KEV", "status": "available"},
            {"sector": "恶意URL", "provider": "URLhaus", "status": "available"},
            {"sector": "恶意软件", "provider": "MalwareBazaar", "status": "available"},
        ],
        "total": 3,
    }


@router.get("/impact")
async def get_impact_alias(
    current_user: User = Depends(get_current_user),
):
    return {
        "impact_summary": {
            "threats_detected": 0,
            "threats_mitigated": 0,
            "economic_loss_prevented": 0,
        },
        "data_sources": [
            {"sector": "威胁情报", "provider": "CISA KEV", "status": "available"},
            {"sector": "恶意URL", "provider": "URLhaus", "status": "available"},
            {"sector": "恶意软件", "provider": "MalwareBazaar", "status": "available"},
        ],
        "status": "active",
    }
