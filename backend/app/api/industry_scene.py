import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user, require_role, Role
from app.core.exceptions import AppException, ValidationException, NotFoundException
from app.core.validators import validate_domain_object
from app.db.database import get_db
from app.db.tables import IndustrySceneConfigTable

router = APIRouter(prefix="/industry-scene", tags=["行业场景"])


INDUSTRY_STRATEGIES = {
    "smart_manufacturing": {
        "id": "smart_manufacturing",
        "name": "智能制造",
        "description": "黑灰产情报在智能制造领域的分析场景——聚焦工业间谍、供应链攻击、设备篡改、知识产权窃取等黑灰产威胁的自动化识别与预警",
        "qa_system_prompt": "你是黑灰产情报分析专家，专注于智能制造领域。请基于情报数据，分析以下黑灰产威胁：1) 工业间谍活动与商业秘密窃取 2) 供应链中的假冒伪劣零部件注入 3) PLC/SCADA等工控系统的远程入侵与篡改 4) 制造企业内部数据泄露渠道 5) 数字孪生与工业互联网平台的攻击面。请用专业术语，结合黑话识别，输出结构化威胁评估。",
        "content_types": [
            {"value": "industrial_espionage_report", "label": "工业间谍威胁报告"},
            {"value": "supply_chain_analysis", "label": "供应链黑灰产链路分析"},
            {"value": "ics_vulnerability_brief", "label": "工控安全漏洞简报"},
            {"value": "manufacturing_threat_trend", "label": "制造业黑灰产趋势研判"},
        ],
        "keywords": ["工业间谍", "供应链攻击", "PLC篡改", "SCADA入侵", "假冒零部件", "知识产权窃取", "工控木马", "数字孪生攻击"],
        "threat_categories": ["工业间谍", "供应链渗透", "设备篡改", "数据窃取", "知识产权泄露"],
        "analysis_dimensions": ["攻击源追溯", "入侵链路还原", "影响范围评估", "黑灰产规模估算", "防御建议"],
        "translation_terms": [
            {"source_term": "PLC", "target_term": "可编程逻辑控制器", "category": "工控术语", "description": "工业控制核心设备"},
            {"source_term": "SCADA", "target_term": "监控与数据采集系统", "category": "工控术语", "description": "工业监控与数据采集平台"},
            {"source_term": "MES", "target_term": "制造执行系统", "category": "工控术语", "description": "制造过程执行与管理平台"},
            {"source_term": "OT", "target_term": "运营技术", "category": "安全术语", "description": "工业运营技术环境"},
            {"source_term": "APT", "target_term": "高级持续性威胁", "category": "安全术语", "description": "长期潜伏的高级网络威胁"},
            {"source_term": "ICS", "target_term": "工业控制系统", "category": "工控术语", "description": "工业自动化控制系统总称"},
        ],
        "dashboard_widgets": [
            {"type": "line", "title": "制造业黑灰产攻击趋势", "metric": "manufacturing_attack_trend"},
            {"type": "bar", "title": "威胁类型分布", "metric": "threat_distribution"},
            {"type": "sankey", "title": "供应链攻击链路", "metric": "supply_chain_attack_paths"},
            {"type": "heatmap", "title": "攻击时段热力图", "metric": "attack_timeline"},
        ],
    },
    "smart_education": {
        "id": "smart_education",
        "name": "智慧教育",
        "description": "黑灰产情报在智慧教育领域的分析场景——聚焦考试作弊产业链、论文代写黑灰产、题库泄露、在线教育平台攻击等威胁的自动化识别与预警",
        "qa_system_prompt": "你是黑灰产情报分析专家，专注于智慧教育领域。请基于情报数据，分析以下黑灰产威胁：1) 考试作弊技术手段与设备供应链 2) 论文代写黑灰产组织结构与运营模式 3) 题库泄露渠道与传播链路 4) 在线教育平台数据窃取与账号交易 5) 学历造假与证书伪造产业链。请识别黑话暗语，追踪资金流向，输出结构化威胁评估。",
        "content_types": [
            {"value": "exam_cheating_analysis", "label": "考试作弊产业链分析"},
            {"value": "ghostwriting_report", "label": "论文代写黑灰产报告"},
            {"value": "question_leak_tracking", "label": "题库泄露追踪简报"},
            {"value": "edu_platform_threat_assessment", "label": "教育平台安全威胁研判"},
        ],
        "keywords": ["作弊器", "代写", "题库泄露", "替考", "学历造假", "证书伪造", "网课代刷", "答案交易"],
        "threat_categories": ["作弊产业链", "代写黑灰产", "题库泄露", "平台入侵", "学历造假"],
        "analysis_dimensions": ["组织架构还原", "资金链路追踪", "传播渠道分析", "黑话暗语识别", "规模估算"],
        "translation_terms": [
            {"source_term": "MOOC", "target_term": "大规模开放在线课程", "category": "教育术语", "description": "大规模开放在线教育平台"},
            {"source_term": "LMS", "target_term": "学习管理系统", "category": "教育术语", "description": "在线学习管理平台"},
            {"source_term": "AI-proctoring", "target_term": "AI远程监考", "category": "教育术语", "description": "基于AI的远程考试监考技术"},
            {"source_term": "CBT", "target_term": "计算机化考试", "category": "教育术语", "description": "基于计算机的标准化考试"},
        ],
        "dashboard_widgets": [
            {"type": "bar", "title": "作弊手段类型分布", "metric": "cheating_method_distribution"},
            {"type": "line", "title": "代写黑灰产交易趋势", "metric": "ghostwriting_trend"},
            {"type": "network", "title": "黑灰产组织关系网络", "metric": "criminal_network"},
            {"type": "funnel", "title": "题库泄露传播漏斗", "metric": "leak_spread_funnel"},
        ],
    },
    "healthcare": {
        "id": "healthcare",
        "name": "医疗健康",
        "description": "黑灰产情报在医疗健康领域的分析场景——聚焦假药流通、医保欺诈、医疗数据交易、医疗设备攻击等威胁的自动化识别与预警",
        "qa_system_prompt": "你是黑灰产情报分析专家，专注于医疗健康领域。请基于情报数据，分析以下黑灰产威胁：1) 假药生产与流通的完整供应链 2) 医保欺诈的组织模式与套现手法 3) 患者数据在暗网的交易价格与流通渠道 4) 医疗设备漏洞利用与远程攻击 5) 非法药品广告与网络推广链路。请追踪黑灰产资金流，识别暗网交易模式，输出结构化威胁评估。",
        "content_types": [
            {"value": "counterfeit_drug_analysis", "label": "假药流通链路分析"},
            {"value": "insurance_fraud_report", "label": "医保欺诈模式报告"},
            {"value": "medical_data_tracking", "label": "医疗数据交易追踪简报"},
            {"value": "healthcare_threat_trend", "label": "医疗黑灰产趋势研判"},
        ],
        "keywords": ["假药", "医保套现", "患者数据交易", "暗网药品", "医疗设备漏洞", "非法处方", "代购药品", "医疗器械造假"],
        "threat_categories": ["假药流通", "医保欺诈", "数据交易", "设备攻击", "非法处方"],
        "analysis_dimensions": ["供应链还原", "资金链追踪", "暗网交易监控", "影响评估", "执法建议"],
        "translation_terms": [
            {"source_term": "EHR", "target_term": "电子健康档案", "category": "医疗术语", "description": "患者电子化健康记录系统"},
            {"source_term": "PACS", "target_term": "影像归档和通信系统", "category": "医疗术语", "description": "医学影像存储与传输系统"},
            {"source_term": "HIS", "target_term": "医院信息系统", "category": "医疗术语", "description": "医院综合信息管理系统"},
            {"source_term": "DICOM", "target_term": "医学数字成像通信", "category": "医疗术语", "description": "医学影像通信标准协议"},
            {"source_term": "GMP", "target_term": "药品生产质量管理规范", "category": "医疗术语", "description": "药品生产质量管理体系标准"},
        ],
        "dashboard_widgets": [
            {"type": "line", "title": "假药流通趋势", "metric": "counterfeit_drug_trend"},
            {"type": "sankey", "title": "医保欺诈资金流向", "metric": "insurance_fraud_flow"},
            {"type": "bar", "title": "暗网医疗数据交易量", "metric": "darkweb_medical_data"},
            {"type": "radar", "title": "医疗安全态势评估", "metric": "healthcare_security_posture"},
        ],
    },
    "financial_services": {
        "id": "financial_services",
        "name": "金融服务",
        "description": "黑灰产情报在金融服务领域的分析场景——聚焦电信诈骗、洗钱链路、支付欺诈、非法集资、加密货币犯罪等威胁的自动化识别与预警",
        "qa_system_prompt": "你是黑灰产情报分析专家，专注于金融服务领域。请基于情报数据，分析以下黑灰产威胁：1) 电信诈骗新手法与技术支撑链 2) 洗钱网络的多层资金归集与分散手法 3) 支付通道盗刷与套现黑灰产 4) 非法集资与庞氏骗局的线上推广模式 5) 加密货币混币器与暗网交易 6) 银行卡买卖与四件套交易。请识别黑话暗语，追踪资金链路，输出结构化威胁评估。",
        "content_types": [
            {"value": "telecom_fraud_analysis", "label": "电信诈骗手法分析报告"},
            {"value": "money_laundering_tracking", "label": "洗钱链路追踪简报"},
            {"value": "payment_fraud_assessment", "label": "支付欺诈模式研判"},
            {"value": "financial_threat_trend", "label": "金融黑灰产趋势分析"},
        ],
        "keywords": ["杀猪盘", "跑分", "四件套", "洗钱", "电诈", "资金盘", "暗网交易", "混币器", "套现", "盗刷"],
        "threat_categories": ["电信诈骗", "洗钱", "支付欺诈", "非法集资", "加密犯罪", "银行卡交易"],
        "analysis_dimensions": ["手法还原", "资金链追踪", "组织架构分析", "黑话识别", "规模估算"],
        "translation_terms": [
            {"source_term": "AML", "target_term": "反洗钱", "category": "金融术语", "description": "反洗钱合规与监管体系"},
            {"source_term": "KYC", "target_term": "了解你的客户", "category": "金融术语", "description": "客户身份识别与尽职调查"},
            {"source_term": "CFT", "target_term": "反恐融资", "category": "金融术语", "description": "反恐怖主义融资监管"},
            {"source_term": "FATF", "target_term": "金融行动特别工作组", "category": "金融术语", "description": "国际反洗钱标准制定组织"},
            {"source_term": "STR", "target_term": "可疑交易报告", "category": "金融术语", "description": "可疑金融交易报告制度"},
            {"source_term": "MIXER", "target_term": "混币器", "category": "加密术语", "description": "加密货币混币匿名化工具"},
        ],
        "dashboard_widgets": [
            {"type": "line", "title": "金融黑灰产交易趋势", "metric": "financial_crime_trend"},
            {"type": "sankey", "title": "洗钱资金链路", "metric": "money_laundering_paths"},
            {"type": "bar", "title": "诈骗类型分布", "metric": "fraud_type_distribution"},
            {"type": "network", "title": "黑灰产组织关系图谱", "metric": "criminal_network_graph"},
            {"type": "funnel", "title": "诈骗转化漏斗", "metric": "fraud_conversion_funnel"},
        ],
    },
}


class IndustrySceneConfigCreate(BaseModel):
    industry: str = Field(..., pattern=r"^(smart_manufacturing|smart_education|healthcare|financial_services)$")
    name: str = Field(..., min_length=1, max_length=256)
    config_json: str = "{}"
    is_active: bool = False
    description: Optional[str] = None


class IndustrySceneConfigUpdate(BaseModel):
    name: Optional[str] = None
    config_json: Optional[str] = None
    is_active: Optional[bool] = None
    description: Optional[str] = None


class SceneSwitchRequest(BaseModel):
    target_industry: str = Field(..., pattern=r"^(smart_manufacturing|smart_education|healthcare|financial_services)$")
    auto_adapt: bool = True


class IndustryQueryRequest(BaseModel):
    industry: str
    query: str
    context: Optional[Dict[str, Any]] = None


def _row_to_dict(row) -> Dict:
    return {
        "id": row.id,
        "industry": row.industry,
        "name": row.name,
        "config_json": row.config_json,
        "is_active": row.is_active,
        "description": row.description,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "created_by": row.created_by,
        "parent_id": getattr(row, "parent_id", None),
        "ab_group": getattr(row, "ab_group", None),
    }


@router.get("/industries")
async def list_industries(
    current_user: User = Depends(get_current_user),
):
    industries = []
    for key, strategy in INDUSTRY_STRATEGIES.items():
        industries.append({
            "id": strategy["id"],
            "name": strategy["name"],
            "description": strategy["description"],
            "content_types": strategy["content_types"],
            "threat_categories": strategy["threat_categories"],
            "analysis_dimensions": strategy["analysis_dimensions"],
        })
    return {"industries": industries, "total": len(industries)}


@router.get("/industries/{industry_id}/strategy")
async def get_industry_strategy(
    industry_id: str,
    current_user: User = Depends(get_current_user),
):
    strategy = INDUSTRY_STRATEGIES.get(industry_id)
    if not strategy:
        raise NotFoundException(detail=f"行业 {industry_id} 不存在")
    return strategy


@router.get("/configs")
async def list_configs(
    industry: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(IndustrySceneConfigTable)
    count_stmt = select(func.count()).select_from(IndustrySceneConfigTable)

    if industry:
        stmt = stmt.where(IndustrySceneConfigTable.industry == industry)
        count_stmt = count_stmt.where(IndustrySceneConfigTable.industry == industry)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(IndustrySceneConfigTable.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    return {"items": [_row_to_dict(r) for r in rows], "total": total, "offset": offset, "limit": limit}


@router.post("/configs", status_code=201)
async def create_config(
    data: IndustrySceneConfigCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if data.industry not in INDUSTRY_STRATEGIES:
        raise ValidationException(detail=f"不支持的行业类型: {data.industry}")

    validation = validate_domain_object("industry_config", data.model_dump())
    if not validation.is_valid:
        raise ValidationException(detail="数据验证失败", details={"errors": validation.errors, "warnings": validation.warnings})

    config_id = uuid.uuid4().hex

    if data.is_active:
        await db.execute(
            IndustrySceneConfigTable.__table__.update()
            .where(IndustrySceneConfigTable.is_active == True)
            .values(is_active=False)
        )

    row = IndustrySceneConfigTable(
        id=config_id,
        industry=data.industry,
        name=data.name,
        config_json=data.config_json,
        is_active=data.is_active,
        description=data.description,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _row_to_dict(row)


@router.get("/configs/{config_id}")
async def get_config(
    config_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(IndustrySceneConfigTable).where(IndustrySceneConfigTable.id == config_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        raise NotFoundException(detail="配置不存在")
    return _row_to_dict(row)


@router.put("/configs/{config_id}")
async def update_config(
    config_id: str,
    data: IndustrySceneConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(IndustrySceneConfigTable).where(IndustrySceneConfigTable.id == config_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        raise NotFoundException(detail="配置不存在")

    if data.is_active:
        await db.execute(
            IndustrySceneConfigTable.__table__.update()
            .where(IndustrySceneConfigTable.is_active == True)
            .values(is_active=False)
        )

    if data.name is not None:
        row.name = data.name
    if data.config_json is not None:
        row.config_json = data.config_json
    if data.is_active is not None:
        row.is_active = data.is_active
    if data.description is not None:
        row.description = data.description
    row.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(row)
    return _row_to_dict(row)


@router.delete("/configs/{config_id}", status_code=204)
async def delete_config(
    config_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(IndustrySceneConfigTable).where(IndustrySceneConfigTable.id == config_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        raise NotFoundException(detail="配置不存在")
    await db.delete(row)
    await db.commit()


@router.post("/configs/{config_id}/activate")
async def activate_config(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(IndustrySceneConfigTable).where(IndustrySceneConfigTable.id == config_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        raise NotFoundException(detail="配置不存在")

    await db.execute(
        IndustrySceneConfigTable.__table__.update()
        .where(IndustrySceneConfigTable.is_active == True)
        .values(is_active=False)
    )

    row.is_active = True
    row.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(row)

    strategy = INDUSTRY_STRATEGIES.get(row.industry)
    if not strategy:
        logger.warning(f"No strategy found for industry: {row.industry}")
        strategy = {}

    request.app.state.active_industry = row.industry
    request.app.state.active_industry_strategy = strategy

    return {
        **_row_to_dict(row),
        "strategy_applied": bool(strategy),
        "industry_name": strategy.get("name", row.industry),
    }


@router.post("/switch")
async def switch_scene(
    request: Request,
    data: SceneSwitchRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    strategy = INDUSTRY_STRATEGIES.get(data.target_industry)
    if not strategy:
        raise ValidationException(detail=f"不支持的行业类型: {data.target_industry}")

    await db.execute(
        IndustrySceneConfigTable.__table__.update()
        .where(IndustrySceneConfigTable.is_active == True)
        .values(is_active=False)
    )

    config_id = uuid.uuid4().hex
    config_json = json.dumps(strategy, ensure_ascii=False, default=str)

    row = IndustrySceneConfigTable(
        id=config_id,
        industry=data.target_industry,
        name=f"{strategy['name']}-黑灰产情报分析配置",
        config_json=config_json,
        is_active=True,
        description=strategy["description"],
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    request.app.state.active_industry = data.target_industry
    request.app.state.active_industry_strategy = strategy

    applied_changes = {
        "qa_system_prompt_updated": True,
        "content_types_updated": True,
        "translation_terms_updated": True,
        "dashboard_widgets_updated": True,
        "threat_categories_updated": True,
    }

    if data.auto_adapt:
        qa_dialogue_manager = getattr(request.app.state, "qa_dialogue_manager", None)
        if qa_dialogue_manager and hasattr(qa_dialogue_manager, "set_industry_prompt"):
            qa_dialogue_manager.set_industry_prompt(strategy["qa_system_prompt"])
            applied_changes["qa_engine_adapted"] = True

        content_generator = getattr(request.app.state, "content_generator", None)
        if content_generator and hasattr(content_generator, "set_industry_config"):
            content_generator.set_industry_config({
                "content_types": strategy["content_types"],
                "threat_categories": strategy["threat_categories"],
            })
            applied_changes["content_engine_adapted"] = True

        translation_engine = getattr(request.app.state, "translation_engine", None)
        if translation_engine and hasattr(translation_engine, "set_industry_terms"):
            translation_engine.set_industry_terms(strategy["translation_terms"])
            applied_changes["translation_engine_adapted"] = True

    return {
        "config_id": config_id,
        "industry": data.target_industry,
        "industry_name": strategy["name"],
        "is_active": True,
        "auto_adapt": data.auto_adapt,
        "applied_changes": applied_changes,
        "message": f"已切换到{strategy['name']}黑灰产情报分析场景",
    }


@router.get("/active")
async def get_active_scene(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    active_industry = getattr(request.app.state, "active_industry", None)
    strategy = getattr(request.app.state, "active_industry_strategy", None)

    if not active_industry or not strategy:
        return {"active": False, "industry": None, "strategy": None}

    if not isinstance(strategy, dict) or not strategy.get("name"):
        logger.warning(f"Active industry strategy data is incomplete for: {active_industry}")
        return {"active": False, "industry": active_industry, "strategy": None}

    return {
        "active": True,
        "industry": active_industry,
        "industry_name": strategy.get("name", active_industry),
        "strategy_summary": {
            "content_types": strategy.get("content_types", []),
            "threat_categories": strategy.get("threat_categories", []),
            "analysis_dimensions": strategy.get("analysis_dimensions", []),
            "dashboard_widgets": strategy.get("dashboard_widgets", []),
        },
    }


@router.post("/query")
async def industry_query(
    request: Request,
    data: IndustryQueryRequest,
    current_user: User = Depends(get_current_user),
):
    strategy = INDUSTRY_STRATEGIES.get(data.industry)
    if not strategy:
        raise ValidationException(detail=f"不支持的行业类型: {data.industry}")

    qa_dialogue_manager = getattr(request.app.state, "qa_dialogue_manager", None)
    if qa_dialogue_manager and hasattr(qa_dialogue_manager, "query_with_industry"):
        result = await qa_dialogue_manager.query_with_industry(
            query=data.query,
            industry=data.industry,
            system_prompt=strategy["qa_system_prompt"],
            context=data.context,
        )
        return {"industry": data.industry, "result": result}

    return {
        "industry": data.industry,
        "industry_name": strategy["name"],
        "system_prompt": strategy["qa_system_prompt"],
        "relevant_keywords": [kw for kw in strategy["keywords"] if kw in data.query],
        "threat_categories": strategy["threat_categories"],
        "query": data.query,
        "message": "行业策略已匹配，请通过智能问答模块发起完整查询",
    }


@router.get("/industries/{industry_id}/terms")
async def get_industry_terms(
    industry_id: str,
    current_user: User = Depends(get_current_user),
):
    strategy = INDUSTRY_STRATEGIES.get(industry_id)
    if not strategy:
        raise NotFoundException(detail=f"行业 {industry_id} 不存在")
    return {"industry": industry_id, "terms": strategy["translation_terms"]}


@router.get("/industries/{industry_id}/dashboard-template")
async def get_dashboard_template(
    industry_id: str,
    current_user: User = Depends(get_current_user),
):
    strategy = INDUSTRY_STRATEGIES.get(industry_id)
    if not strategy:
        raise NotFoundException(detail=f"行业 {industry_id} 不存在")
    return {
        "industry": industry_id,
        "widgets": strategy["dashboard_widgets"],
        "total_widgets": len(strategy["dashboard_widgets"]),
    }


@router.get("/industries/{industry_id}/config")
async def get_industry_config(
    industry_id: str,
    current_user: User = Depends(get_current_user),
):
    strategy = INDUSTRY_STRATEGIES.get(industry_id)
    if not strategy:
        raise NotFoundException(detail=f"行业 {industry_id} 不存在")

    from app.db.database import async_session_factory
    try:
        async with async_session_factory() as session:
            stmt = select(IndustrySceneConfigTable).where(
                IndustrySceneConfigTable.industry == industry_id
            )
            result = await session.execute(stmt)
            row = result.scalars().first()
            if row:
                config_data = row.config_json if isinstance(row.config_json, dict) else json.loads(row.config_json or "{}")
                return {"industry_id": industry_id, "config": config_data}
    except Exception as exc:
        logger.warning(f"Failed to load industry config from DB: {exc}")

    return {
        "industry_id": industry_id,
        "config": {
            "qa_system_prompt": strategy.get("qa_system_prompt", ""),
            "content_types": strategy.get("content_types", []),
            "translation_terms": strategy.get("translation_terms", []),
        },
    }


@router.put("/industries/{industry_id}/config")
async def update_industry_config(
    industry_id: str,
    config: Dict[str, Any],
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    strategy = INDUSTRY_STRATEGIES.get(industry_id)
    if not strategy:
        raise NotFoundException(detail=f"行业 {industry_id} 不存在")

    config_str = json.dumps(config, ensure_ascii=False)
    if len(config_str) > 50000:
        raise ValidationException(detail="配置数据过大，最大允许50KB")

    from app.db.database import async_session_factory
    try:
        async with async_session_factory() as session:
            stmt = select(IndustrySceneConfigTable).where(
                IndustrySceneConfigTable.industry == industry_id
            )
            result = await session.execute(stmt)
            row = result.scalars().first()
            if row:
                row.config_json = json.dumps(config, ensure_ascii=False) if isinstance(config, dict) else str(config)
            else:
                new_row = IndustrySceneConfigTable(
                    id=str(uuid.uuid4()),
                    industry=industry_id,
                    name=strategy.get("name", industry_id),
                    config_json=json.dumps(config, ensure_ascii=False) if isinstance(config, dict) else str(config),
                    is_active=False,
                )
                session.add(new_row)
            await session.commit()
    except Exception as exc:
        logger.warning(f"Failed to save industry config to DB: {exc}")

    return {"status": "success", "industry_id": industry_id}
