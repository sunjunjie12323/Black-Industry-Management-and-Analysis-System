import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user
from app.core.db_utils import db_write
from app.core.translation_engine import TranslationEngine
from app.db.database import get_db
from app.db.tables import TranslationMemoryTable, TerminologyTable

router = APIRouter(prefix="/translation", tags=["自动翻译"])


class TranslateRequest(BaseModel):
    text: str = Field(..., min_length=1)
    source_lang: str = "zh"
    target_lang: str = "en"
    domain: Optional[str] = None


class BatchTranslateRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    texts: List[str] = Field(..., min_length=1, max_length=100)
    source_lang: str = Field("zh", max_length=8)
    target_lang: str = Field("en", max_length=8)
    domain: Optional[str] = None


class TerminologyCreate(BaseModel):
    term: str = Field(..., min_length=1, max_length=256)
    translation: str = Field(..., min_length=1, max_length=256)
    source_lang: str = "zh"
    target_lang: str = "en"
    domain: Optional[str] = None
    note: Optional[str] = None


class TMCreate(BaseModel):
    source_text: str = Field(..., min_length=1)
    target_text: str = Field(..., min_length=1)
    source_lang: str = "zh"
    target_lang: str = "en"
    domain: Optional[str] = None


SUPPORTED_LANGUAGES = [
    {"code": "zh", "name": "中文", "native": "中文"},
    {"code": "en", "name": "英语", "native": "English"},
    {"code": "ja", "name": "日语", "native": "日本語"},
    {"code": "ko", "name": "韩语", "native": "한국어"},
    {"code": "ru", "name": "俄语", "native": "Русский"},
    {"code": "de", "name": "德语", "native": "Deutsch"},
    {"code": "fr", "name": "法语", "native": "Français"},
    {"code": "es", "name": "西班牙语", "native": "Español"},
    {"code": "ar", "name": "阿拉伯语", "native": "العربية"},
]


async def _get_translation_engine(request: Request, db: AsyncSession) -> TranslationEngine:
    engine = getattr(request.app.state, "translation_engine", None)
    if engine is not None:
        return engine
    llm = getattr(request.app.state, "llm", None)
    engine = TranslationEngine(llm_service=llm)
    tm_result = await db.execute(select(TranslationMemoryTable))
    tm_rows = tm_result.scalars().all()
    engine.load_translation_memories([
        {
            "id": r.id,
            "source_text": r.source_text,
            "target_text": r.target_text,
            "source_lang": r.source_lang,
            "target_lang": r.target_lang,
            "domain": r.domain,
        }
        for r in tm_rows
    ])
    term_result = await db.execute(select(TerminologyTable))
    term_rows = term_result.scalars().all()
    engine.load_terminology_list([
        {
            "term": r.term,
            "translation": r.translation,
            "source_lang": r.source_lang,
            "target_lang": r.target_lang,
        }
        for r in term_rows
    ])
    return engine


@router.post("/reload")
async def reload_translation_data(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "translation_engine", None)
    if engine is None:
        raise HTTPException(status_code=503, detail="翻译引擎未初始化")
    tm_result = await db.execute(select(TranslationMemoryTable))
    tm_rows = tm_result.scalars().all()
    engine.load_translation_memories([
        {
            "id": r.id,
            "source_text": r.source_text,
            "target_text": r.target_text,
            "source_lang": r.source_lang,
            "target_lang": r.target_lang,
            "domain": r.domain,
        }
        for r in tm_rows
    ])
    term_result = await db.execute(select(TerminologyTable))
    term_rows = term_result.scalars().all()
    engine.load_terminology_list([
        {
            "term": r.term,
            "translation": r.translation,
            "source_lang": r.source_lang,
            "target_lang": r.target_lang,
        }
        for r in term_rows
    ])
    return {"reloaded": True, "tm_count": len(tm_rows), "terminology_count": len(term_rows)}


INDUSTRY_TERMS = {
    "manufacturing": [
        {"term": "供应链攻击", "translation": "Supply Chain Attack", "source_lang": "zh", "target_lang": "en"},
        {"term": "工控系统", "translation": "Industrial Control System", "source_lang": "zh", "target_lang": "en"},
        {"term": "SCADA系统", "translation": "SCADA System", "source_lang": "zh", "target_lang": "en"},
        {"term": "PLC劫持", "translation": "PLC Hijacking", "source_lang": "zh", "target_lang": "en"},
        {"term": "勒索软件", "translation": "Ransomware", "source_lang": "zh", "target_lang": "en"},
        {"term": "OT网络", "translation": "Operational Technology Network", "source_lang": "zh", "target_lang": "en"},
        {"term": "工业间谍", "translation": "Industrial Espionage", "source_lang": "zh", "target_lang": "en"},
        {"term": "知识产权窃取", "translation": "Intellectual Property Theft", "source_lang": "zh", "target_lang": "en"},
        {"term": "固件植入", "translation": "Firmware Implant", "source_lang": "zh", "target_lang": "en"},
        {"term": "设备篡改", "translation": "Device Tampering", "source_lang": "zh", "target_lang": "en"},
    ],
    "education": [
        {"term": "钓鱼攻击", "translation": "Phishing Attack", "source_lang": "zh", "target_lang": "en"},
        {"term": "数据泄露", "translation": "Data Breach", "source_lang": "zh", "target_lang": "en"},
        {"term": "身份冒用", "translation": "Identity Spoofing", "source_lang": "zh", "target_lang": "en"},
        {"term": "远程代码执行", "translation": "Remote Code Execution", "source_lang": "zh", "target_lang": "en"},
        {"term": "学术欺诈", "translation": "Academic Fraud", "source_lang": "zh", "target_lang": "en"},
        {"term": "论文代写", "translation": "Ghostwriting Service", "source_lang": "zh", "target_lang": "en"},
        {"term": "题库泄露", "translation": "Exam Question Bank Leak", "source_lang": "zh", "target_lang": "en"},
        {"term": "学历造假", "translation": "Degree Forgery", "source_lang": "zh", "target_lang": "en"},
        {"term": "考试作弊产业链", "translation": "Exam Cheating Chain", "source_lang": "zh", "target_lang": "en"},
        {"term": "在线代考", "translation": "Online Proxy Testing", "source_lang": "zh", "target_lang": "en"},
    ],
    "healthcare": [
        {"term": "医疗数据泄露", "translation": "Healthcare Data Breach", "source_lang": "zh", "target_lang": "en"},
        {"term": "医疗设备漏洞", "translation": "Medical Device Vulnerability", "source_lang": "zh", "target_lang": "en"},
        {"term": "电子病历", "translation": "Electronic Health Record", "source_lang": "zh", "target_lang": "en"},
        {"term": "勒索病毒", "translation": "Ransomware Virus", "source_lang": "zh", "target_lang": "en"},
        {"term": "假药流通", "translation": "Counterfeit Drug Distribution", "source_lang": "zh", "target_lang": "en"},
        {"term": "医保欺诈", "translation": "Health Insurance Fraud", "source_lang": "zh", "target_lang": "en"},
        {"term": "医疗数据交易", "translation": "Medical Data Trafficking", "source_lang": "zh", "target_lang": "en"},
        {"term": "处方药非法销售", "translation": "Illegal Prescription Drug Sales", "source_lang": "zh", "target_lang": "en"},
    ],
    "finance": [
        {"term": "金融诈骗", "translation": "Financial Fraud", "source_lang": "zh", "target_lang": "en"},
        {"term": "信用卡欺诈", "translation": "Credit Card Fraud", "source_lang": "zh", "target_lang": "en"},
        {"term": "洗钱", "translation": "Money Laundering", "source_lang": "zh", "target_lang": "en"},
        {"term": "网络钓鱼", "translation": "Cyber Phishing", "source_lang": "zh", "target_lang": "en"},
        {"term": "交易异常检测", "translation": "Anomalous Transaction Detection", "source_lang": "zh", "target_lang": "en"},
        {"term": "银行木马", "translation": "Banking Trojan", "source_lang": "zh", "target_lang": "en"},
        {"term": "支付系统攻击", "translation": "Payment System Attack", "source_lang": "zh", "target_lang": "en"},
        {"term": "数字货币犯罪", "translation": "Cryptocurrency Crime", "source_lang": "zh", "target_lang": "en"},
        {"term": "电信诈骗", "translation": "Telecom Fraud", "source_lang": "zh", "target_lang": "en"},
        {"term": "非法集资", "translation": "Illegal Fundraising", "source_lang": "zh", "target_lang": "en"},
        {"term": "套路贷", "translation": "Predatory Lending Trap", "source_lang": "zh", "target_lang": "en"},
        {"term": "资金盘", "translation": "Ponzi Scheme Platform", "source_lang": "zh", "target_lang": "en"},
    ],
    "blacktalk": [
        {"term": "跑分", "translation": "Money Laundering Relay", "source_lang": "zh", "target_lang": "en"},
        {"term": "杀猪盘", "translation": "Pig Butchering Scam", "source_lang": "zh", "target_lang": "en"},
        {"term": "四件套", "translation": "Four-Piece Identity Kit", "source_lang": "zh", "target_lang": "en"},
        {"term": "猫池", "translation": "SMS Pool Device", "source_lang": "zh", "target_lang": "en"},
        {"term": "水房", "translation": "Money Laundering Operation", "source_lang": "zh", "target_lang": "en"},
        {"term": "料子", "translation": "Stolen Personal Data", "source_lang": "zh", "target_lang": "en"},
        {"term": "车手", "translation": "Cash Withdrawal Mule", "source_lang": "zh", "target_lang": "en"},
        {"term": "肉鸡", "translation": "Zombie Host", "source_lang": "zh", "target_lang": "en"},
        {"term": "话术", "translation": "Social Engineering Script", "source_lang": "zh", "target_lang": "en"},
        {"term": "接码", "translation": "Verification Code Receiving Service", "source_lang": "zh", "target_lang": "en"},
        {"term": "养号", "translation": "Account Farming", "source_lang": "zh", "target_lang": "en"},
        {"term": "黑料", "translation": "Illicit Data / Compromising Information", "source_lang": "zh", "target_lang": "en"},
        {"term": "卡商", "translation": "Bank Card Dealer", "source_lang": "zh", "target_lang": "en"},
        {"term": "料商", "translation": "Stolen Data Dealer", "source_lang": "zh", "target_lang": "en"},
        {"term": "引流", "translation": "Traffic Diversion for Black Market", "source_lang": "zh", "target_lang": "en"},
        {"term": "色流", "translation": "Adult Traffic Diversion", "source_lang": "zh", "target_lang": "en"},
        {"term": "菠菜", "translation": "Online Gambling (Euphemism)", "source_lang": "zh", "target_lang": "en"},
        {"term": "黑卡", "translation": "Illicit Bank Card", "source_lang": "zh", "target_lang": "en"},
        {"term": "拦截卡", "translation": "Intercept SIM Card", "source_lang": "zh", "target_lang": "en"},
        {"term": "马仔", "translation": "Low-Level Operative", "source_lang": "zh", "target_lang": "en"},
        {"term": "套现", "translation": "Illegal Cash-Out", "source_lang": "zh", "target_lang": "en"},
        {"term": "代付", "translation": "Proxy Payment Service", "source_lang": "zh", "target_lang": "en"},
        {"term": "实名", "translation": "Real-Name Verified Identity", "source_lang": "zh", "target_lang": "en"},
        {"term": "裸贷", "translation": "Naked-Photo Collateral Loan", "source_lang": "zh", "target_lang": "en"},
    ],
}


@router.get("/industry-terms")
async def get_industry_terms(
    industry: Optional[str] = Query(None, description="行业筛选: manufacturing, education, healthcare, finance, blacktalk"),
    current_user: User = Depends(get_current_user),
):
    if industry:
        if industry not in INDUSTRY_TERMS:
            raise HTTPException(status_code=400, detail=f"不支持的行业: {industry}，可选值: {', '.join(INDUSTRY_TERMS.keys())}")
        return {"industry": industry, "terms": INDUSTRY_TERMS[industry], "total": len(INDUSTRY_TERMS[industry])}
    all_terms = []
    for ind, terms in INDUSTRY_TERMS.items():
        for t in terms:
            t_copy = dict(t)
            t_copy["industry"] = ind
            all_terms.append(t_copy)
    return {"terms": all_terms, "total": len(all_terms), "industries": list(INDUSTRY_TERMS.keys())}


@router.post("/translate")
async def translate(
    data: TranslateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = await _get_translation_engine(request, db)
    result = await engine.translate(
        text=data.text,
        source_lang=data.source_lang,
        target_lang=data.target_lang,
        domain=data.domain,
    )
    return result.to_dict()


@router.post("/batch-translate")
async def batch_translate(
    data: BatchTranslateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = await _get_translation_engine(request, db)
    results = await engine.batch_translate(
        texts=data.texts,
        source_lang=data.source_lang,
        target_lang=data.target_lang,
        domain=data.domain,
    )
    return {
        "results": [r.to_dict() for r in results],
        "source_lang": data.source_lang,
        "target_lang": data.target_lang,
        "total": len(results),
    }


@router.get("/tm-matches")
async def find_tm_matches(
    request: Request,
    text: str = Query(..., min_length=1),
    source_lang: str = Query("zh"),
    target_lang: str = Query("en"),
    top_k: int = Query(3, ge=1, le=10),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = await _get_translation_engine(request, db)
    matches = engine.find_tm_matches(text, source_lang, target_lang, top_k)
    return {"matches": matches, "total": len(matches)}


@router.post("/tm", status_code=201)
async def create_translation_memory(
    data: TMCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    tm_id = uuid.uuid4().hex

    row = TranslationMemoryTable(
        id=tm_id,
        source_text=data.source_text,
        source_lang=data.source_lang,
        target_text=data.target_text,
        target_lang=data.target_lang,
        domain=data.domain,
    )
    async with db_write(db, operation="创建翻译记忆"):
        db.add(row)
    await db.refresh(row)

    return {
        "id": row.id,
        "source_text": row.source_text,
        "source_lang": row.source_lang,
        "target_text": row.target_text,
        "target_lang": row.target_lang,
        "domain": row.domain,
    }


@router.get("/languages")
async def list_languages(
    current_user: User = Depends(get_current_user),
):
    return {"languages": SUPPORTED_LANGUAGES, "total": len(SUPPORTED_LANGUAGES)}


@router.get("/terminology")
async def list_terminology(
    source_lang: Optional[str] = None,
    target_lang: Optional[str] = None,
    domain: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(TerminologyTable)
    count_stmt = select(func.count()).select_from(TerminologyTable)

    if source_lang:
        stmt = stmt.where(TerminologyTable.source_lang == source_lang)
        count_stmt = count_stmt.where(TerminologyTable.source_lang == source_lang)
    if target_lang:
        stmt = stmt.where(TerminologyTable.target_lang == target_lang)
        count_stmt = count_stmt.where(TerminologyTable.target_lang == target_lang)
    if domain:
        stmt = stmt.where(TerminologyTable.domain == domain)
        count_stmt = count_stmt.where(TerminologyTable.domain == domain)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(TerminologyTable.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    items = [
        {
            "id": r.id,
            "term": r.term,
            "translation": r.translation,
            "source_lang": r.source_lang,
            "target_lang": r.target_lang,
            "domain": r.domain,
            "note": r.note,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
    return {"items": items, "total": total, "offset": offset, "limit": limit}


class TMUpdateRequest(BaseModel):
    source_text: Optional[str] = None
    target_text: Optional[str] = None
    source_lang: Optional[str] = None
    target_lang: Optional[str] = None
    domain: Optional[str] = None


@router.put("/tm/{tm_id}")
async def update_translation_memory(
    tm_id: str,
    data: TMUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(TranslationMemoryTable).where(TranslationMemoryTable.id == tm_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="翻译记忆不存在")

    update_data = data.model_dump(exclude_unset=True)
    async with db_write(db, operation="更新翻译记忆"):
        for key, value in update_data.items():
            if hasattr(row, key) and value is not None:
                setattr(row, key, value)
    await db.refresh(row)
    return {
        "id": row.id,
        "source_text": row.source_text,
        "target_text": row.target_text,
        "source_lang": row.source_lang,
        "target_lang": row.target_lang,
        "domain": row.domain,
        "updated": True,
    }


@router.delete("/tm/{tm_id}", status_code=204)
async def delete_translation_memory(
    tm_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(TranslationMemoryTable).where(TranslationMemoryTable.id == tm_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="翻译记忆不存在")
    async with db_write(db, operation="删除翻译记忆"):
        await db.delete(row)


@router.post("/terminology/batch", status_code=201)
async def batch_create_terminology(
    items: List[TerminologyCreate],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    created = []
    async with db_write(db, operation="批量创建术语"):
        for item in items:
            term_id = uuid.uuid4().hex
            row = TerminologyTable(
                id=term_id,
                term=item.term,
                translation=item.translation,
                source_lang=item.source_lang,
                target_lang=item.target_lang,
                domain=item.domain,
                note=item.note,
            )
            db.add(row)
            created.append({"id": term_id, "term": item.term, "translation": item.translation})
    return {"created": created, "total": len(created)}


@router.post("/tm/batch", status_code=201)
async def batch_create_translation_memory(
    items: List[TMCreate],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    created = []
    async with db_write(db, operation="批量创建翻译记忆"):
        for item in items:
            tm_id = uuid.uuid4().hex
            row = TranslationMemoryTable(
                id=tm_id,
                source_text=item.source_text,
                target_text=item.target_text,
                source_lang=item.source_lang,
                target_lang=item.target_lang,
                domain=item.domain,
            )
            db.add(row)
            created.append({"id": tm_id, "source_text": item.source_text[:50], "target_text": item.target_text[:50]})
    return {"created": created, "total": len(created)}


class TerminologyUpdateRequest(BaseModel):
    term: Optional[str] = None
    translation: Optional[str] = None
    domain: Optional[str] = None
    note: Optional[str] = None


@router.put("/terminology/{term_id}")
async def update_terminology(
    term_id: str,
    data: TerminologyUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(TerminologyTable).where(TerminologyTable.id == term_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="术语不存在")

    update_data = data.model_dump(exclude_unset=True)
    async with db_write(db, operation="更新术语"):
        for key, value in update_data.items():
            if hasattr(row, key) and value is not None:
                setattr(row, key, value)
    await db.refresh(row)
    return {
        "id": row.id,
        "term": row.term,
        "translation": row.translation,
        "source_lang": row.source_lang,
        "target_lang": row.target_lang,
        "domain": row.domain,
        "note": row.note,
        "updated": True,
    }


@router.post("/terminology", status_code=201)
async def create_terminology(
    data: TerminologyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    term_id = uuid.uuid4().hex

    row = TerminologyTable(
        id=term_id,
        term=data.term,
        translation=data.translation,
        source_lang=data.source_lang,
        target_lang=data.target_lang,
        domain=data.domain,
        note=data.note,
    )
    async with db_write(db, operation="创建术语"):
        db.add(row)
    await db.refresh(row)

    return {
        "id": row.id,
        "term": row.term,
        "translation": row.translation,
        "source_lang": row.source_lang,
        "target_lang": row.target_lang,
        "domain": row.domain,
        "note": row.note,
    }


@router.delete("/terminology/{term_id}", status_code=204)
async def delete_terminology(
    term_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(TerminologyTable).where(TerminologyTable.id == term_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="术语不存在")
    async with db_write(db, operation="删除术语"):
        await db.delete(row)


@router.get("/translation-memory")
async def list_translation_memory(
    source_lang: Optional[str] = None,
    target_lang: Optional[str] = None,
    domain: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(TranslationMemoryTable)
    count_stmt = select(func.count()).select_from(TranslationMemoryTable)

    if source_lang:
        stmt = stmt.where(TranslationMemoryTable.source_lang == source_lang)
        count_stmt = count_stmt.where(TranslationMemoryTable.source_lang == source_lang)
    if target_lang:
        stmt = stmt.where(TranslationMemoryTable.target_lang == target_lang)
        count_stmt = count_stmt.where(TranslationMemoryTable.target_lang == target_lang)
    if domain:
        stmt = stmt.where(TranslationMemoryTable.domain == domain)
        count_stmt = count_stmt.where(TranslationMemoryTable.domain == domain)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(TranslationMemoryTable.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    items = [
        {
            "id": r.id,
            "source_text": r.source_text,
            "source_lang": r.source_lang,
            "target_text": r.target_text,
            "target_lang": r.target_lang,
            "domain": r.domain,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
    return {"items": items, "total": total, "offset": offset, "limit": limit}


class QualityScoreRequest(BaseModel):
    source: str = Field(..., min_length=1)
    translation: str = Field(..., min_length=1)
    source_lang: str = Field("zh", max_length=8)
    target_lang: str = Field("en", max_length=8)


class DetectLanguageRequest(BaseModel):
    text: str = Field(..., min_length=1)


class LLMTranslateRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    text: str = Field(..., min_length=1, max_length=10000)
    source_lang: str = Field("zh", max_length=8)
    target_lang: str = Field("en", max_length=8)
    domain: Optional[str] = None


@router.post("/quality-score")
async def score_translation_quality(
    data: QualityScoreRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = await _get_translation_engine(request, db)
    result = await engine.get_translation_quality_score(
        source=data.source,
        translation=data.translation,
        source_lang=data.source_lang,
        target_lang=data.target_lang,
    )
    return result


@router.post("/detect-language")
async def detect_language(
    data: DetectLanguageRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = await _get_translation_engine(request, db)
    result = await engine.detect_language(text=data.text)
    return result


@router.post("/translate-llm")
async def translate_with_llm(
    data: LLMTranslateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engine = await _get_translation_engine(request, db)
    result = await engine.translate_with_llm(
        text=data.text,
        source_lang=data.source_lang,
        target_lang=data.target_lang,
        domain=data.domain,
    )
    return result


class TMBatchDeleteRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    ids: List[str] = Field(..., min_length=1, max_length=200)


@router.delete("/memory/batch")
async def batch_delete_translation_memory(
    data: TMBatchDeleteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(TranslationMemoryTable).where(TranslationMemoryTable.id.in_(data.ids))
    )
    rows = result.scalars().all()
    found_ids = {r.id for r in rows}
    missing_ids = set(data.ids) - found_ids

    async with db_write(db, operation="批量删除翻译记忆"):
        for row in rows:
            await db.delete(row)

    return {
        "deleted": len(rows),
        "missing_ids": list(missing_ids),
        "requested": len(data.ids),
    }


@router.get("/statistics")
async def get_translation_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    tm_count_result = await db.execute(select(func.count()).select_from(TranslationMemoryTable))
    tm_count = tm_count_result.scalar() or 0

    term_count_result = await db.execute(select(func.count()).select_from(TerminologyTable))
    term_count = term_count_result.scalar() or 0

    tm_domain_result = await db.execute(
        select(TranslationMemoryTable.domain, func.count()).group_by(TranslationMemoryTable.domain)
    )
    tm_domain_distribution = {row[0] or "未分类": row[1] for row in tm_domain_result.all()}

    term_domain_result = await db.execute(
        select(TerminologyTable.domain, func.count()).group_by(TerminologyTable.domain)
    )
    term_domain_distribution = {row[0] or "未分类": row[1] for row in term_domain_result.all()}

    tm_lang_result = await db.execute(
        select(
            TranslationMemoryTable.source_lang,
            TranslationMemoryTable.target_lang,
            func.count(),
        ).group_by(TranslationMemoryTable.source_lang, TranslationMemoryTable.target_lang)
    )
    tm_lang_distribution = [
        {"source_lang": row[0], "target_lang": row[1], "count": row[2]}
        for row in tm_lang_result.all()
    ]

    term_lang_result = await db.execute(
        select(
            TerminologyTable.source_lang,
            TerminologyTable.target_lang,
            func.count(),
        ).group_by(TerminologyTable.source_lang, TerminologyTable.target_lang)
    )
    term_lang_distribution = [
        {"source_lang": row[0], "target_lang": row[1], "count": row[2]}
        for row in term_lang_result.all()
    ]

    return {
        "tm_count": tm_count,
        "terminology_count": term_count,
        "tm_domain_distribution": tm_domain_distribution,
        "terminology_domain_distribution": term_domain_distribution,
        "tm_language_pair_distribution": tm_lang_distribution,
        "terminology_language_pair_distribution": term_lang_distribution,
    }

