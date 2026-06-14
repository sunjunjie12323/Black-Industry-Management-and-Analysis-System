import json
import uuid
from datetime import datetime, timezone

from loguru import logger

from app.db.database import engine, Base, async_session_factory
from app.db.tables import (
    PromptTemplateTable,
    PreprocessTaskTable,
    FinetuneTaskTable,
    QAConversationTable,
    GeneratedContentTable,
    IndustryConfigTable,
    TranslationMemoryTable,
    TerminologyTable,
)

from app.config import settings
if not settings.SEED_DATABASE:
    import sys
    print("WARNING: seed_new_tables.py is designed for development/demo only. Set SEED_DATABASE=true in .env to enable.", file=sys.stderr)


PROMPT_TEMPLATES_SEED = [
    {
        "name": "威胁情报分析模板",
        "description": "用于分析原始威胁情报，提取关键指标和攻击模式",
        "category": "analysis",
        "content": "请分析以下威胁情报内容，提取关键IoC指标、攻击模式和威胁等级：\n\n{{content}}\n\n请从以下维度分析：\n1. 威胁等级评估：{{threat_level_criteria}}\n2. 攻击模式识别：{{attack_pattern}}\n3. IoC指标提取：{{ioc_types}}",
        "variables": [
            {"name": "content", "description": "待分析的情报内容", "required": True, "var_type": "string"},
            {"name": "threat_level_criteria", "description": "威胁等级评估标准", "default_value": "critical/high/medium/low/info", "required": False, "var_type": "string"},
            {"name": "attack_pattern", "description": "关注的攻击模式类型", "default_value": "MITRE ATT&CK", "required": False, "var_type": "string"},
            {"name": "ioc_types", "description": "需要提取的IoC类型", "default_value": "IP/Domain/URL/Hash/Email", "required": False, "var_type": "string"},
        ],
        "tags": ["威胁分析", "IoC提取", "ATT&CK"],
    },
    {
        "name": "黑话翻译模板",
        "description": "将黑灰产黑话翻译为标准术语",
        "category": "blacktalk",
        "content": "请将以下黑灰产黑话内容翻译为标准安全术语：\n\n{{blacktalk_content}}\n\n翻译要求：\n1. 识别所有黑话术语\n2. 提供标准安全术语对照\n3. 解释黑话的实际含义\n4. 标注相关威胁类型：{{threat_type}}",
        "variables": [
            {"name": "blacktalk_content", "description": "包含黑话的内容", "required": True, "var_type": "string"},
            {"name": "threat_type", "description": "威胁类型提示", "default_value": "诈骗/洗钱/黑客攻击", "required": False, "var_type": "string"},
        ],
        "tags": ["黑话翻译", "术语标准化"],
    },
    {
        "name": "情报摘要生成模板",
        "description": "生成威胁情报摘要报告",
        "category": "summarization",
        "content": "请为以下威胁情报生成结构化摘要：\n\n{{intelligence_content}}\n\n摘要要求：\n1. 核心威胁概述（不超过{{summary_length}}字）\n2. 关键发现列表\n3. 受影响范围：{{scope}}\n4. 建议措施",
        "variables": [
            {"name": "intelligence_content", "description": "情报内容", "required": True, "var_type": "string"},
            {"name": "summary_length", "description": "摘要长度限制", "default_value": "200", "required": False, "var_type": "number"},
            {"name": "scope", "description": "影响范围", "default_value": "全行业", "required": False, "var_type": "string"},
        ],
        "tags": ["摘要生成", "报告"],
    },
    {
        "name": "实体提取模板",
        "description": "从情报中提取关键实体",
        "category": "extraction",
        "content": "请从以下内容中提取关键实体：\n\n{{content}}\n\n提取类型：\n1. IP地址和域名\n2. 电话号码和邮箱\n3. 账号和钱包地址\n4. 组织和个人名称\n5. 恶意软件和工具名称\n\n输出格式：JSON\n置信度阈值：{{confidence_threshold}}",
        "variables": [
            {"name": "content", "description": "待提取实体的内容", "required": True, "var_type": "string"},
            {"name": "confidence_threshold", "description": "置信度阈值", "default_value": "0.7", "required": False, "var_type": "number"},
        ],
        "tags": ["实体提取", "NER"],
    },
    {
        "name": "威胁分类模板",
        "description": "对威胁情报进行分类",
        "category": "classification",
        "content": "请对以下威胁情报进行分类：\n\n{{content}}\n\n分类维度：\n1. 威胁类型：诈骗/赌博/洗钱/黑客/钓鱼/勒索/其他\n2. 攻击阶段：侦察/武器化/投递/利用/安装/命令控制/行动\n3. 行业影响：{{industry_scope}}\n4. 紧急程度：立即/24小时/7天/30天",
        "variables": [
            {"name": "content", "description": "待分类的情报内容", "required": True, "var_type": "string"},
            {"name": "industry_scope", "description": "行业范围", "default_value": "金融/制造/教育/医疗", "required": False, "var_type": "string"},
        ],
        "tags": ["分类", "威胁类型"],
    },
    {
        "name": "安全建议生成模板",
        "description": "基于威胁情报生成安全防护建议",
        "category": "generation",
        "content": "基于以下威胁情报，生成安全防护建议：\n\n{{threat_intelligence}}\n\n目标行业：{{target_industry}}\n防护层级：\n1. 网络层防护\n2. 终端防护\n3. 数据防护\n4. 人员安全意识\n5. 应急响应流程",
        "variables": [
            {"name": "threat_intelligence", "description": "威胁情报内容", "required": True, "var_type": "string"},
            {"name": "target_industry", "description": "目标行业", "default_value": "通用", "required": False, "var_type": "string"},
        ],
        "tags": ["安全建议", "防护"],
    },
    {
        "name": "攻击链路还原模板",
        "description": "还原黑灰产攻击链路，分析各环节关联",
        "category": "attack_chain",
        "content": "请基于以下情报还原完整的黑灰产攻击链路：\n\n{{intelligence_content}}\n\n分析要求：\n1. 识别攻击链路各环节（引流→接触→信任建立→诱导→收割→洗钱）\n2. 各环节使用的手法和工具\n3. 关联实体（人员/组织/平台/工具）\n4. 链路中的关键节点和脆弱环节\n5. 防御阻断建议\n\n攻击链类型：{{chain_type}}",
        "variables": [
            {"name": "intelligence_content", "description": "情报内容", "required": True, "var_type": "string"},
            {"name": "chain_type", "description": "攻击链类型", "default_value": "电信诈骗/网络赌博/勒索软件/供应链攻击", "required": False, "var_type": "string"},
        ],
        "tags": ["攻击链路", "链路还原", "关联分析"],
    },
    {
        "name": "黑灰产态势研判模板",
        "description": "对黑灰产威胁态势进行综合研判",
        "category": "threat_intel",
        "content": "请对以下黑灰产威胁情报进行综合态势研判：\n\n{{intelligence_data}}\n\n研判维度：\n1. 威胁等级：{{threat_level}}\n2. 活跃趋势：上升/平稳/下降\n3. 攻击目标行业：{{target_industries}}\n4. 攻击手法演进：新型手法识别\n5. 关联历史事件：{{historical_context}}\n6. 防御建议与预警措施",
        "variables": [
            {"name": "intelligence_data", "description": "待研判的情报数据", "required": True, "var_type": "string"},
            {"name": "threat_level", "description": "初步威胁等级", "default_value": "待评估", "required": False, "var_type": "string"},
            {"name": "target_industries", "description": "受影响行业", "default_value": "金融/制造/教育/医疗", "required": False, "var_type": "string"},
            {"name": "historical_context", "description": "历史关联事件", "default_value": "无", "required": False, "var_type": "string"},
        ],
        "tags": ["态势研判", "威胁评估", "综合分析"],
    },
    {
        "name": "高危预警通报模板",
        "description": "生成高危黑灰产威胁预警通报",
        "category": "threat_intel",
        "content": "请基于以下情报生成高危预警通报：\n\n{{alert_intelligence}}\n\n预警通报格式：\n1. 预警等级：红色/橙色/黄色/蓝色\n2. 威胁概述（一句话描述）\n3. 影响范围：{{affected_scope}}\n4. 攻击手法详述\n5. IoC指标清单\n6. 紧急处置措施（24小时内必须执行）\n7. 后续监控要点\n\n紧急程度：{{urgency}}",
        "variables": [
            {"name": "alert_intelligence", "description": "触发预警的情报", "required": True, "var_type": "string"},
            {"name": "affected_scope", "description": "影响范围", "default_value": "全行业", "required": False, "var_type": "string"},
            {"name": "urgency", "description": "紧急程度", "default_value": "紧急", "required": False, "var_type": "string"},
        ],
        "tags": ["预警通报", "高危", "应急响应"],
    },
    {
        "name": "犯罪模式识别模板",
        "description": "识别黑灰产犯罪模式和组织架构",
        "category": "attack_chain",
        "content": "请分析以下情报，识别黑灰产犯罪模式和组织架构：\n\n{{crime_intelligence}}\n\n分析要求：\n1. 犯罪模式分类：{{crime_type}}\n2. 组织架构还原（层级/分工/角色）\n3. 资金流向分析\n4. 技术支撑链路\n5. 上下游关联方\n6. 打击建议与关键突破点",
        "variables": [
            {"name": "crime_intelligence", "description": "犯罪情报内容", "required": True, "var_type": "string"},
            {"name": "crime_type", "description": "犯罪类型提示", "default_value": "电信诈骗/网络赌博/非法集资/洗钱/黑产工具", "required": False, "var_type": "string"},
        ],
        "tags": ["犯罪模式", "组织架构", "链路分析"],
    },
]

PREPROCESS_TASKS_SEED = [
    {
        "name": "批量导入暗网数据",
        "task_type": "import",
        "config_json": json.dumps({"source": "darkweb", "format": "json", "batch_size": 100}),
    },
    {
        "name": "情报数据清洗任务",
        "task_type": "clean",
        "config_json": json.dumps({"remove_duplicates": True, "decode_blacktalk": True, "extract_entities": True}),
    },
    {
        "name": "威胁等级标注",
        "task_type": "label",
        "config_json": json.dumps({"label_type": "threat_level", "levels": ["critical", "high", "medium", "low", "info"]}),
    },
]

FINETUNE_TASKS_SEED = [
    {
        "name": "黑话识别LoRA微调",
        "method": "lora",
        "base_model": "deepseek-chat",
        "config_json": json.dumps({"learning_rate": 0.0001, "epochs": 3, "batch_size": 8, "lora_rank": 16, "lora_alpha": 32}),
        "status": "completed",
        "progress": 1.0,
        "metrics_json": json.dumps({"accuracy": 0.92, "f1": 0.89, "loss": 0.15}),
    },
    {
        "name": "威胁分类全量微调",
        "method": "full",
        "base_model": "qwen-14b",
        "config_json": json.dumps({"learning_rate": 0.00005, "epochs": 5, "batch_size": 4}),
        "status": "pending",
        "progress": 0.0,
    },
]

QA_CONVERSATIONS_SEED = [
    {
        "title": "近期洗钱手法分析",
        "industry": "finance",
        "rag_enabled": True,
        "messages": [
            {"role": "user", "content": "近期有哪些新型洗钱手法？", "references": [], "created_at": datetime.now(timezone.utc).isoformat()},
            {"role": "assistant", "content": "根据近期情报分析，新型洗钱手法主要包括：1. 跑分平台升级为分布式架构；2. 利用虚拟货币混币器；3. 通过直播打赏洗钱。建议加强大额异常交易监控。", "references": [{"type": "intelligence", "id": "ref_001", "snippet": "跑分平台分布式架构分析", "threat_level": "high"}], "created_at": datetime.now(timezone.utc).isoformat()},
        ],
    },
    {
        "title": "勒索软件防护咨询",
        "industry": "manufacturing",
        "rag_enabled": True,
        "messages": [
            {"role": "user", "content": "制造业如何防范勒索软件攻击？", "references": [], "created_at": datetime.now(timezone.utc).isoformat()},
            {"role": "assistant", "content": "制造业防范勒索软件建议：1. 工控网络与办公网络隔离；2. 定期备份关键生产数据；3. 部署EDR终端防护；4. 建立应急响应预案。", "references": [], "created_at": datetime.now(timezone.utc).isoformat()},
        ],
    },
]

GENERATED_CONTENTS_SEED = [
    {
        "title": "2024年Q4黑灰产趋势报告摘要",
        "content_type": "report_summary",
        "content": "本季度黑灰产活动呈现以下趋势：1. AI技术被广泛用于自动化攻击和深度伪造；2. 跑分平台向去中心化方向发展；3. 跨境洗钱通道更加隐蔽；4. 针对制造业的勒索攻击显著增加。",
        "review_status": "approved",
        "reviewer": "admin",
        "review_comment": "内容准确，建议发布",
        "source_refs": ["raw_001", "raw_002", "analysis_001"],
    },
    {
        "title": "金融行业安全简报",
        "content_type": "intel_brief",
        "content": "近期金融行业面临的主要威胁：电信诈骗话术升级，利用AI语音克隆冒充银行客服；新型套路贷变种出现，利用短视频平台引流。",
        "review_status": "pending",
        "source_refs": ["raw_003"],
    },
    {
        "title": "某跑分平台威胁研判报告",
        "content_type": "threat_assessment",
        "content": "经分析，该跑分平台采用分布式架构，涉及虚拟货币混币器清洗资金。威胁等级：高危。影响范围：金融行业。建议立即封堵相关钱包地址和IP。",
        "review_status": "approved",
        "reviewer": "admin",
        "review_comment": "研判准确，IoC指标已提取",
        "source_refs": ["raw_004", "analysis_002"],
    },
    {
        "title": "杀猪盘攻击链路分析",
        "content_type": "attack_chain_analysis",
        "content": "攻击链路：社交平台引流→建立信任→诱导投资→虚假平台收割→虚拟货币洗钱。关键节点：引流环节使用AI生成人设，收割环节使用自建虚假交易平台。",
        "review_status": "expert_review",
        "reviewer": "analyst_01",
        "source_refs": ["raw_005"],
    },
    {
        "title": "高危预警：新型勒索软件攻击制造业",
        "content_type": "high_risk_alert",
        "content": "预警等级：橙色。近期发现针对制造业工控系统的新型勒索软件变种，利用PLC固件漏洞横向移动。影响范围：智能制造企业。紧急处置：立即隔离工控网络，更新PLC固件。",
        "review_status": "approved",
        "reviewer": "admin",
        "review_comment": "预警等级准确，已通知相关企业",
        "source_refs": ["raw_006", "raw_007"],
    },
]

INDUSTRY_CONFIGS_SEED = [
    {
        "industry": "manufacturing",
        "name": "智能制造黑灰产威胁配置",
        "description": "面向制造业的黑灰产威胁情报分析配置，关注工业间谍、供应链攻击、设备篡改、知识产权窃取、勒索软件",
        "prompt_templates": [],
        "rag_collections": ["manufacturing_threats", "ics_vulnerabilities", "supply_chain_attacks"],
        "model_config_json": json.dumps({"model": "deepseek-chat", "temperature": 0.3, "max_tokens": 4096}),
        "features_json": json.dumps({"auto_analysis": True, "realtime_alert": True, "stix_export": True, "threat_assessment": True}),
        "is_active": True,
    },
    {
        "industry": "finance",
        "name": "金融服务反欺诈情报配置",
        "description": "面向金融行业的反欺诈情报配置，关注电信诈骗、洗钱链路、跑分平台、杀猪盘、非法集资、套路贷",
        "prompt_templates": [],
        "rag_collections": ["finance_fraud", "money_laundering", "telecom_fraud"],
        "model_config_json": json.dumps({"model": "deepseek-chat", "temperature": 0.2, "max_tokens": 4096}),
        "features_json": json.dumps({"auto_analysis": True, "realtime_alert": True, "transaction_monitoring": True, "attack_chain_analysis": True}),
        "is_active": True,
    },
    {
        "industry": "education",
        "name": "智慧教育黑灰产威胁配置",
        "description": "面向教育行业的黑灰产威胁配置，关注考试作弊产业链、论文代写、题库泄露、学历造假、数据泄露",
        "prompt_templates": [],
        "rag_collections": ["education_security", "exam_cheating_chain", "phishing_indicators"],
        "model_config_json": json.dumps({"model": "deepseek-chat", "temperature": 0.3, "max_tokens": 2048}),
        "features_json": json.dumps({"auto_analysis": False, "realtime_alert": True, "stix_export": False, "crime_pattern_analysis": True}),
        "is_active": False,
    },
    {
        "industry": "healthcare",
        "name": "医疗健康黑灰产威胁配置",
        "description": "面向医疗行业的黑灰产威胁配置，关注假药流通、医保欺诈、医疗数据交易、处方药非法销售、医疗设备攻击",
        "prompt_templates": [],
        "rag_collections": ["healthcare_security", "medical_device_vulns", "counterfeit_drugs"],
        "model_config_json": json.dumps({"model": "deepseek-chat", "temperature": 0.2, "max_tokens": 4096}),
        "features_json": json.dumps({"auto_analysis": True, "realtime_alert": True, "hipaa_compliance": True, "threat_assessment": True}),
        "is_active": False,
    },
]

TERMINOLOGY_SEED = [
    {"term": "跑分", "translation": "money laundering relay", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "指通过第三方支付通道进行资金清洗"},
    {"term": "杀猪盘", "translation": "pig butchering scam", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "长期感情投资型诈骗"},
    {"term": "四件套", "translation": "four-piece identity kit", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "身份证+银行卡+手机卡+U盾"},
    {"term": "猫池", "translation": "SMS pool device", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "批量收发短信设备"},
    {"term": "水房", "translation": "money laundering operation", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "资金清洗环节/团队"},
    {"term": "料子", "translation": "stolen personal data", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "被盗取的个人信息数据"},
    {"term": "车手", "translation": "cash withdrawal mule", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "专门负责ATM取现的人员"},
    {"term": "肉鸡", "translation": "zombie host", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "被恶意控制的计算机"},
    {"term": "话术", "translation": "social engineering script", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "诈骗用的对话模板"},
    {"term": "资金盘", "translation": "Ponzi scheme", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "庞氏骗局类非法集资"},
    {"term": "接码", "translation": "verification code receiving service", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "接收验证码的黑灰产服务"},
    {"term": "养号", "translation": "account farming", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "培育账号提高权重以用于黑产"},
    {"term": "黑料", "translation": "illicit data", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "违法数据/隐私信息"},
    {"term": "卡商", "translation": "bank card dealer", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "银行卡贩卖者"},
    {"term": "料商", "translation": "stolen data dealer", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "数据贩卖者"},
    {"term": "引流", "translation": "traffic diversion for black market", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "为黑产输送用户流量"},
    {"term": "色流", "translation": "adult traffic diversion", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "色情内容引流"},
    {"term": "菠菜", "translation": "online gambling (euphemism)", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "网络赌博谐音"},
    {"term": "黑卡", "translation": "illicit bank card", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "非法银行卡/信用卡"},
    {"term": "拦截卡", "translation": "intercept SIM card", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "可拦截验证码的手机卡"},
    {"term": "马仔", "translation": "low-level operative", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "黑灰产底层执行者"},
    {"term": "套现", "translation": "illegal cash-out", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "非法套取现金"},
    {"term": "代付", "translation": "proxy payment service", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "代为支付的黑灰产服务"},
    {"term": "裸贷", "translation": "naked-photo collateral loan", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "以裸照抵押的非法借贷"},
    {"term": "套路贷", "translation": "predatory lending trap", "source_lang": "zh", "target_lang": "en", "domain": "threat_intel", "note": "欺诈性贷款陷阱"},
]


async def seed_new_tables():
    from app.config import settings
    if settings.is_production:
        logger.warning("seed_new_tables() called in production environment — aborting seed to prevent fake data injection")
        return
    logger.info("Seeding new tables...")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as session:
        template_count_result = await session.execute(
            __import__("sqlalchemy").select(__import__("sqlalchemy").func.count()).select_from(PromptTemplateTable)
        )
        if (template_count_result.scalar() or 0) > 0:
            logger.info("New tables already seeded, skipping")
            return

        for tpl in PROMPT_TEMPLATES_SEED:
            row = PromptTemplateTable(
                id=uuid.uuid4().hex,
                name=tpl["name"],
                description=tpl["description"],
                category=tpl["category"],
                content=tpl["content"],
                variables_json=json.dumps(tpl["variables"], ensure_ascii=False),
                tags_json=json.dumps(tpl["tags"], ensure_ascii=False),
            )
            session.add(row)
        logger.info(f"Seeded {len(PROMPT_TEMPLATES_SEED)} prompt templates")

        for task in PREPROCESS_TASKS_SEED:
            row = PreprocessTaskTable(
                id=uuid.uuid4().hex,
                name=task["name"],
                task_type=task["task_type"],
                status="pending",
                config_json=task["config_json"],
            )
            session.add(row)
        logger.info(f"Seeded {len(PREPROCESS_TASKS_SEED)} preprocess tasks")

        for task in FINETUNE_TASKS_SEED:
            row = FinetuneTaskTable(
                id=uuid.uuid4().hex,
                name=task["name"],
                method=task["method"],
                base_model=task["base_model"],
                status=task["status"],
                config_json=task["config_json"],
                progress=task["progress"],
                metrics_json=task.get("metrics_json"),
            )
            session.add(row)
        logger.info(f"Seeded {len(FINETUNE_TASKS_SEED)} finetune tasks")

        for conv in QA_CONVERSATIONS_SEED:
            row = QAConversationTable(
                id=uuid.uuid4().hex,
                title=conv["title"],
                messages_json=json.dumps(conv["messages"], ensure_ascii=False, default=str),
                industry=conv["industry"],
                rag_enabled=conv["rag_enabled"],
            )
            session.add(row)
        logger.info(f"Seeded {len(QA_CONVERSATIONS_SEED)} QA conversations")

        for content in GENERATED_CONTENTS_SEED:
            row = GeneratedContentTable(
                id=uuid.uuid4().hex,
                title=content["title"],
                content_type=content["content_type"],
                content=content["content"],
                review_status=content["review_status"],
                reviewer=content.get("reviewer"),
                review_comment=content.get("review_comment"),
                source_refs_json=json.dumps(content["source_refs"], ensure_ascii=False),
            )
            session.add(row)
        logger.info(f"Seeded {len(GENERATED_CONTENTS_SEED)} generated contents")

        for config in INDUSTRY_CONFIGS_SEED:
            row = IndustryConfigTable(
                id=uuid.uuid4().hex,
                industry=config["industry"],
                name=config["name"],
                description=config["description"],
                prompt_templates_json=json.dumps(config["prompt_templates"], ensure_ascii=False),
                rag_collections_json=json.dumps(config["rag_collections"], ensure_ascii=False),
                model_config_json=config["model_config_json"],
                features_json=config["features_json"],
                is_active=config["is_active"],
            )
            session.add(row)
        logger.info(f"Seeded {len(INDUSTRY_CONFIGS_SEED)} industry configs")

        for term in TERMINOLOGY_SEED:
            row = TerminologyTable(
                id=uuid.uuid4().hex,
                term=term["term"],
                translation=term["translation"],
                source_lang=term["source_lang"],
                target_lang=term["target_lang"],
                domain=term["domain"],
                note=term["note"],
            )
            session.add(row)
        logger.info(f"Seeded {len(TERMINOLOGY_SEED)} terminology entries")

        await session.commit()
    logger.info("New tables seeding completed")
