import asyncio
import json
import random
import uuid
from datetime import datetime, timedelta, timezone

from loguru import logger

from sqlalchemy import select
from app.db.database import engine, Base, async_session_factory
from app.db.tables import (
    RawIntelligenceTable, PIRTable,
    EntityTable, RelationTable, ReportTable,
    CleanedIntelligenceTable, AnalyzedIntelligenceTable,
)
from app.core.knowledge_graph import KnowledgeGraph
from app.models.entity import Entity, EntityType, Relation, RelationType
from app.core.blacktalk_engine import BlackTalkEngine, BlackTalkTerm
from app.core.vector_store import VectorStore
from app.core.local_embedding import LocalEmbeddingEngine

from app.config import settings
if not settings.SEED_DATABASE:
    import sys
    print("WARNING: seed_full.py is designed for development/demo only. Set SEED_DATABASE=true in .env to enable.", file=sys.stderr)


PERSONS = [
    {"value": "张伟", "context": "暗影网络犯罪集团头目，负责整体运营和指挥，绰号'影子'", "confidence": 0.95},
    {"value": "李明", "context": "暗影网络犯罪集团技术骨干，擅长开发钓鱼工具和恶意软件", "confidence": 0.9},
    {"value": "王强", "context": "黑水洗钱网络核心资金操手，负责多层级资金转移", "confidence": 0.88},
    {"value": "赵刚", "context": "幽灵钓鱼组织钓鱼工程师，负责设计和部署钓鱼页面", "confidence": 0.85},
    {"value": "陈芳", "context": "龙腾诈骗团伙社工专家，擅长话术设计和受害者心理操控", "confidence": 0.87},
    {"value": "刘洋", "context": "数据猎手联盟数据贩子，长期在暗网出售公民个人信息", "confidence": 0.92},
    {"value": "周杰", "context": "黑水洗钱网络底层马仔，负责ATM取现和虚拟货币兑换", "confidence": 0.75},
    {"value": "吴昊", "context": "暗影网络犯罪集团黑客，擅长漏洞利用和服务器入侵", "confidence": 0.9},
]

ORGANIZATIONS = [
    {"value": "暗影网络犯罪集团", "context": "大型跨国网络犯罪组织，涉及钓鱼、诈骗、数据贩卖等多领域", "confidence": 0.95},
    {"value": "龙腾诈骗团伙", "context": "专门从事杀猪盘和电信诈骗的犯罪团伙，活动范围覆盖东南亚", "confidence": 0.9},
    {"value": "幽灵钓鱼组织", "context": "专注钓鱼攻击的黑产组织，拥有大量钓鱼站点和自动化工具", "confidence": 0.88},
    {"value": "黑水洗钱网络", "context": "专业洗钱网络，提供跑分、虚拟货币清洗等资金通道服务", "confidence": 0.92},
    {"value": "数据猎手联盟", "context": "数据贩卖联盟，通过脱库、撞库获取并出售公民个人信息", "confidence": 0.9},
]

PHONES = [
    {"value": "+86 17062348891", "context": "张伟常用虚拟手机号，用于指挥联络", "confidence": 0.8},
    {"value": "+86 17093827654", "context": "陈芳工作手机号，用于诈骗联络", "confidence": 0.78},
    {"value": "+852 98761234", "context": "王强香港号码，用于跨境资金调度", "confidence": 0.82},
    {"value": "+86 19823456789", "context": "赵刚备用号码，注册钓鱼域名用", "confidence": 0.7},
    {"value": "+66 812345678", "context": "刘洋泰国号码，暗网交易联络", "confidence": 0.75},
]

ACCOUNTS = [
    {"value": "QQ: 2837461950", "context": "张伟主用QQ号，用于团伙内部沟通", "confidence": 0.85},
    {"value": "微信: shadow_zw2024", "context": "张伟微信号，用于日常联络", "confidence": 0.8},
    {"value": "Telegram: @darkdata_liu", "context": "刘洋Telegram账号，用于暗网数据交易", "confidence": 0.9},
    {"value": "QQ: 3948572610", "context": "陈芳QQ号，用于杀猪盘目标接触", "confidence": 0.82},
    {"value": "Telegram: @ghostfish_zhao", "context": "赵刚Telegram账号，钓鱼工具交流", "confidence": 0.78},
]

IPS = [
    {"value": "185.234.72.11", "context": "暗影集团钓鱼服务器IP，位于荷兰阿姆斯特丹", "confidence": 0.88},
    {"value": "103.89.90.45", "context": "龙腾诈骗团伙C2控制服务器，位于柬埔寨", "confidence": 0.85},
    {"value": "45.77.123.89", "context": "幽灵钓鱼组织代理服务器，Vultr云主机", "confidence": 0.8},
    {"value": "91.215.85.167", "context": "数据猎手联盟数据中转服务器，位于俄罗斯", "confidence": 0.82},
    {"value": "172.93.185.42", "context": "黑水洗钱网络支付网关服务器", "confidence": 0.78},
]

DOMAINS = [
    {"value": "secure-bank-verify.cn", "context": "钓鱼网站，仿冒某银行在线验证页面", "confidence": 0.92},
    {"value": "login-pay-safe.com", "context": "钓鱼网站，仿冒支付平台登录页面", "confidence": 0.9},
    {"value": "id-check-portal.net", "context": "钓鱼网站，仿冒身份认证平台", "confidence": 0.88},
]

EMAILS = [
    {"value": "shadow_op@protonmail.com", "context": "张伟匿名邮箱，用于外部联络", "confidence": 0.8},
    {"value": "darkdata2024@tutanota.com", "context": "刘洋匿名邮箱，暗网交易联络", "confidence": 0.85},
    {"value": "ghost.phish@secmail.pro", "context": "赵刚匿名邮箱，钓鱼业务联络", "confidence": 0.78},
]

BLACKTALKS = [
    {"value": "跑分", "context": "洗钱，通过第三方支付平台转移非法资金", "confidence": 1.0},
    {"value": "料子", "context": "个人隐私数据，特指可用于诈骗的完整信息", "confidence": 1.0},
    {"value": "水房", "context": "洗钱环节，专门负责资金清洗的团队", "confidence": 1.0},
    {"value": "猫池", "context": "批量收发短信的设备，用于接收验证码", "confidence": 1.0},
    {"value": "杀猪盘", "context": "长期感情诈骗，通过建立感情骗取钱财", "confidence": 1.0},
    {"value": "狗带", "context": "被抓，指黑产人员被执法部门逮捕", "confidence": 0.9},
    {"value": "菜农", "context": "网络赌博运营者，也指低级诈骗者", "confidence": 1.0},
    {"value": "四件套", "context": "身份证+银行卡+手机卡+U盾的犯罪工具套装", "confidence": 1.0},
]

TOOLS = [
    {"value": "猫池设备", "context": "多卡聚合设备，可同时插入数十张手机卡批量接收验证码", "confidence": 0.9},
    {"value": "自动拨号软件", "context": "自动拨打诈骗电话的软件，可模拟任意来电号码", "confidence": 0.88},
    {"value": "钓鱼页面生成器", "context": "自动化生成钓鱼网页的工具，支持仿冒各大平台", "confidence": 0.92},
]

CRYPTO_WALLETS = [
    {"value": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "context": "暗影集团BTC主钱包，疑似接收诈骗资金", "confidence": 0.85},
    {"value": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18", "context": "黑水洗钱网络ETH钱包，用于资金中转", "confidence": 0.8},
]

MALWARES = [
    {"value": "钓鱼攻击套件", "context": "包含钓鱼页面模板、邮件模板、域名管理的一体化攻击工具包", "confidence": 0.9},
    {"value": "远程控制木马", "context": "定制化RAT木马，可窃取浏览器凭证和加密货币钱包", "confidence": 0.88},
    {"value": "DDoS攻击脚本", "context": "基于IoT僵尸网络的DDoS攻击工具，支持多种攻击模式", "confidence": 0.82},
]


PERSON_ORG_MAP = [
    (0, 0),
    (1, 0),
    (7, 0),
    (4, 1),
    (3, 2),
    (2, 3),
    (6, 3),
    (5, 4),
]

RELATIONS_DATA = []

for p_idx, o_idx in PERSON_ORG_MAP:
    RELATIONS_DATA.append({
        "source_type": "person", "source_idx": p_idx,
        "target_type": "organization", "target_idx": o_idx,
        "relation_type": RelationType.BELONGS_TO,
        "evidence": f"{PERSONS[p_idx]['value']}属于{ORGANIZATIONS[o_idx]['value']}",
        "confidence": 0.85,
    })

PERSON_TOOL_MAP = [(1, 2), (3, 2), (0, 1), (4, 0), (7, 0)]
for p_idx, t_idx in PERSON_TOOL_MAP:
    RELATIONS_DATA.append({
        "source_type": "person", "source_idx": p_idx,
        "target_type": "tool", "target_idx": t_idx,
        "relation_type": RelationType.USES,
        "evidence": f"{PERSONS[p_idx]['value']}使用{TOOLS[t_idx]['value']}",
        "confidence": 0.8,
    })

PERSON_PHONE_MAP = [(0, 0), (4, 1), (2, 2), (3, 3)]
for p_idx, ph_idx in PERSON_PHONE_MAP:
    RELATIONS_DATA.append({
        "source_type": "person", "source_idx": p_idx,
        "target_type": "phone", "target_idx": ph_idx,
        "relation_type": RelationType.USES,
        "evidence": f"{PERSONS[p_idx]['value']}使用手机号{PHONES[ph_idx]['value']}",
        "confidence": 0.78,
    })

PERSON_ACCOUNT_MAP = [(0, 0), (0, 1), (5, 2), (4, 3)]
for p_idx, a_idx in PERSON_ACCOUNT_MAP:
    RELATIONS_DATA.append({
        "source_type": "person", "source_idx": p_idx,
        "target_type": "account", "target_idx": a_idx,
        "relation_type": RelationType.USES,
        "evidence": f"{PERSONS[p_idx]['value']}使用账号{ACCOUNTS[a_idx]['value']}",
        "confidence": 0.8,
    })

ORG_MALWARE_MAP = [(0, 0), (2, 0), (0, 2)]
for o_idx, m_idx in ORG_MALWARE_MAP:
    RELATIONS_DATA.append({
        "source_type": "organization", "source_idx": o_idx,
        "target_type": "malware", "target_idx": m_idx,
        "relation_type": RelationType.OPERATES,
        "evidence": f"{ORGANIZATIONS[o_idx]['value']}运营{MALWARES[m_idx]['value']}",
        "confidence": 0.82,
    })

ACCOUNT_IP_MAP = [(0, 0), (2, 3), (4, 2), (1, 4), (3, 1)]
for a_idx, ip_idx in ACCOUNT_IP_MAP:
    RELATIONS_DATA.append({
        "source_type": "account", "source_idx": a_idx,
        "target_type": "ip", "target_idx": ip_idx,
        "relation_type": RelationType.ASSOCIATED_WITH,
        "evidence": f"账号{ACCOUNTS[a_idx]['value']}关联IP {IPS[ip_idx]['value']}",
        "confidence": 0.75,
    })

BLACKTALK_ORG_MAP = [(0, 3), (1, 4), (2, 3), (4, 1), (3, 2)]
for b_idx, o_idx in BLACKTALK_ORG_MAP:
    RELATIONS_DATA.append({
        "source_type": "blacktalk", "source_idx": b_idx,
        "target_type": "organization", "target_idx": o_idx,
        "relation_type": RelationType.ASSOCIATED_WITH,
        "evidence": f"黑话'{BLACKTALKS[b_idx]['value']}'常用于{ORGANIZATIONS[o_idx]['value']}的活动中",
        "confidence": 0.7,
    })

PERSON_COMM_MAP = [(0, 1), (0, 2), (4, 5)]
for p1_idx, p2_idx in PERSON_COMM_MAP:
    RELATIONS_DATA.append({
        "source_type": "person", "source_idx": p1_idx,
        "target_type": "person", "target_idx": p2_idx,
        "relation_type": RelationType.COMMUNICATES_WITH,
        "evidence": f"{PERSONS[p1_idx]['value']}与{PERSONS[p2_idx]['value']}存在联络",
        "confidence": 0.72,
    })

ORG_WALLET_MAP = [(0, 0), (3, 1)]
for o_idx, w_idx in ORG_WALLET_MAP:
    RELATIONS_DATA.append({
        "source_type": "organization", "source_idx": o_idx,
        "target_type": "crypto_wallet", "target_idx": w_idx,
        "relation_type": RelationType.ASSOCIATED_WITH,
        "evidence": f"{ORGANIZATIONS[o_idx]['value']}关联钱包{CRYPTO_WALLETS[w_idx]['value'][:20]}...",
        "confidence": 0.8,
    })

PERSON_EMAIL_MAP = [(0, 0), (5, 1), (3, 2)]
for p_idx, e_idx in PERSON_EMAIL_MAP:
    RELATIONS_DATA.append({
        "source_type": "person", "source_idx": p_idx,
        "target_type": "email", "target_idx": e_idx,
        "relation_type": RelationType.USES,
        "evidence": f"{PERSONS[p_idx]['value']}使用邮箱{EMAILS[e_idx]['value']}",
        "confidence": 0.78,
    })

ORG_TOOL_MAP = [(2, 2), (0, 1)]
for o_idx, t_idx in ORG_TOOL_MAP:
    RELATIONS_DATA.append({
        "source_type": "organization", "source_idx": o_idx,
        "target_type": "tool", "target_idx": t_idx,
        "relation_type": RelationType.CONTROLS,
        "evidence": f"{ORGANIZATIONS[o_idx]['value']}控制{TOOLS[t_idx]['value']}",
        "confidence": 0.82,
    })

PERSON_DOMAIN_MAP = [(1, 0), (3, 1)]
for p_idx, d_idx in PERSON_DOMAIN_MAP:
    RELATIONS_DATA.append({
        "source_type": "person", "source_idx": p_idx,
        "target_type": "domain", "target_idx": d_idx,
        "relation_type": RelationType.USES,
        "evidence": f"{PERSONS[p_idx]['value']}使用钓鱼域名{DOMAINS[d_idx]['value']}",
        "confidence": 0.8,
    })

ORG_SELLS_MAP = [(4, 1), (0, 0)]
for o_idx, m_idx in ORG_SELLS_MAP:
    RELATIONS_DATA.append({
        "source_type": "organization", "source_idx": o_idx,
        "target_type": "malware", "target_idx": m_idx,
        "relation_type": RelationType.SELLS,
        "evidence": f"{ORGANIZATIONS[o_idx]['value']}出售{MALWARES[m_idx]['value']}",
        "confidence": 0.75,
    })

BLACKTALK_DERIVED_MAP = [(5, 0), (7, 2)]
for b_idx, t_idx in BLACKTALK_DERIVED_MAP:
    RELATIONS_DATA.append({
        "source_type": "blacktalk", "source_idx": b_idx,
        "target_type": "tool", "target_idx": t_idx,
        "relation_type": RelationType.DERIVED_FROM,
        "evidence": f"黑话'{BLACKTALKS[b_idx]['value']}'源自{TOOLS[t_idx]['value']}相关活动",
        "confidence": 0.7,
    })

ORG_BUYS_MAP = [(1, 1)]
for o_idx, m_idx in ORG_BUYS_MAP:
    RELATIONS_DATA.append({
        "source_type": "organization", "source_idx": o_idx,
        "target_type": "malware", "target_idx": m_idx,
        "relation_type": RelationType.BUYS,
        "evidence": f"{ORGANIZATIONS[o_idx]['value']}购买{MALWARES[m_idx]['value']}",
        "confidence": 0.72,
    })


RAW_INTELLIGENCE_DATA = [
    {
        "source": "darkweb",
        "content": "【出售】2024年中国某电商平台完整数据库，包含1200万用户记录，字段：姓名、身份证号、手机号、收货地址、支付信息。支持抽样验证，价格面议。联系方式：暗网市场ID: D4rkV3nd0r",
        "raw_content": "[D4rkV3nd0r] 出售2024年中国电商平台数据库 | 12M records | fullz: name+id+phone+address+payment | sample available | PM for price",
        "status": "raw",
        "threat_level": "critical",
        "metadata": {"threat_level": "critical", "category": "data_breach", "language": "zh", "confidence": 0.9},
    },
    {
        "source": "telegram",
        "content": "紧急通知：新版钓鱼页面生成器v3.2已发布，支持仿冒国内前20大银行和支付平台，自带SSL证书自动配置，域名轮换功能。需要的私聊 @phish_tool_admin，限量50份。",
        "raw_content": "🚀 钓鱼页面生成器v3.2发布 | 支持20+银行/支付平台 | 自动SSL | 域名轮换 | 私聊@phish_tool_admin | 限量50份",
        "status": "raw",
        "threat_level": "high",
        "metadata": {"threat_level": "high", "category": "phishing_tool", "language": "zh", "confidence": 0.88},
    },
    {
        "source": "wechat",
        "content": "跑分渠道稳定开通中，日处理量500w+，费率1.5%，T+0结算。支持支付宝、微信、银联通道。四件套齐全可开专属通道，有意者加微信：pafen2024",
        "raw_content": "跑分渠道 | 日500w+ | 费率1.5% | T+0 | 支付宝/微信/银联 | 四件套开专属通道 | wx:pafen2024",
        "status": "raw",
        "threat_level": "high",
        "metadata": {"threat_level": "high", "category": "money_laundering", "language": "zh", "confidence": 0.85},
    },
    {
        "source": "forum",
        "content": "分析报告：近期杀猪盘新手法——诈骗团伙开始使用AI换脸技术进行视频通话，受害者难以辨别真伪。建议加强公众防范意识教育，重点提醒网恋对象要求投资转账的风险。",
        "raw_content": "杀猪盘新手法分析：AI换脸视频通话 | 受害者难以辨别 | 建议：加强防范教育 | 重点：网恋+投资=诈骗",
        "status": "pending",
        "threat_level": "high",
        "metadata": {"threat_level": "high", "category": "fraud_analysis", "language": "zh", "confidence": 0.82},
    },
    {
        "source": "darkweb",
        "content": "批量出售中国公民四件套（身份证+银行卡+手机卡+U盾），均为真人实名，可配合猫池使用。每套价格：800-1500元，量大从优。支持远程验证。联系：暗网市场ID: FullSet_D3aler",
        "raw_content": "[FullSet_D3aler] 批量四件套 | 实名真人 | 配合猫池 | 800-1500/套 | 批发优惠 | 远程验证",
        "status": "raw",
        "threat_level": "critical",
        "metadata": {"threat_level": "critical", "category": "identity_fraud", "language": "zh", "confidence": 0.92},
    },
    {
        "source": "telegram",
        "content": "水房团队招募：需要经验丰富的走账人员，熟悉虚拟货币OTC操作，日薪3000+。工作地点东南亚，包食宿机票。有意者TG联系：@shuifang_hr",
        "raw_content": "水房招募 | 走账人员 | 虚拟货币OTC | 日薪3000+ | 东南亚 | 包食宿机票 | TG:@shuifang_hr",
        "status": "raw",
        "threat_level": "high",
        "metadata": {"threat_level": "high", "category": "money_laundering_recruitment", "language": "zh", "confidence": 0.8},
    },
    {
        "source": "web",
        "content": "安全通告：检测到大量仿冒某国有银行的钓鱼网站，域名采用相似字符替换策略（如将'1'替换为'l'），已确认涉及用户超过5000人。钓鱼页面通过短信链接传播，要求用户输入网银账号和密码。",
        "raw_content": "安全通告：仿冒国有银行钓鱼网站 | 域名字符替换 | 5000+用户受影响 | 短信传播 | 窃取网银凭证",
        "status": "pending",
        "threat_level": "high",
        "metadata": {"threat_level": "high", "category": "phishing_alert", "language": "zh", "confidence": 0.9},
    },
    {
        "source": "darkweb",
        "content": "出售远程控制木马源码，功能包括：键盘记录、屏幕截图、浏览器凭证窃取、加密货币钱包劫持。支持Windows/Mac双平台，免杀效果好。附赠部署教程。价格：5BTC",
        "raw_content": "[MalwareDev] RAT源码出售 | 键盘记录+截图+凭证窃取+钱包劫持 | Win/Mac | 免杀 | 部署教程 | 5BTC",
        "status": "raw",
        "threat_level": "critical",
        "metadata": {"threat_level": "critical", "category": "malware_sale", "language": "zh", "confidence": 0.88},
    },
    {
        "source": "wechat",
        "content": "料子批发：最新脱库数据，某省社保系统20万人，含姓名+身份证+社保号+手机号。质量保证，可抽样。价格：2元/条，万条起批。需要的私聊",
        "raw_content": "料子批发 | 某省社保系统20万人 | 姓名+身份证+社保号+手机号 | 2元/条 | 万条起批",
        "status": "raw",
        "threat_level": "critical",
        "metadata": {"threat_level": "critical", "category": "data_sale", "language": "zh", "confidence": 0.9},
    },
    {
        "source": "telegram",
        "content": "猫池设备清仓：32口猫池，支持移动联通电信三网，自带管理后台，可远程控制。适合接码、养号使用。原价3500，现价2200包邮。仅剩15台。联系：@maochi_sale",
        "raw_content": "猫池清仓 | 32口 | 三网 | 远程管理 | 接码/养号 | 2200包邮 | 余15台 | @maochi_sale",
        "status": "raw",
        "threat_level": "medium",
        "metadata": {"threat_level": "medium", "category": "equipment_sale", "language": "zh", "confidence": 0.85},
    },
    {
        "source": "forum",
        "content": "技术分享：如何利用社会工程学绕过银行风控系统进行大额转账。核心思路：1.获取目标身份信息 2.模拟目标常用设备和网络环境 3.分步骤逐步提高转账额度 4.利用节假日风控宽松时段操作。仅供研究参考。",
        "raw_content": "社工绕过银行风控 | 1.获取身份信息 2.模拟设备环境 3.逐步提额 4.节假日操作 | 仅供研究",
        "status": "pending",
        "threat_level": "high",
        "metadata": {"threat_level": "high", "category": "technique_sharing", "language": "zh", "confidence": 0.78},
    },
    {
        "source": "darkweb",
        "content": "长期收购企业邮箱凭证，要求：1.国内中大型企业 2.高管或财务岗位优先 3.能登录OA系统的加分。价格根据企业规模和权限等级面议。安全交易，走暗网担保。",
        "raw_content": "[CredBuyer] 长期收购企业邮箱凭证 | 中大型企业 | 高管/财务优先 | OA加分 | 价格面议 | 暗网担保",
        "status": "raw",
        "threat_level": "high",
        "metadata": {"threat_level": "high", "category": "credential_theft", "language": "zh", "confidence": 0.82},
    },
    {
        "source": "wechat",
        "content": "杀猪盘话术模板更新：新增AI语音克隆模块，可模拟目标熟人声音进行电话确认，大幅提高信任度。配合原有聊天话术使用，转化率提升40%。老客户免费升级。",
        "raw_content": "杀猪盘话术更新 | AI语音克隆 | 模拟熟人声音 | 信任度提升 | 转化率+40% | 老客户免费",
        "status": "raw",
        "threat_level": "critical",
        "metadata": {"threat_level": "critical", "category": "fraud_tool", "language": "zh", "confidence": 0.85},
    },
    {
        "source": "telegram",
        "content": "虚拟货币洗钱通道：BTC/USDT→CNY，日处理量200万，汇率实时+2%，1小时内到账。长期合作可享优惠费率。走码商通道，安全稳定。联系：@crypto_wash_88",
        "raw_content": "虚拟货币洗钱 | BTC/USDT→CNY | 日200万 | 实时+2% | 1小时到账 | 码商通道 | @crypto_wash_88",
        "status": "raw",
        "threat_level": "high",
        "metadata": {"threat_level": "high", "category": "crypto_laundering", "language": "zh", "confidence": 0.88},
    },
    {
        "source": "web",
        "content": "威胁情报：监测到针对国内金融机构的APT攻击活动，攻击者利用0day漏洞入侵内部网络，部署持久化后门。攻击IP段：185.234.72.0/24，关联域名使用Let's Encrypt证书。攻击时间集中在工作日9:00-18:00。",
        "raw_content": "APT攻击国内金融机构 | 0day漏洞 | 持久化后门 | IP:185.234.72.0/24 | Let's Encrypt | 工作日9-18时",
        "status": "pending",
        "threat_level": "critical",
        "metadata": {"threat_level": "critical", "category": "apt_attack", "language": "zh", "confidence": 0.92},
    },
    {
        "source": "forum",
        "content": "接码平台推荐：新开接码平台，支持国内主流APP注册验证码接收，号码覆盖全国31省，单价0.5-2元。API接口文档完善，适合批量养号。注册送10元体验金。",
        "raw_content": "接码平台推荐 | 主流APP验证码 | 31省号码 | 0.5-2元/条 | API接口 | 批量养号 | 注册送10元",
        "status": "raw",
        "threat_level": "medium",
        "metadata": {"threat_level": "medium", "category": "sms_service", "language": "zh", "confidence": 0.8},
    },
    {
        "source": "darkweb",
        "content": "出售某省公安机关内部系统访问权限，可查询公民完整户籍信息、出入境记录、车辆信息。权限有效期6个月，价格：50BTC。仅限暗网交易，不议价。",
        "raw_content": "[InsiderAccess] 出售公安系统权限 | 户籍+出入境+车辆 | 6个月有效期 | 50BTC | 暗网交易 | 不议价",
        "status": "raw",
        "threat_level": "critical",
        "metadata": {"threat_level": "critical", "category": "insider_access", "language": "zh", "confidence": 0.85},
    },
    {
        "source": "telegram",
        "content": "DDoS攻击服务：提供专业DDoS压力测试服务，支持HTTP/HTTPS/TCP/UDP多种协议，峰值流量500Gbps+，可绕过Cloudflare等CDN防护。按小时计费，测试联系：@ddos_pro_service",
        "raw_content": "DDoS服务 | HTTP/HTTPS/TCP/UDP | 500Gbps+ | 绕过CDN | 按小时计费 | @ddos_pro_service",
        "status": "raw",
        "threat_level": "high",
        "metadata": {"threat_level": "high", "category": "ddos_service", "language": "zh", "confidence": 0.82},
    },
    {
        "source": "wechat",
        "content": "黑产工具合集出售：包含自动注册机、养号系统、群控软件、自动加人工具、消息群发器。全套打包价8000元，单买2000元/个。支持远程演示，满意后付款。",
        "raw_content": "黑产工具合集 | 注册机+养号+群控+加人+群发 | 打包8000 | 单买2000/个 | 远程演示 | 满意付款",
        "status": "raw",
        "threat_level": "high",
        "metadata": {"threat_level": "high", "category": "tool_sale", "language": "zh", "confidence": 0.85},
    },
    {
        "source": "forum",
        "content": "撞库工具分享：最新版撞库工具，支持多线程并发，内置代理池管理，自动去重和结果分类。搭配最新泄露数据库使用效果最佳。开源免费，仅供安全研究。",
        "raw_content": "撞库工具 | 多线程 | 代理池 | 自动去重 | 搭配泄露库 | 开源免费 | 仅供研究",
        "status": "pending",
        "threat_level": "medium",
        "metadata": {"threat_level": "medium", "category": "credential_stuffing", "language": "zh", "confidence": 0.78},
    },
    {
        "source": "darkweb",
        "content": "出售某互联网公司内部员工通讯录，包含3万名员工姓名、工号、部门、职位、手机号、企业邮箱。可配合社工钓鱼使用。样本已上传，自行验证。价格：3BTC。",
        "raw_content": "[CorpData] 互联网公司员工通讯录 | 3万人 | 姓名+工号+部门+职位+手机+邮箱 | 社工钓鱼 | 3BTC | 样本可验",
        "status": "raw",
        "threat_level": "high",
        "metadata": {"threat_level": "high", "category": "corporate_data_breach", "language": "zh", "confidence": 0.88},
    },
]


PIRS_DATA = [
    {
        "title": "新型信贷欺诈手法监测",
        "description": "监测近期出现的信贷欺诈新型手法，包括套路贷、房贷背债等变种，重点关注利用AI技术辅助的信贷欺诈模式",
        "priority": "high",
        "status": "active",
        "keywords": ["信贷", "欺诈", "套路贷", "背债", "AI欺诈"],
        "target_sources": ["telegram", "forum", "wechat"],
    },
    {
        "title": "暗网数据泄露追踪",
        "description": "追踪暗网市场上出售的中国公民个人数据泄露事件，重点关注金融、医疗、教育等敏感行业的数据泄露",
        "priority": "critical",
        "status": "active",
        "keywords": ["数据泄露", "脱库", "个人信息", "fullz", "数据库"],
        "target_sources": ["darkweb", "forum"],
    },
    {
        "title": "AI赋能黑产趋势分析",
        "description": "分析黑产利用AI技术（换脸、语音克隆、自动化攻击）的趋势和案例，评估AI黑产对传统风控体系的冲击",
        "priority": "medium",
        "status": "active",
        "keywords": ["AI", "换脸", "语音克隆", "自动化", "深度伪造"],
        "target_sources": ["telegram", "wechat", "darkweb"],
    },
    {
        "title": "跨境洗钱通道追踪",
        "description": "追踪利用虚拟货币、第三方支付等渠道进行的跨境洗钱活动，重点监测跑分平台、虚拟货币OTC交易和地下钱庄",
        "priority": "critical",
        "status": "active",
        "keywords": ["洗钱", "跑分", "虚拟货币", "OTC", "地下钱庄", "水房"],
        "target_sources": ["telegram", "darkweb", "wechat"],
    },
    {
        "title": "钓鱼攻击基础设施监测",
        "description": "监测新型钓鱼攻击基础设施，包括钓鱼域名注册、钓鱼页面生成工具、SSL证书滥用等，建立钓鱼攻击预警机制",
        "priority": "high",
        "status": "active",
        "keywords": ["钓鱼", "phishing", "域名", "SSL", "仿冒"],
        "target_sources": ["web", "darkweb", "forum"],
    },
]


ADDITIONAL_BLACKTALK_TERMS = [
    {"term": "狗带", "meaning": "被抓，指黑产人员被执法部门逮捕", "category": "general",
     "context": "听说隔壁组的阿强狗带了，大家最近小心点"},
    {"term": "开料", "meaning": "开始使用被盗数据进行诈骗活动", "category": "fraud",
     "context": "这批料子质量不错，明天开料"},
    {"term": "黑吃黑", "meaning": "黑产内部互相欺骗或抢夺资源", "category": "general",
     "context": "那个料主黑吃黑，给的料子一半是假的"},
    {"term": "免杀", "meaning": "绕过杀毒软件检测的技术或方法", "category": "hacking",
     "context": "这个木马免杀效果很好，主流杀软都过"},
    {"term": "暗桩", "meaning": "隐藏的后门程序或潜伏的内部人员", "category": "hacking",
     "context": "服务器里留了个暗桩，随时可以回去"},
    {"term": "炸群", "meaning": "在群聊中大量发送诈骗信息或广告", "category": "fraud",
     "context": "今晚8点集中炸群，话术已经准备好了"},
    {"term": "换脸", "meaning": "使用AI深度伪造技术替换视频中的人脸", "category": "fraud",
     "context": "换脸技术现在很成熟了，视频通话都看不出来"},
    {"term": "克隆音", "meaning": "使用AI技术克隆他人声音进行语音诈骗", "category": "fraud",
     "context": "克隆音只需要3秒语音样本就能生成"},
    {"term": "羊毛党", "meaning": "专门利用优惠活动漏洞非法获利的群体", "category": "fraud",
     "context": "这个活动被羊毛党薅了，损失几十万"},
    {"term": "料商", "meaning": "专门贩卖个人信息的商人", "category": "fraud",
     "context": "料商那边有新货，某银行客户数据"},
    {"term": "车队", "meaning": "专门负责资金转移和取现的团队", "category": "money_laundering",
     "context": "车队已经就位，等资金到位就开始走账"},
    {"term": "接单", "meaning": "接受黑产任务或订单", "category": "general",
     "context": "今天接了三个单，都是脱库的活"},
    {"term": "交割", "meaning": "完成黑产交易的交付环节", "category": "general",
     "context": "数据已经交割完毕，确认收款"},
    {"term": "洗手", "meaning": "退出黑产行业，不再参与违法活动", "category": "general",
     "context": "老王去年就洗手了，现在做正经生意"},
    {"term": "僵尸网络", "meaning": "被集中控制的大量受感染设备网络", "category": "hacking",
     "context": "僵尸网络规模扩大到10万台了"},
    {"term": "零日", "meaning": "尚未被公开或修补的软件安全漏洞", "category": "hacking",
     "context": "手里有个零日，可以远程提权"},
    {"term": "渗透", "meaning": "入侵目标系统或网络的过程", "category": "hacking",
     "context": "目标系统渗透完成，已获取管理员权限"},
    {"term": "逆向", "meaning": "对软件进行逆向工程分析", "category": "hacking",
     "context": "逆向分析发现这个APP的加密算法有漏洞"},
    {"term": "钓鱼", "meaning": "通过伪造网站或信息窃取用户凭证", "category": "fraud",
     "context": "钓鱼页面已经部署好了，等鱼上钩"},
    {"term": "暗网", "meaning": "需要特殊工具才能访问的隐藏网络", "category": "general",
     "context": "这批货只在暗网上流通"},
    {"term": "洗白", "meaning": "将非法资金转为合法来源的过程", "category": "money_laundering",
     "context": "资金通过三层层级已经洗白了"},
    {"term": "过桥", "meaning": "通过中间账户转移资金以掩盖来源", "category": "money_laundering",
     "context": "先过桥到几个空壳公司账户，再转出来"},
    {"term": "码商", "meaning": "提供收款二维码用于洗钱的人", "category": "money_laundering",
     "context": "码商那边准备了500个二维码，够今天用的"},
    {"term": "通道", "meaning": "用于资金转移的支付渠道", "category": "money_laundering",
     "context": "支付宝通道今天被风控了，换微信通道"},
    {"term": "电诈", "meaning": "电信诈骗，通过电话或网络实施诈骗", "category": "fraud",
     "context": "电诈窝点转移到东南亚了，国内打击太严"},
]


REPORTS_DATA = [
    {
        "title": "暗影网络犯罪集团活动分析报告",
        "status": "published",
        "summary": "本报告对暗影网络犯罪集团近期的活动进行了深入分析。该组织主要活跃于东南亚地区，通过钓鱼攻击、数据贩卖和加密货币洗钱等手段进行非法活动。目前已识别出8名核心成员，关联5个加密钱包地址和3个钓鱼网站域名。建议加强对此组织的监控，并通知相关执法部门。",
        "key_findings_json": json.dumps(["组织核心成员8人，头目为张伟", "使用BTC和ETH进行资金清洗", "关联3个钓鱼网站域名", "月均非法交易额估计超过500万元"], ensure_ascii=False),
        "threat_actors_json": json.dumps([{"name": "张伟", "role": "头目", "confidence": 0.9}, {"name": "李明", "role": "技术骨干", "confidence": 0.85}], ensure_ascii=False),
        "iocs_json": json.dumps(["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "185.220.101.34", "secure-login-verify.com"], ensure_ascii=False),
        "confidence_score": 0.88,
        "author": "系统自动生成",
    },
    {
        "title": "2024年Q4电信诈骗趋势报告",
        "status": "published",
        "summary": "本季度电信诈骗案件数量持续上升，杀猪盘类诈骗占比最高（42%），其次为冒充公检法（28%）和兼职诈骗（18%）。诈骗团伙 increasingly 使用AI语音合成技术，使得冒充类诈骗更难识别。建议加强公众教育，特别是针对中老年群体的反诈宣传。",
        "key_findings_json": json.dumps(["杀猪盘占比42%，为最大威胁类型", "AI语音合成技术被广泛采用", "跨境诈骗团伙活跃度增加35%", "虚拟货币支付占比从15%上升至28%"], ensure_ascii=False),
        "threat_actors_json": json.dumps([{"name": "龙腾诈骗团伙", "type": "organization", "confidence": 0.82}], ensure_ascii=False),
        "confidence_score": 0.82,
        "author": "系统自动生成",
    },
    {
        "title": "暗网数据泄露追踪月报",
        "status": "published",
        "summary": "本月监测到12起重大数据泄露事件，涉及电商、金融、医疗等多个行业。其中一起泄露事件涉及超过1200万条用户记录，包含姓名、身份证号和手机号等敏感信息。暗网数据交易价格持续走低，表明数据供给过剩。",
        "key_findings_json": json.dumps(["监测到12起重大数据泄露事件", "最大一起涉及1200万条用户记录", "数据交易价格同比下降40%", "医疗行业成为新目标"], ensure_ascii=False),
        "confidence_score": 0.75,
        "author": "系统自动生成",
    },
    {
        "title": "黑灰产暗语术语分析报告",
        "status": "published",
        "summary": "本报告整理了当前黑灰产领域常用的暗语术语85个，涵盖洗钱、诈骗、数据贩卖等多个领域。其中跑分、料子、四件套等术语使用频率最高。暗语的快速演变反映了黑产从业者规避监管的策略升级。",
        "key_findings_json": json.dumps(["整理暗语术语85个", "跑分、料子、四件套使用频率最高", "新术语月均增长5-8个", "暗语演变速度加快"], ensure_ascii=False),
        "confidence_score": 0.9,
        "author": "系统自动生成",
    },
    {
        "title": "加密货币洗钱渠道分析",
        "status": "review",
        "summary": "本报告分析了当前主流的加密货币洗钱渠道，包括混币器、跨链桥和去中心化交易所等。发现黑水洗钱网络通过ETH钱包0x742d35Cc...进行资金中转，累计交易额估计超过2000万元。",
        "key_findings_json": json.dumps(["混币器使用量月增22%", "跨链桥成为新洗钱通道", "黑水洗钱网络累计交易超2000万", "DeFi协议被滥用比例增加"], ensure_ascii=False),
        "confidence_score": 0.78,
        "author": "系统自动生成",
    },
    {
        "title": "钓鱼攻击手法演进分析",
        "status": "draft",
        "summary": "钓鱼攻击手法持续演进，从传统的邮件钓鱼发展到AI生成的个性化钓鱼页面。幽灵钓鱼组织使用的钓鱼页面生成器可自动仿冒各大平台，成功率较传统手法提升3倍。",
        "key_findings_json": json.dumps(["AI生成钓鱼页面成功率提升3倍", "多因素认证绕过技术出现", "移动端钓鱼攻击占比超过PC端", "钓鱼即服务(PhaaS)模式兴起"], ensure_ascii=False),
        "confidence_score": 0.72,
        "author": "系统自动生成",
    },
    {
        "title": "跨境网络赌博产业链分析",
        "status": "draft",
        "summary": "跨境网络赌博产业链日趋成熟，从引流、技术支撑到资金结算形成完整闭环。菜农（网络赌博运营者）通过Telegram群组进行招募和管理，使用虚拟货币进行赌资结算。",
        "key_findings_json": json.dumps(["产业链形成完整闭环", "Telegram成为主要招募渠道", "虚拟货币结算占比超过60%", "东南亚地区为主要运营基地"], ensure_ascii=False),
        "confidence_score": 0.68,
        "author": "系统自动生成",
    },
    {
        "title": "恶意软件传播渠道监测报告",
        "status": "review",
        "summary": "本月监测到远程控制木马和DDoS攻击脚本在暗网大量交易。暗影集团同时运营钓鱼攻击套件和DDoS攻击脚本，形成双重威胁。远程控制木马主要通过钓鱼邮件和恶意软件捆绑传播。",
        "key_findings_json": json.dumps(["远程控制木马交易量增加50%", "DDoS攻击脚本价格下降30%", "恶意软件捆绑传播成为主流", "APT攻击工具开始流入黑市"], ensure_ascii=False),
        "confidence_score": 0.8,
        "author": "系统自动生成",
    },
]


async def seed_all():
    from app.config import settings
    if settings.is_production:
        logger.warning("seed_all() called in production environment — aborting seed to prevent fake data injection")
        return
    logger.info("=== 开始完整种子数据填充 ===")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("[1/9] 数据库表创建/验证完成")

    kg = KnowledgeGraph(persist_dir="./graph_data")

    entity_registry = {}
    now = datetime.now(timezone.utc)

    entity_defs = [
        ("person", EntityType.PERSON, PERSONS),
        ("organization", EntityType.ORGANIZATION, ORGANIZATIONS),
        ("phone", EntityType.PHONE, PHONES),
        ("account", EntityType.ACCOUNT, ACCOUNTS),
        ("ip", EntityType.IP, IPS),
        ("domain", EntityType.DOMAIN, DOMAINS),
        ("email", EntityType.EMAIL, EMAILS),
        ("blacktalk", EntityType.BLACKTALK, BLACKTALKS),
        ("tool", EntityType.TOOL, TOOLS),
        ("crypto_wallet", EntityType.CRYPTO_WALLET, CRYPTO_WALLETS),
        ("malware", EntityType.MALWARE, MALWARES),
    ]

    entity_count = 0
    for type_key, entity_type, data_list in entity_defs:
        entity_registry[type_key] = []
        for item in data_list:
            entity = Entity(
                id=uuid.uuid4().hex,
                type=entity_type,
                value=item["value"],
                context=item.get("context"),
                confidence=item.get("confidence", 0.5),
                first_seen=now - timedelta(days=random.randint(1, 365)),
                last_seen=now,
                metadata={},
            )
            await kg.add_entity(entity)
            entity_registry[type_key].append(entity.id)
            entity_count += 1
    logger.info(f"[2/9] 知识图谱实体填充完成: {entity_count} 个实体")

    relation_count = 0
    for rel_data in RELATIONS_DATA:
        source_id = entity_registry[rel_data["source_type"]][rel_data["source_idx"]]
        target_id = entity_registry[rel_data["target_type"]][rel_data["target_idx"]]
        relation = Relation(
            id=uuid.uuid4().hex,
            source_entity_id=source_id,
            target_entity_id=target_id,
            type=rel_data["relation_type"],
            confidence=rel_data.get("confidence", 0.5),
            evidence=rel_data.get("evidence"),
            first_seen=now - timedelta(days=random.randint(1, 180)),
            last_seen=now,
        )
        await kg.add_relation(relation)
        relation_count += 1
    logger.info(f"[2/9] 知识图谱关系填充完成: {relation_count} 条关系")

    await kg.save()
    logger.info("[2/9] 知识图谱已保存")

    async with async_session_factory() as session:
        for idx, intel in enumerate(RAW_INTELLIGENCE_DATA):
            raw_id = uuid.uuid4().hex
            collected_at = now - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23))
            metadata = intel.get("metadata", {})
            raw = RawIntelligenceTable(
                id=raw_id,
                source=intel["source"],
                content=intel["content"],
                raw_content=intel.get("raw_content"),
                collected_at=collected_at,
                status=intel.get("status", "raw"),
                metadata_json=json.dumps(metadata, ensure_ascii=False),
            )
            session.add(raw)
        await session.commit()
    logger.info(f"[3/9] 原始情报数据填充完成: {len(RAW_INTELLIGENCE_DATA)} 条")

    PIR_IDS = []
    async with async_session_factory() as session:
        for pir_data in PIRS_DATA:
            pir_id = uuid.uuid4().hex
            PIR_IDS.append(pir_id)
            pir = PIRTable(
                id=pir_id,
                title=pir_data["title"],
                description=pir_data["description"],
                priority=pir_data["priority"],
                status=pir_data.get("status", "active"),
                keywords_json=json.dumps(pir_data["keywords"], ensure_ascii=False),
                target_sources_json=json.dumps(pir_data["target_sources"], ensure_ascii=False),
                created_at=now - timedelta(days=random.randint(1, 60)),
                updated_at=now,
            )
            session.add(pir)
        await session.commit()
    logger.info(f"[4/9] PIR情报需求填充完成: {len(PIRS_DATA)} 条")

    async with async_session_factory() as session:
        for type_key, entity_type, data_list in entity_defs:
            for idx, item in enumerate(data_list):
                entity_id = entity_registry[type_key][idx]
                existing = await session.get(EntityTable, entity_id)
                if not existing:
                    entity_row = EntityTable(
                        id=entity_id,
                        type=entity_type.value,
                        value=item["value"],
                        context=item.get("context", ""),
                        confidence=item.get("confidence", 0.8),
                        first_seen=now - timedelta(days=random.randint(1, 365)),
                        last_seen=now,
                    )
                    session.add(entity_row)

        for rel_data in RELATIONS_DATA:
            source_id = entity_registry[rel_data["source_type"]][rel_data["source_idx"]]
            target_id = entity_registry[rel_data["target_type"]][rel_data["target_idx"]]
            rel_id = uuid.uuid4().hex
            rel_row = RelationTable(
                id=rel_id,
                source_entity_id=source_id,
                target_entity_id=target_id,
                type=rel_data["relation_type"].value,
                confidence=rel_data.get("confidence", 0.7),
                evidence=rel_data.get("evidence"),
                first_seen=now - timedelta(days=random.randint(1, 180)),
                last_seen=now,
            )
            session.add(rel_row)

        await session.commit()
    logger.info("[5/9] 实体和关系数据库表填充完成")

    async with async_session_factory() as session:
        for i, rdata in enumerate(REPORTS_DATA):
            report_id = uuid.uuid4().hex
            pir_id = PIR_IDS[i % len(PIR_IDS)] if PIR_IDS else None
            report_row = ReportTable(
                id=report_id,
                title=rdata["title"],
                pir_id=pir_id,
                status=rdata["status"],
                summary=rdata["summary"],
                key_findings_json=rdata.get("key_findings_json"),
                threat_actors_json=rdata.get("threat_actors_json"),
                iocs_json=rdata.get("iocs_json"),
                confidence_score=rdata.get("confidence_score", 0.75),
                author=rdata.get("author", "系统自动生成"),
                created_at=now - timedelta(days=random.randint(1, 30)),
                updated_at=now,
                published_at=now if rdata["status"] == "published" else None,
            )
            session.add(report_row)
        await session.commit()
    logger.info(f"[6/9] 报告数据填充完成: {len(REPORTS_DATA)} 条")

    async with async_session_factory() as session:
        raw_result = await session.execute(select(RawIntelligenceTable).limit(15))
        raw_items = raw_result.scalars().all()

        for raw in raw_items:
            cleaned_id = uuid.uuid4().hex
            cleaned = CleanedIntelligenceTable(
                id=cleaned_id,
                raw_id=raw.id,
                content=raw.content[:500] if raw.content else "",
                threat_level="info",
                cleaned_at=now,
            )
            session.add(cleaned)
            await session.flush()

            threat_levels = ["critical", "high", "medium", "low", "info"]
            threat_weights = [10, 25, 35, 20, 10]
            threat_level = random.choices(threat_levels, weights=threat_weights, k=1)[0]

            analyzed = AnalyzedIntelligenceTable(
                id=uuid.uuid4().hex,
                cleaned_id=cleaned_id,
                threat_level=threat_level,
                threat_categories_json=json.dumps([random.choice(["fraud", "phishing", "malware", "data_breach", "money_laundering"])], ensure_ascii=False),
                confidence_score=round(random.uniform(0.5, 0.95), 2),
                analysis_summary=f"经分析，该情报涉及{threat_level}级别威胁，建议纳入监控。",
                analyzed_at=now,
            )
            session.add(analyzed)

        await session.commit()
    logger.info(f"[7/9] 清洗和分析情报数据填充完成: {len(raw_items)} 条")

    try:
        embedding_engine = LocalEmbeddingEngine(dim=256)
        vector_store = VectorStore(
            persist_dir="./chroma_data",
            embedding_engine=embedding_engine,
        )
        blacktalk_engine = BlackTalkEngine(vector_store=vector_store)

        learned_count = 0
        for term_data in ADDITIONAL_BLACKTALK_TERMS:
            try:
                await blacktalk_engine.learn(
                    term=term_data["term"],
                    meaning=term_data["meaning"],
                    context=term_data["context"],
                    source="manual",
                )
                learned_count += 1
            except Exception as exc:
                logger.warning(f"添加黑话术语'{term_data['term']}'失败: {exc}")

        try:
            await blacktalk_engine.initialize_vectors()
        except Exception as exc:
            logger.warning(f"黑话向量初始化失败（不影响数据填充）: {exc}")

        logger.info(f"[8/9] 黑话术语填充完成: {learned_count} 个新术语 (引擎总词库: {len(blacktalk_engine._dictionary)})")
    except Exception as exc:
        logger.warning(f"BlackTalkEngine初始化失败，跳过黑话术语填充: {exc}")
        logger.info("[8/9] 黑话术语填充跳过（VectorStore不可用）")

    await kg.save()
    logger.info("[9/9] 知识图谱最终持久化完成")

    stats = await kg.get_statistics()
    logger.info(f"=== 种子数据填充完成 ===")
    logger.info(f"  知识图谱: {stats['node_count']} 个节点, {stats['edge_count']} 条边")
    logger.info(f"  实体类型分布: {stats['entity_types']}")
    logger.info(f"  关系类型分布: {stats['relation_types']}")
    logger.info(f"  原始情报: {len(RAW_INTELLIGENCE_DATA)} 条")
    logger.info(f"  PIR需求: {len(PIRS_DATA)} 条")
    logger.info(f"  报告: {len(REPORTS_DATA)} 条")
    logger.info(f"  黑话术语: {len(ADDITIONAL_BLACKTALK_TERMS)} 个新增")


if __name__ == "__main__":
    if not settings.SEED_DATABASE:
        import sys
        print("WARNING: seed_full.py is designed for development/demo only. Set SEED_DATABASE=true in .env to enable.", file=sys.stderr)
        sys.exit(1)
    asyncio.run(seed_all())
