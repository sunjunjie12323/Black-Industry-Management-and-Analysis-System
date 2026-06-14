import asyncio
import json
import uuid
import random
import re
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

from loguru import logger

from app.core.tracing import get_tracer

from app.core.data_governance import DataClassification, DataMinimizer, ClassificationLevel
from app.core.data_masking import PIIDetector
from app.core.message_queue import TOPIC_INTELLIGENCE_COLLECTED

from app.db.tables import RawIntelligenceTable, PIRTable
from app.core.knowledge_graph import KnowledgeGraph
from app.models.entity import Entity, EntityType, Relation, RelationType


_DEFAULT_RSS_SOURCES = [
    {
        "name": "CISA KEV",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "json_api",
        "source_tag": "web",
        "parser": "cisa_kev",
        "poll_interval_minutes": 60,
    },
    {
        "name": "URLhaus",
        "url": "https://urlhaus-api.abuse.ch/v1/recent/",
        "type": "json_api",
        "source_tag": "web",
        "parser": "urlhaus",
        "poll_interval_minutes": 30,
    },
    {
        "name": "MalwareBazaar",
        "url": "https://mb-api.abuse.ch/api/v1/",
        "type": "json_api_post",
        "source_tag": "darkweb",
        "parser": "malware_bazaar",
        "post_data": {"query": "get_recent", "selector": "time"},
        "poll_interval_minutes": 30,
    },
]

_DEFAULT_RSS_FEEDS = [
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "type": "rss",
        "source_tag": "web",
        "poll_interval_minutes": 60,
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "type": "rss",
        "source_tag": "web",
        "poll_interval_minutes": 60,
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "type": "rss",
        "source_tag": "web",
        "poll_interval_minutes": 120,
    },
]

_THREAT_LEVELS = ["critical", "high", "medium", "low", "info"]
_THREAT_LEVEL_WEIGHTS = [10, 25, 35, 20, 10]

_SOURCE_TYPES = ["darkweb", "telegram", "forum", "wechat", "web"]
_SOURCE_WEIGHTS = [30, 25, 20, 15, 10]

_INTEL_TEMPLATES: List[Dict] = [
    {
        "category": "data_breach_ecommerce",
        "templates": [
            "【出售】{year}年{platform}电商数据库，包含{count}万用户记录，字段：姓名、身份证号、手机号、收货地址、支付信息。支持抽样验证，价格面议。联系方式：暗网市场ID: {vendor_id}",
            "脱库数据出售：{platform}电商平台{year}年完整用户库，{count}万条，含实名+收货地址+支付绑定，数据新鲜度{days}天内。暗网交易，走担保。联系：{vendor_id}",
        ],
        "threat_level": "critical",
        "source_pool": ["darkweb", "forum"],
    },
    {
        "category": "data_breach_finance",
        "templates": [
            "金融数据出售：{platform}金融平台{count}万条用户数据，含姓名+身份证+银行卡号+手机号+信用评分，数据来源内部脱库。价格{price}BTC，支持小批量验证。暗网ID: {vendor_id}",
            "银行客户数据批量出售，{platform}{year}年{count}万条，含完整四要素，可配合跑分使用。暗网担保交易，联系：{vendor_id}",
        ],
        "threat_level": "critical",
        "source_pool": ["darkweb"],
    },
    {
        "category": "data_breach_medical",
        "templates": [
            "医疗数据出售：{platform}医疗系统{count}万人份，含姓名+身份证+病历编号+诊断信息+医保卡号。数据真实可验，价格{price}元/万条。暗网ID: {vendor_id}",
            "某省{platform}系统数据库，{count}万人，含姓名+身份证+{field}+手机号。质量保证，可抽样。价格：{price}元/条，万条起批。需要的私聊",
        ],
        "threat_level": "critical",
        "source_pool": ["darkweb", "wechat"],
    },
    {
        "category": "data_breach_education",
        "templates": [
            "教育系统数据：{platform}{count}万学生信息，含姓名+身份证+学号+家庭住址+家长手机号。适合精准诈骗和贷款推广。暗网ID: {vendor_id}",
            "高校数据批量出售，{platform}等{count}所学校，学生+教职工信息，含身份证和手机号，可用于注册和养号。联系：{vendor_id}",
        ],
        "threat_level": "high",
        "source_pool": ["darkweb", "telegram"],
    },
    {
        "category": "phishing_bank",
        "templates": [
            "紧急通知：检测到大量仿冒{bank}的钓鱼网站，域名采用{tactic}策略，已确认涉及用户超过{count}人。钓鱼页面通过{channel}传播，要求用户输入网银账号和密码。",
            "钓鱼攻击预警：{bank}网银仿冒页面活跃，使用{tactic}绕过安全检测，{channel}大规模推送钓鱼链接，已收到{count}起用户举报。请立即排查相关域名。",
        ],
        "threat_level": "high",
        "source_pool": ["web", "forum"],
    },
    {
        "category": "phishing_social",
        "templates": [
            "仿冒{platform}登录页面钓鱼攻击分析：攻击者注册{count}个相似域名，通过{channel}诱导用户输入账号密码，已窃取{count2}组凭证。钓鱼页面使用合法SSL证书。",
            "社交平台钓鱼报告：{platform}仿冒登录页激增，域名模式为{pattern}，通过{channel}传播。已发现{count}个活跃钓鱼站点，建议加入黑名单。",
        ],
        "threat_level": "high",
        "source_pool": ["web", "forum"],
    },
    {
        "category": "phishing_gov",
        "templates": [
            "仿冒政府网站钓鱼预警：检测到仿冒{gov_site}的钓鱼站点，通过{channel}发送虚假通知，诱导用户填写身份证号和银行卡信息。已影响{count}名用户，域名注册时间{days}天内。",
            "政务平台钓鱼攻击：{gov_site}仿冒站点利用{tactic}规避检测，通过{channel}大规模推送，目标为办理政务的公民群体。已确认{count}人信息泄露。",
        ],
        "threat_level": "critical",
        "source_pool": ["web"],
    },
    {
        "category": "fraud_pig_butcher",
        "templates": [
            "杀猪盘话术模板更新：新增AI语音克隆模块，可模拟目标熟人声音进行电话确认，大幅提高信任度。配合原有聊天话术使用，转化率提升{percent}%。老客户免费升级。",
            "杀猪盘新手法分析：诈骗团伙开始使用AI换脸技术进行视频通话，受害者难以辨别真伪。建议加强公众防范意识教育，重点提醒网恋对象要求投资转账的风险。",
        ],
        "threat_level": "high",
        "source_pool": ["wechat", "telegram"],
    },
    {
        "category": "fraud_impersonation",
        "templates": [
            '冒充公检法诈骗新变种：诈骗分子利用{tech}伪造{document}，通过{channel}联系受害者，要求将资金转入"安全账户"。近期{region}地区高发，已造成{amount}万元损失。',
            "冒充{role}诈骗预警：犯罪团伙使用{tech}技术增强可信度，通过{channel}精准定位受害者，单笔诈骗金额最高达{amount}万元。目标群体为{target}。",
        ],
        "threat_level": "high",
        "source_pool": ["wechat", "forum"],
    },
    {
        "category": "fraud_part_time",
        "templates": [
            "兼职诈骗新手法：通过{platform}发布高薪兼职信息，前期小额返利建立信任，后期要求{action}，受害者人均损失{amount}元。已发现{count}个诈骗群组。",
            "刷单诈骗变种分析：从传统电商刷单演变为{variant}，利用{platform}引流，话术升级为{tactic}。受害群体扩大至{target}，日均新增受害者{count}人。",
        ],
        "threat_level": "medium",
        "source_pool": ["wechat", "telegram"],
    },
    {
        "category": "money_laundering_crypto",
        "templates": [
            "虚拟货币洗钱通道：{crypto}→CNY，日处理量{amount}万，汇率实时+{rate}%，{hours}小时内到账。长期合作可享优惠费率。走码商通道，安全稳定。联系：{contact}",
            "加密货币混币服务：支持BTC/ETH/USDT混币，池容量{amount}BTC+，延迟{hours}小时出币，手续费{rate}%。已运行{days}天零故障。TG: {contact}",
        ],
        "threat_level": "high",
        "source_pool": ["telegram", "darkweb"],
    },
    {
        "category": "money_laundering_payment",
        "templates": [
            "跑分渠道稳定开通中，日处理量{amount}w+，费率{rate}%，T+0结算。支持支付宝、微信、银联通道。四件套齐全可开专属通道，有意者加微信：{contact}",
            "第三方支付跑分：{platform}通道稳定，日{amount}万额度，费率{rate}%起，支持T+0/T+1。已有{count}个码商入驻，资金安全有保障。联系：{contact}",
        ],
        "threat_level": "high",
        "source_pool": ["wechat", "telegram"],
    },
    {
        "category": "money_laundering_underground",
        "templates": [
            "地下钱庄通道：{region}↔{region2}双向资金通道，日处理量{amount}万美元，汇率优于银行{rate}%，{hours}小时到账。长期合作可签协议。暗网ID: {vendor_id}",
            "跨境资金通道：{region}→{region2}，支持大额{amount}万美元/笔，走{method}路线，{days}天到账。安全可靠，已运营{years}年。联系：{contact}",
        ],
        "threat_level": "critical",
        "source_pool": ["darkweb"],
    },
    {
        "category": "malware_trojan",
        "templates": [
            "出售远程控制木马源码，功能包括：键盘记录、屏幕截图、浏览器凭证窃取、加密货币钱包劫持。支持Windows/Mac双平台，免杀效果好。附赠部署教程。价格：{price}BTC",
            "定制RAT木马出售：{features}，支持{platform_os}平台，免杀期{days}天+，含远程部署服务。已售{count}份，零售后问题。暗网ID: {vendor_id}",
        ],
        "threat_level": "critical",
        "source_pool": ["darkweb", "telegram"],
    },
    {
        "category": "malware_ransomware",
        "templates": [
            "勒索软件即服务(RaaS)：{name}勒索软件加盟计划，提供定制化勒索页面、多语言支持、自动谈判系统。分成比例{rate}%，已累计勒索{amount}BTC。加入TG群：{contact}",
            "新型勒索软件{name}分析：采用{encrypt}加密算法，{hours}小时内完成全盘加密，支持{platform_os}系统。已攻击{count}个目标，赎金要求{amount}BTC起。解密工具暂无。",
        ],
        "threat_level": "critical",
        "source_pool": ["darkweb", "forum"],
    },
    {
        "category": "malware_ddos",
        "templates": [
            "DDoS攻击服务：提供专业DDoS压力测试服务，支持HTTP/HTTPS/TCP/UDP多种协议，峰值流量{bandwidth}Gbps+，可绕过{cdn}等CDN防护。按小时计费，测试联系：{contact}",
            "DDoS僵尸网络出租：{count}台肉鸡，峰值{bandwidth}Gbps，支持{protocols}协议，可绕过主流防护。按时计费，量大优惠。联系：{contact}",
        ],
        "threat_level": "high",
        "source_pool": ["telegram", "darkweb"],
    },
    {
        "category": "tool_maochi",
        "templates": [
            "猫池设备清仓：{ports}口猫池，支持移动联通电信三网，自带管理后台，可远程控制。适合接码、养号使用。原价{price_old}，现价{price_new}包邮。仅剩{count}台。联系：{contact}",
            "新款猫池到货：{ports}口/64口可选，支持4G/5G，远程管理，自动切换运营商，接码成功率{rate}%。批发价{price_new}起。联系：{contact}",
        ],
        "threat_level": "medium",
        "source_pool": ["telegram", "wechat"],
    },
    {
        "category": "tool_dialer",
        "templates": [
            "自动拨号软件v{version}：可模拟任意来电号码，支持{count}路并发，自动语音播报，录音存档。适合{use_case}场景。价格{price}元/套，含一年更新。联系：{contact}",
            "智能拨号系统：支持号码伪装、语音合成、自动应答，{count}路并发，成功率{rate}%。含话术模板库{templates}个。价格：{price}元。联系：{contact}",
        ],
        "threat_level": "high",
        "source_pool": ["telegram", "wechat"],
    },
    {
        "category": "tool_sijiantao",
        "templates": [
            "批量出售四件套（身份证+银行卡+手机卡+U盾），均为真人实名，可配合猫池使用。每套价格：{price_low}-{price_high}元，量大从优。支持远程验证。联系：{vendor_id}",
            "四件套长期供应：实名真人资料，含身份证+银行卡+手机卡+U盾，支持{count}省号码选择，配合猫池和接码平台使用效果最佳。暗网ID: {vendor_id}",
        ],
        "threat_level": "critical",
        "source_pool": ["darkweb", "wechat"],
    },
    {
        "category": "social_engineering_enterprise",
        "templates": [
            "长期收购企业邮箱凭证，要求：1.国内{scale}企业 2.{role_ent}岗位优先 3.能登录OA系统的加分。价格根据企业规模和权限等级面议。安全交易，走暗网担保。",
            "企业内网渗透服务：提供{service}，已成功渗透{count}家{industry}企业，获取{data_type}数据。价格面议，暗网担保交易。联系：{vendor_id}",
        ],
        "threat_level": "high",
        "source_pool": ["darkweb", "forum"],
    },
    {
        "category": "social_engineering_personal",
        "templates": [
            "社工库查询服务：支持身份证、手机号、姓名、邮箱等多维度查询，数据覆盖{count}亿+，实时更新。API接口调用，按次计费。暗网ID: {vendor_id}",
            "个人信息深度查询：输入手机号可查姓名+身份证+住址+亲属+开房记录+快递信息，数据来源{source}，准确率{rate}%。单次查询{price}元。联系：{contact}",
        ],
        "threat_level": "critical",
        "source_pool": ["darkweb", "telegram"],
    },
    {
        "category": "vulnerability_0day",
        "templates": [
            "出售0day漏洞：{product} {version_vuln}远程代码执行漏洞，影响全球{count}万+目标，已验证可利用。附带PoC和利用工具。价格：{price}BTC，仅售{buyers}人。暗网ID: {vendor_id}",
            "0day漏洞交易：{product}未公开漏洞，{vuln_type}类型，可{effect}，影响范围{scope}。含完整利用链和绕过方案。价格面议，暗网担保。联系：{vendor_id}",
        ],
        "threat_level": "critical",
        "source_pool": ["darkweb"],
    },
    {
        "category": "vulnerability_nday",
        "templates": [
            "Nday漏洞利用工具包：包含{count}个近期公开漏洞的自动化利用工具，覆盖{products}等热门产品。含批量扫描+自动利用模块。价格：{price}BTC。暗网ID: {vendor_id}",
            "漏洞利用框架更新：新增{count}个Nday漏洞利用模块，包括{vuln_list}。支持批量扫描和自动化利用，含详细文档。订阅价{price}BTC/月。联系：{vendor_id}",
        ],
        "threat_level": "high",
        "source_pool": ["darkweb", "forum"],
    },
    {
        "category": "vulnerability_web",
        "templates": [
            "Web漏洞批量扫描服务：覆盖SQL注入、XSS、SSRF、反序列化等{count}种漏洞类型，已集成{tools}等工具链。支持自定义目标列表和漏洞利用。价格：{price}元/次。联系：{contact}",
            "Web渗透工具包：集成{count}种常见Web漏洞检测和利用模块，支持{platform_os}平台，含自动化报告生成。开源+付费高级版。TG群：{contact}",
        ],
        "threat_level": "medium",
        "source_pool": ["forum", "telegram"],
    },
]

_ENTITY_TEMPLATES: List[Dict] = [
    {"type": EntityType.PERSON, "values": [
        "黑客'暗夜'", "黑客'幽灵'", "黑客'毒蛇'", "黑客'风暴'", "黑客'影子'",
        "卡商'老陈'", "卡商'阿龙'", "料商'小周'", "料商'大刘'", "码商'阿华'",
        "水房头目'阿杰'", "车手'小马'", "话务员'小美'", "操盘手'老赵'",
    ]},
    {"type": EntityType.ORGANIZATION, "values": [
        "暗夜黑客组织", "毒蛇数据联盟", "幽灵钓鱼团队", "风暴勒索集团",
        "影子洗钱网络", "黑鹰社工团队", "毒蛛诈骗团伙", "暗流跑分平台",
    ]},
    {"type": EntityType.IP, "values": [
        f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        for _ in range(20)
    ]},
    {"type": EntityType.DOMAIN, "values": [
        "secure-verify-portal.cn", "bank-login-safe.com", "pay-check-auth.net",
        "id-secure-verify.org", "login-safe-bank.cn", "auth-verify-pay.com",
        "safe-check-portal.net", "verify-identity.cn", "pay-secure-login.com",
        "check-bank-safe.org", "ssl-verify-auth.net", "token-secure-pay.cn",
    ]},
    {"type": EntityType.ACCOUNT, "values": [
        "Telegram: @dark_vendor_88", "Telegram: @phish_master_x",
        "Telegram: @data_hunter_pro", "Telegram: @crypto_wash_99",
        "QQ: 2837461950", "QQ: 3948572610", "QQ: 5061728394",
        "微信: shadow_op_2024", "微信: dark_trade_88",
    ]},
    {"type": EntityType.EMAIL, "values": [
        "dark_op@protonmail.com", "shadow_trade@tutanota.com",
        "phish_admin@secmail.pro", "data_vendor@protonmail.com",
        "crypto_wash@tutanota.com", "malware_dev@secmail.pro",
    ]},
    {"type": EntityType.TOOL, "values": [
        "自动注册机v4.0", "群控系统Pro", "养号大师", "消息群发器X",
        "撞库工具包", "社工库查询系统", "批量加人工具", "话术管理平台",
    ]},
    {"type": EntityType.MALWARE, "values": [
        "银行木马DarkSteal", "勒索软件NightLock", "挖矿木马CryptoMiner",
        "键盘记录器KeyHunter", "屏幕窃取器ScreenGrab", "凭证窃取器CredSnatcher",
    ]},
    {"type": EntityType.CRYPTO_WALLET, "values": [
        "bc1q" + uuid.uuid4().hex[:34],
        "0x" + uuid.uuid4().hex[:40],
    ]},
    {"type": EntityType.SERVICE, "values": [
        "接码平台速码", "跑分通道极速版", "VPN隐身服务", "代理池服务",
        "验证码识别服务", "短信轰炸服务", "域名注册批量服务",
    ]},
    {"type": EntityType.BLACKTALK, "values": [
        "开料", "黑吃黑", "免杀", "暗桩", "炸群", "换脸", "克隆音",
        "羊毛党", "料商", "车队", "接单", "交割", "洗手", "零日",
        "渗透", "逆向", "洗白", "过桥", "码商", "通道", "电诈",
    ]},
]

_RELATION_TEMPLATES: List[Dict] = [
    {"type": RelationType.USES, "evidence_template": "{source}使用{target}"},
    {"type": RelationType.BELONGS_TO, "evidence_template": "{source}属于{target}"},
    {"type": RelationType.COMMUNICATES_WITH, "evidence_template": "{source}与{target}存在联络"},
    {"type": RelationType.OPERATES, "evidence_template": "{source}运营{target}"},
    {"type": RelationType.SELLS, "evidence_template": "{source}出售{target}"},
    {"type": RelationType.BUYS, "evidence_template": "{source}购买{target}"},
    {"type": RelationType.ASSOCIATED_WITH, "evidence_template": "{source}与{target}存在关联"},
    {"type": RelationType.CONTROLS, "evidence_template": "{source}控制{target}"},
    {"type": RelationType.DERIVED_FROM, "evidence_template": "{source}源自{target}相关活动"},
]

_PIR_TEMPLATES: List[Dict] = [
    {
        "title": "新型{threat_type}手法监测",
        "description": "监测近期出现的{threat_type}新型手法，重点关注利用AI技术辅助的攻击模式，评估对现有风控体系的冲击",
        "priority_pool": ["high", "critical"],
        "keywords_pool": [["AI", "深度伪造", "自动化攻击"], ["新型", "变种", "升级"]],
        "sources_pool": ["telegram", "forum", "wechat", "darkweb"],
    },
    {
        "title": "{region}地区黑产活动追踪",
        "description": "追踪{region}地区黑产组织的最新活动动态，包括人员招募、工具交易、资金流转等关键情报",
        "priority_pool": ["high", "medium"],
        "keywords_pool": [["黑产", "招募", "交易"], ["资金", "通道", "洗钱"]],
        "sources_pool": ["telegram", "darkweb", "wechat"],
    },
    {
        "title": "{industry}行业数据泄露预警",
        "description": "监测{industry}行业相关数据泄露事件，追踪暗网数据交易动态，评估泄露数据规模和影响范围",
        "priority_pool": ["critical", "high"],
        "keywords_pool": [["数据泄露", "脱库", "数据库"], ["个人信息", "隐私", "fullz"]],
        "sources_pool": ["darkweb", "forum"],
    },
    {
        "title": "暗网{commodity}交易追踪",
        "description": "追踪暗网市场上{commodity}的交易动态，识别主要卖家和交易模式，建立预警机制",
        "priority_pool": ["high", "medium"],
        "keywords_pool": [["暗网", "交易", "出售"], ["购买", "批量", "价格"]],
        "sources_pool": ["darkweb", "telegram"],
    },
]

_FILL_VALUES = {
    "year": ["2024", "2025", "2026"],
    "platform": ["某电商", "某金融", "某社交", "某出行", "某外卖", "某视频", "某游戏", "某教育"],
    "count": ["50", "100", "200", "500", "800", "1200", "3000"],
    "vendor_id": ["D4rkV3nd0r", "D4taK1ng", "Sh4d0wDeal", "Bl4ckMkt", "N1ghtTr4der", "D3epSh0p", "S1lentV3ndor"],
    "price": ["2", "3", "5", "8", "10", "15", "20"],
    "price_low": ["800", "1000", "1200"],
    "price_high": ["1500", "2000", "3000"],
    "days": ["7", "15", "30", "60", "90"],
    "field": ["社保号", "医保号", "学历信息", "公积金账号"],
    "bank": ["工商银行", "建设银行", "农业银行", "中国银行", "招商银行", "交通银行"],
    "tactic": ["相似字符替换", "国际化域名", "子域名仿冒", "HTTPS伪造"],
    "channel": ["短信链接", "微信群", "QQ群", "钓鱼邮件", "搜索引擎广告"],
    "platform_social": ["微信", "QQ", "抖音", "微博", "小红书"],
    "pattern": ["login-{brand}-verify.com", "secure-{brand}-auth.cn", "{brand}-verify.net"],
    "gov_site": ["国家税务总局", "社保局", "公积金中心", "公安局", "民政局"],
    "percent": ["30", "40", "50", "60"],
    "tech": ["AI换脸技术", "来电显示伪造", "虚拟号码", "深度伪造语音"],
    "document": ["逮捕令", "法院传票", "冻结通知书", "协查通报"],
    "role": ["公检法人员", "银行客服", "快递员", "社保局工作人员"],
    "region": ["华东", "华南", "华北", "西南", "华中"],
    "amount": ["50", "100", "200", "500", "1000"],
    "target": ["中老年群体", "企业财务人员", "留学生", "网购用户"],
    "variant": ["信用贷诈骗", "投资理财诈骗", "虚拟货币诈骗"],
    "crypto": ["BTC/USDT", "ETH/USDT", "BTC/ETH"],
    "rate": ["1.5", "2", "2.5", "3", "5"],
    "hours": ["1", "2", "3", "6"],
    "contact": ["@crypto_wash_88", "@dark_trade_pro", "@phish_tool_admin", "@shuifang_hr", "@maochi_sale", "@ddos_pro_service"],
    "region2": ["东南亚", "中东", "欧洲", "北美"],
    "method": ["地下钱庄", "虚拟货币", "贸易对冲", "第三方支付"],
    "years": ["3", "5", "8"],
    "features": ["键盘记录+屏幕截图+凭证窃取", "远程桌面+文件管理+摄像头监控", "浏览器劫持+剪贴板监控+钱包窃取"],
    "platform_os": ["Windows/Mac", "Windows/Linux", "全平台"],
    "name": ["DarkLock", "NightCrypt", "ShadowVault", "CryptoStorm"],
    "encrypt": ["AES-256+RSA-4096", "ChaCha20+RSA-2048", "Salsa20+ECC"],
    "bandwidth": ["200", "300", "500", "800", "1000"],
    "cdn": ["Cloudflare", "Akamai", "AWS Shield"],
    "protocols": ["HTTP/HTTPS/TCP/UDP", "SYN/UDP/HTTP", "NTP/DNS/SSDP"],
    "ports": ["32", "64", "128"],
    "price_old": ["3500", "5000", "8000"],
    "price_new": ["2200", "3500", "5500"],
    "version": ["3.2", "4.0", "5.1"],
    "use_case": ["催收", "诈骗", "营销"],
    "templates": ["50", "100", "200"],
    "scale": ["中大型", "大型", "知名"],
    "role_ent": ["高管", "财务", "IT管理员"],
    "service": ["内网横向渗透", "域控提权", "数据窃取"],
    "industry": ["金融", "互联网", "制造", "能源"],
    "data_type": ["客户", "财务", "技术"],
    "source": ["社工库", "脱库数据", "内部泄露"],
    "product": ["Apache Tomcat", "Nginx", "Redis", "WebLogic", "Confluence", "Exchange"],
    "version_vuln": ["9.x", "10.x", "最新版"],
    "vuln_type": ["RCE", "提权", "认证绕过", "SSRF"],
    "effect": ["远程执行任意代码", "获取系统最高权限", "绕过认证直接登录"],
    "scope": ["全球", "亚太地区", "中国区"],
    "buyers": ["3", "5", "10"],
    "products": ["WebLogic/Confluence/Exchange", "Tomcat/Nginx/Apache", "Redis/MongoDB/MySQL"],
    "vuln_list": ["CVE-2024-xxxx/CVE-2024-yyyy/CVE-2025-zzzz", "CVE-2025-xxxx/CVE-2025-yyyy"],
    "tools": ["Nuclei/SQLMap/Xray", "AWVS/Burp/Goby"],
    "threat_type": ["诈骗", "钓鱼", "勒索", "洗钱", "数据窃取"],
    "commodity": ["数据", "工具", "漏洞", "账号"],
    "count2": ["200", "500", "1000"],
    "action": ["缴纳保证金", "转账验证", "充值解冻"],
}


class DataSourceConfig:
    def __init__(self, name: str, url: str, source_type: str, source_tag: str,
                 parser: str = "generic", poll_interval_minutes: int = 30,
                 headers: Dict = None, post_data: Dict = None,
                 enabled: bool = True):
        self.name = name
        self.url = url
        self.source_type = source_type
        self.source_tag = source_tag
        self.parser = parser
        self.poll_interval_minutes = poll_interval_minutes
        self.headers = headers or {}
        self.post_data = post_data
        self.enabled = enabled
        self.last_fetched: Optional[datetime] = None
        self.fetch_count = 0
        self.error_count = 0
        self.last_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "url": self.url,
            "source_type": self.source_type,
            "source_tag": self.source_tag,
            "parser": self.parser,
            "poll_interval_minutes": self.poll_interval_minutes,
            "enabled": self.enabled,
            "last_fetched": self.last_fetched.isoformat() if self.last_fetched else None,
            "fetch_count": self.fetch_count,
            "error_count": self.error_count,
        }


class SampleDataGenerator:
    def __init__(self, kg: KnowledgeGraph, blacktalk_engine=None):
        self.kg = kg
        self.blacktalk_engine = blacktalk_engine

    def _pick_threat_level(self) -> str:
        return random.choices(_THREAT_LEVELS, weights=_THREAT_LEVEL_WEIGHTS, k=1)[0]

    def _pick_source(self, preferred: Optional[List[str]] = None) -> str:
        if preferred:
            return random.choice(preferred)
        return random.choices(_SOURCE_TYPES, weights=_SOURCE_WEIGHTS, k=1)[0]

    def _fill_template(self, template: str) -> str:
        placeholders = re.findall(r'\{(\w+)\}', template)
        filled = template
        for ph in placeholders:
            if ph in _FILL_VALUES:
                filled = filled.replace(f"{{{ph}}}", random.choice(_FILL_VALUES[ph]), 1)
        remaining = re.findall(r'\{(\w+)\}', filled)
        for ph in remaining:
            filled = filled.replace(f"{{{ph}}}", str(random.randint(1, 999)), 1)
        return filled

    def generate_intelligence(self, count: int) -> list:
        results = []
        now = datetime.now(timezone.utc)
        selected = random.choices(_INTEL_TEMPLATES, k=count)

        for template in selected:
            tmpl = random.choice(template["templates"])
            content = self._fill_template(tmpl)
            source = self._pick_source(template.get("source_pool"))
            threat_level = template.get("threat_level", self._pick_threat_level())

            if random.random() < 0.3:
                threat_level = self._pick_threat_level()

            raw_content_variants = {
                "darkweb": f"[{random.choice(_FILL_VALUES['vendor_id'])}] {content[:80]} | 暗网交易 | 担保",
                "telegram": f"🚀 {content[:80]} | TG: {random.choice(_FILL_VALUES['contact'])}",
                "forum": f"【分享】{content[:80]} | 仅供研究",
                "wechat": f"{content[:80]} | wx: {random.choice(_FILL_VALUES['contact']).replace('@', '')}",
                "web": f"安全通告：{content[:80]}",
            }

            collected_at = now - timedelta(
                days=random.randint(0, 7),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
            )

            metadata = {
                "threat_level": threat_level,
                "category": template["category"],
                "language": "zh",
                "confidence": round(random.uniform(0.7, 0.95), 2),
                "auto_collected": True,
                "sample_data": True,
            }

            results.append({
                "id": uuid.uuid4().hex,
                "source": source,
                "source_url": "",
                "content": content,
                "raw_content": raw_content_variants.get(source, content[:100]),
                "collected_at": collected_at,
                "status": "raw",
                "metadata_json": json.dumps(metadata, ensure_ascii=False),
            })

        return results

    def generate_entities(self, count: int) -> list:
        results = []
        existing_values = set()
        for entity in self.kg._entities.values():
            existing_values.add(entity.value)

        for _ in range(count * 3):
            if len(results) >= count:
                break
            template = random.choice(_ENTITY_TEMPLATES)
            value = random.choice(template["values"])
            if value in existing_values:
                continue

            context_map = {
                EntityType.IP: f"模拟{template['type'].value}地址，疑似黑产相关",
                EntityType.DOMAIN: f"模拟{template['type'].value}，疑似钓鱼或恶意域名",
                EntityType.ACCOUNT: f"模拟{template['type'].value}，疑似黑产联络账号",
                EntityType.EMAIL: f"模拟{template['type'].value}，疑似黑产匿名邮箱",
                EntityType.PERSON: f"模拟{template['type'].value}，疑似黑产人员",
                EntityType.ORGANIZATION: f"模拟{template['type'].value}，疑似黑产组织",
                EntityType.TOOL: f"模拟{template['type'].value}，疑似黑产工具",
                EntityType.MALWARE: f"模拟{template['type'].value}，疑似恶意软件",
                EntityType.CRYPTO_WALLET: f"模拟{template['type'].value}，疑似黑产资金钱包",
                EntityType.SERVICE: f"模拟{template['type'].value}，疑似黑产服务",
                EntityType.BLACKTALK: f"模拟{template['type'].value}，黑话术语",
            }

            results.append({
                "id": uuid.uuid4().hex,
                "entity_type": template["type"],
                "value": value,
                "context": context_map.get(template["type"], "模拟采集实体"),
                "source_ids": [],
                "confidence": round(random.uniform(0.6, 0.95), 2),
            })
            existing_values.add(value)

        return results

    def generate_relations(self, count: int) -> list:
        results = []
        entity_ids = list(self.kg._entities.keys())
        if len(entity_ids) < 2:
            return results

        for _ in range(count * 3):
            if len(results) >= count:
                break
            source_id = random.choice(entity_ids)
            target_id = random.choice(entity_ids)
            if source_id == target_id:
                continue
            if self.kg.graph.has_edge(source_id, target_id):
                continue

            rel_template = random.choice(_RELATION_TEMPLATES)
            source_entity = self.kg._entities.get(source_id)
            target_entity = self.kg._entities.get(target_id)
            if not source_entity or not target_entity:
                continue

            evidence = rel_template["evidence_template"].format(
                source=source_entity.value,
                target=target_entity.value,
            )

            results.append({
                "id": uuid.uuid4().hex,
                "source_id": source_id,
                "target_id": target_id,
                "relation_type": rel_template["type"],
                "evidence": evidence,
                "confidence": round(random.uniform(0.5, 0.9), 2),
            })

        return results

    async def generate_blacktalk(self) -> int:
        count = 0
        if not self.blacktalk_engine:
            return 0

        try:
            existing_terms = set()
            for term in self.blacktalk_engine._dictionary.values():
                existing_terms.add(term.term)

            new_terms = random.sample(
                [t for t in _ENTITY_TEMPLATES if t["type"] == EntityType.BLACKTALK],
                1,
            )
            if new_terms:
                blacktalk_template = new_terms[0]
                candidates = [v for v in blacktalk_template["values"] if v not in existing_terms]
                selected = random.sample(candidates, min(random.randint(1, 3), len(candidates)))

                meaning_map = {
                    "开料": "开始使用被盗数据进行诈骗活动",
                    "黑吃黑": "黑产内部互相欺骗或抢夺资源",
                    "免杀": "绕过杀毒软件检测的技术或方法",
                    "暗桩": "隐藏的后门程序或潜伏的内部人员",
                    "炸群": "在群聊中大量发送诈骗信息或广告",
                    "换脸": "使用AI深度伪造技术替换视频中的人脸",
                    "克隆音": "使用AI技术克隆他人声音进行语音诈骗",
                    "羊毛党": "专门利用优惠活动漏洞非法获利的群体",
                    "料商": "专门贩卖个人信息的商人",
                    "车队": "专门负责资金转移和取现的团队",
                    "接单": "接受黑产任务或订单",
                    "交割": "完成黑产交易的交付环节",
                    "洗手": "退出黑产行业，不再参与违法活动",
                    "零日": "尚未被公开或修补的软件安全漏洞",
                    "渗透": "入侵目标系统或网络的过程",
                    "逆向": "对软件进行逆向工程分析",
                    "洗白": "将非法资金转为合法来源的过程",
                    "过桥": "通过中间账户转移资金以掩盖来源",
                    "码商": "提供收款二维码用于洗钱的人",
                    "通道": "用于资金转移的支付渠道",
                    "电诈": "电信诈骗，通过电话或网络实施诈骗",
                }

                category_map = {
                    "开料": "fraud", "黑吃黑": "general", "免杀": "hacking",
                    "暗桩": "hacking", "炸群": "fraud", "换脸": "fraud",
                    "克隆音": "fraud", "羊毛党": "fraud", "料商": "fraud",
                    "车队": "money_laundering", "接单": "general",
                    "交割": "general", "洗手": "general", "零日": "hacking",
                    "渗透": "hacking", "逆向": "hacking", "洗白": "money_laundering",
                    "过桥": "money_laundering", "码商": "money_laundering",
                    "通道": "money_laundering", "电诈": "fraud",
                }

                for term in selected:
                    try:
                        await self.blacktalk_engine.learn(
                            term=term,
                            meaning=meaning_map.get(term, f"黑产术语：{term}"),
                            context=f"模拟数据生成黑话术语'{term}'",
                            source="sample_data_generator",
                        )
                        count += 1
                    except Exception as e:
                        logger.debug(f"Blacktalk learn failed for '{term}': {e}")

        except Exception as e:
            logger.debug(f"Blacktalk generation skipped: {e}")

        return count

    def generate_pir(self) -> dict:
        template = random.choice(_PIR_TEMPLATES)
        title = self._fill_template(template["title"])
        description = self._fill_template(template["description"])
        priority = random.choice(template["priority_pool"])
        keywords = []
        for kw_pool in template["keywords_pool"]:
            keywords.extend(random.sample(kw_pool, min(2, len(kw_pool))))
        sources = random.sample(template["sources_pool"], min(3, len(template["sources_pool"])))
        now = datetime.now(timezone.utc)

        return {
            "id": uuid.uuid4().hex,
            "title": title,
            "description": description,
            "priority": priority,
            "status": "active",
            "keywords_json": json.dumps(keywords, ensure_ascii=False),
            "target_sources_json": json.dumps(sources, ensure_ascii=False),
            "created_at": now,
            "updated_at": now,
        }

    async def generate_sample_data(self, count: int = 5, db_session=None) -> dict:
        logger.info(f"Generating {count} sample data items")
        stats = {
            "intelligence": 0,
            "entities": 0,
            "relations": 0,
            "blacktalk": 0,
            "pir": 0,
            "errors": [],
        }

        try:
            intel_count = random.randint(2, max(2, count))
            intel_data = self.generate_intelligence(intel_count)
            if db_session is not None:
                for item in intel_data:
                    db_session.add(RawIntelligenceTable(**item))
                    stats["intelligence"] += 1
                await db_session.commit()
            else:
                from app.db.database import async_session_factory
                async with async_session_factory() as session:
                    for item in intel_data:
                        session.add(RawIntelligenceTable(**item))
                        stats["intelligence"] += 1
                    await session.commit()
        except Exception as e:
            logger.warning(f"Sample intelligence generation failed: {e}")
            stats["errors"].append(f"sample_intel: {str(e)[:100]}")

        try:
            entity_count = random.randint(2, max(2, count))
            entity_data = self.generate_entities(entity_count)
            for item in entity_data:
                entity = Entity(
                    id=item["id"],
                    type=item["entity_type"],
                    value=item["value"],
                    context=item.get("context"),
                    source_ids=item.get("source_ids", []),
                    confidence=item.get("confidence", 0.8),
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                )
                await self.kg.add_entity(entity)
                stats["entities"] += 1
        except Exception as e:
            logger.warning(f"Sample entity generation failed: {e}")
            stats["errors"].append(f"sample_entity: {str(e)[:100]}")

        try:
            relation_count = random.randint(3, max(3, count))
            relation_data = self.generate_relations(relation_count)
            for item in relation_data:
                relation = Relation(
                    id=item["id"],
                    source_entity_id=item["source_id"],
                    target_entity_id=item["target_id"],
                    type=item["relation_type"],
                    confidence=item.get("confidence", 0.7),
                    evidence=item.get("evidence"),
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                )
                await self.kg.add_relation(relation)
                stats["relations"] += 1
        except Exception as e:
            logger.warning(f"Sample relation generation failed: {e}")
            stats["errors"].append(f"sample_relation: {str(e)[:100]}")

        try:
            await self.kg.save()
        except Exception as e:
            stats["errors"].append(f"kg_save: {str(e)[:100]}")

        try:
            bt_count = await self.generate_blacktalk()
            stats["blacktalk"] = bt_count
        except Exception as e:
            logger.warning(f"Sample blacktalk generation failed: {e}")
            stats["errors"].append(f"blacktalk: {str(e)[:100]}")

        try:
            if random.random() < 0.3:
                pir_data = self.generate_pir()
                if db_session is not None:
                    db_session.add(PIRTable(**pir_data))
                    await db_session.commit()
                else:
                    from app.db.database import async_session_factory
                    async with async_session_factory() as session:
                        session.add(PIRTable(**pir_data))
                        await session.commit()
                stats["pir"] = 1
        except Exception as e:
            logger.warning(f"Sample PIR generation failed: {e}")
            stats["errors"].append(f"pir: {str(e)[:100]}")

        logger.info(
            f"SampleDataGenerator completed: intel={stats['intelligence']}, "
            f"entities={stats['entities']}, relations={stats['relations']}, "
            f"blacktalk={stats['blacktalk']}, pir={stats['pir']}"
        )
        return stats


class AutoCollector:
    def __init__(self, kg: KnowledgeGraph, blacktalk_engine=None, llm_service=None,
                 data_classification=None, data_minimizer=None, pii_detector=None,
                 provenance_chain=None, message_queue=None, worker_pool=None):
        self.kg = kg
        self.blacktalk_engine = blacktalk_engine
        self._llm = llm_service
        self.data_classification = data_classification
        self.data_minimizer = data_minimizer
        self.pii_detector = pii_detector
        self.provenance_chain = provenance_chain
        self.message_queue = message_queue
        self.worker_pool = worker_pool
        self._running = False
        self._timer = None
        self._interval_minutes = 30
        self._collection_count = 0
        self._last_collection_at: Optional[datetime] = None
        self._lock = threading.Lock()
        self._http_session = None
        self._sources: List[DataSourceConfig] = []
        self._init_default_sources()

    def _init_default_sources(self):
        for src in _DEFAULT_RSS_SOURCES:
            self._sources.append(DataSourceConfig(
                name=src["name"],
                url=src["url"],
                source_type=src["type"],
                source_tag=src["source_tag"],
                parser=src.get("parser", "generic"),
                poll_interval_minutes=src.get("poll_interval_minutes", 30),
                post_data=src.get("post_data"),
            ))
        for src in _DEFAULT_RSS_FEEDS:
            self._sources.append(DataSourceConfig(
                name=src["name"],
                url=src["url"],
                source_type=src["type"],
                source_tag=src["source_tag"],
                poll_interval_minutes=src.get("poll_interval_minutes", 60),
            ))

    def add_source(self, source: DataSourceConfig):
        self._sources.append(source)
        logger.info(f"Added data source: {source.name} ({source.url})")

    def remove_source(self, name: str) -> bool:
        before = len(self._sources)
        self._sources = [s for s in self._sources if s.name != name]
        return len(self._sources) < before

    def list_sources(self) -> list[dict]:
        return [s.to_dict() for s in self._sources]

    def _get_http_session(self):
        if self._http_session is None or self._http_session.closed:
            try:
                import aiohttp
                self._http_session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=30),
                    headers={"User-Agent": "ThreatIntelBot/1.0"},
                )
            except ImportError:
                logger.warning("aiohttp not installed, HTTP fetching disabled")
                return None
        return self._http_session

    def _get_llm(self):
        if self._llm is None:
            try:
                from app.core.llm import LLMService
                self._llm = LLMService()
            except Exception as e:
                logger.warning(f"LLM service not available: {e}")
        return self._llm

    async def collect_once(self) -> dict:
        stats = {
            "intelligence": 0,
            "entities": 0,
            "relations": 0,
            "blacktalk": 0,
            "pir": 0,
            "errors": [],
            "sources_fetched": 0,
            "sources_failed": 0,
        }

        tracer = get_tracer("auto_collector")
        with tracer.start_as_current_span("auto_collector.collect_once") as span:
            fetch_stats = await self._fetch_from_sources()
            stats["intelligence"] += fetch_stats["collected"]
            stats["sources_fetched"] = fetch_stats["fetched"]
            stats["sources_failed"] = fetch_stats["failed"]
            stats["errors"].extend(fetch_stats.get("errors", []))

            if fetch_stats["collected"] > 0:
                await self._apply_data_governance(fetch_stats.get("items", []))

            entity_data = await self._extract_entities_from_recent_intel()
            if entity_data:
                for item in entity_data:
                    try:
                        entity = Entity(
                            id=item["id"],
                            type=item["entity_type"],
                            value=item["value"],
                            context=item.get("context"),
                            source_ids=item.get("source_ids", []),
                            confidence=item.get("confidence", 0.8),
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc),
                        )
                        await self.kg.add_entity(entity)
                        stats["entities"] += 1
                    except Exception as e:
                        logger.debug(f"Entity add failed: {e}")

                try:
                    relation_data = self._build_relations_from_entities(min(3, len(entity_data)))
                    for item in relation_data:
                        relation = Relation(
                            id=item["id"],
                            source_entity_id=item["source_id"],
                            target_entity_id=item["target_id"],
                            type=item["relation_type"],
                            confidence=item.get("confidence", 0.7),
                            evidence=item.get("evidence"),
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc),
                        )
                        await self.kg.add_relation(relation)
                        stats["relations"] += 1
                except Exception as e:
                    logger.debug(f"Relation build failed: {e}")

                try:
                    await self.kg.save()
                except Exception as e:
                    stats["errors"].append(f"kg_save: {str(e)[:100]}")

            with self._lock:
                self._collection_count += 1
                self._last_collection_at = datetime.now(timezone.utc)

            span.set_attribute("intelligence_count", stats["intelligence"])
            span.set_attribute("entities_count", stats["entities"])
            span.set_attribute("relations_count", stats["relations"])
            span.set_attribute("sources_fetched", stats["sources_fetched"])
            span.set_attribute("sources_failed", stats["sources_failed"])

        logger.info(
            f"AutoCollection completed: intel={stats['intelligence']}, "
            f"entities={stats['entities']}, relations={stats['relations']}, "
            f"sources_fetched={stats['sources_fetched']}, sources_failed={stats['sources_failed']}"
        )
        return stats

    async def _apply_data_governance(self, items: list):
        for item in items:
            content = item.get("content", "")
            if self.data_classification:
                try:
                    cls_result = self.data_classification.classify(content, item.get("metadata"))
                    item["classification_level"] = cls_result.level.value
                except Exception as exc:
                    logger.warning(f"AutoCollector data classification failed: {exc}")
            if self.pii_detector:
                try:
                    pii_matches = self.pii_detector.detect_pii(content)
                    if pii_matches:
                        item["pii_detected"] = True
                        item["pii_types"] = list({m.pii_type.value for m in pii_matches})
                        if self.data_minimizer and item.get("classification_level") == ClassificationLevel.RESTRICTED.value:
                            item["content"] = self.data_minimizer.minimize_pii(
                                content, ClassificationLevel.RESTRICTED
                            )
                except Exception as exc:
                    logger.warning(f"AutoCollector PII detection failed: {exc}")
            if self.provenance_chain:
                try:
                    await self.provenance_chain.record_provenance(
                        intelligence_id=item.get("id", uuid.uuid4().hex),
                        stage="collected",
                        input_data={"source": item.get("source", "unknown"), "source_url": item.get("source_url", "")},
                        output_data={"content": (item.get("content", "") or "")[:500]},
                    )
                except Exception as exc:
                    logger.warning(f"AutoCollector provenance chain record failed: {exc}")
        if self.message_queue and items:
            try:
                await self.message_queue.publish(
                    TOPIC_INTELLIGENCE_COLLECTED,
                    {"items": items, "count": len(items)},
                )
            except Exception as exc:
                logger.warning(f"AutoCollector message queue publish failed: {exc}")

    async def _fetch_from_sources(self) -> dict:
        stats = {"collected": 0, "fetched": 0, "failed": 0, "errors": [], "items": []}
        session = self._get_http_session()
        if session is None:
            return stats

        eligible_sources = []
        for source in self._sources:
            if not source.enabled:
                continue
            if source.last_fetched:
                elapsed = (datetime.now(timezone.utc) - source.last_fetched).total_seconds() / 60
                if elapsed < source.poll_interval_minutes:
                    continue
            eligible_sources.append(source)

        if self.worker_pool and eligible_sources:
            stats = await self._fetch_with_worker_pool(session, eligible_sources, stats)
        else:
            stats = await self._fetch_serial(session, eligible_sources, stats)

        return stats

    async def _fetch_serial(self, session, sources: list, stats: dict, db_session=None) -> dict:
        for source in sources:
            try:
                items = await self._fetch_source(session, source)
                if items:
                    if db_session is not None:
                        for item in items:
                            try:
                                db_session.add(RawIntelligenceTable(**item))
                                stats["collected"] += 1
                                stats["items"].append(item)
                            except Exception as e:
                                logger.debug(f"Failed to store item from {source.name}: {e}")
                        await db_session.commit()
                    else:
                        from app.db.database import async_session_factory
                        async with async_session_factory() as sess:
                            for item in items:
                                try:
                                    sess.add(RawIntelligenceTable(**item))
                                    stats["collected"] += 1
                                    stats["items"].append(item)
                                except Exception as e:
                                    logger.debug(f"Failed to store item from {source.name}: {e}")
                            await sess.commit()

                source.last_fetched = datetime.now(timezone.utc)
                source.fetch_count += 1
                stats["fetched"] += 1
                logger.info(f"Fetched {len(items)} items from {source.name}")
            except Exception as e:
                source.error_count += 1
                source.last_error = str(e)[:200]
                stats["failed"] += 1
                stats["errors"].append(f"{source.name}: {str(e)[:100]}")
                logger.warning(f"Failed to fetch from {source.name}: {e}")
        return stats

    async def _fetch_with_worker_pool(self, session, sources: list, stats: dict) -> dict:
        from app.core.worker_pool import CollectionWorkerPool

        pool = self.worker_pool
        if not isinstance(pool, CollectionWorkerPool):
            return await self._fetch_serial(session, sources, stats)

        if not pool._running:
            await pool.start()

        futures = []
        for source in sources:
            future = await pool.submit_collection(
                self._fetch_and_store_source, source.name, session, source
            )
            futures.append((source, future))

        for source, future in futures:
            try:
                result = await future
                if result:
                    stats["collected"] += result.get("collected", 0)
                    stats["fetched"] += result.get("fetched", 0)
                    stats["failed"] += result.get("failed", 0)
                    stats["errors"].extend(result.get("errors", []))
                    stats["items"].extend(result.get("items", []))
            except Exception as e:
                source.error_count += 1
                source.last_error = str(e)[:200]
                stats["failed"] += 1
                stats["errors"].append(f"{source.name}: {str(e)[:100]}")
                logger.warning(f"Worker pool fetch failed for {source.name}: {e}")

        return stats

    async def _fetch_and_store_source(self, session, source: DataSourceConfig, db_session=None) -> dict:
        result = {"collected": 0, "fetched": 0, "failed": 0, "errors": [], "items": []}
        try:
            items = await self._fetch_source(session, source)
            if items:
                if db_session is not None:
                    for item in items:
                        try:
                            db_session.add(RawIntelligenceTable(**item))
                            result["collected"] += 1
                            result["items"].append(item)
                        except Exception as e:
                            logger.debug(f"Failed to store item from {source.name}: {e}")
                    await db_session.commit()
                else:
                    from app.db.database import async_session_factory
                    async with async_session_factory() as sess:
                        for item in items:
                            try:
                                sess.add(RawIntelligenceTable(**item))
                                result["collected"] += 1
                                result["items"].append(item)
                            except Exception as e:
                                logger.debug(f"Failed to store item from {source.name}: {e}")
                        await sess.commit()

                if self.message_queue:
                    try:
                        from app.core.message_queue import TOPIC_INTELLIGENCE_COLLECTED
                        await self.message_queue.publish(TOPIC_INTELLIGENCE_COLLECTED, {
                            "collector": source.name,
                            "count": len(items),
                            "source_tag": source.source_tag,
                        })
                    except Exception as exc:
                        logger.error(f"Failed to publish collection result for {source.name}: {exc}")

            source.last_fetched = datetime.now(timezone.utc)
            source.fetch_count += 1
            result["fetched"] = 1
            logger.info(f"Fetched {len(items)} items from {source.name}")
        except Exception as e:
            source.error_count += 1
            source.last_error = str(e)[:200]
            result["failed"] = 1
            result["errors"].append(f"{source.name}: {str(e)[:100]}")
            logger.warning(f"Failed to fetch from {source.name}: {e}")
        return result

    async def _fetch_source(self, session, source: DataSourceConfig) -> list[dict]:
        items = []

        if source.source_type == "json_api":
            async with session.get(source.url, headers=source.headers) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                data = await resp.json(content_type=None)
                items = self._parse_json_api(data, source)

        elif source.source_type == "json_api_post":
            async with session.post(source.url, data=source.post_data, headers=source.headers) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                data = await resp.json(content_type=None)
                items = self._parse_json_api(data, source)

        elif source.source_type == "rss":
            async with session.get(source.url, headers=source.headers) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                text = await resp.text()
                items = self._parse_rss(text, source)

        elif source.source_type == "html":
            async with session.get(source.url, headers=source.headers) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                text = await resp.text()
                items = self._parse_html(text, source)

        return items

    def _parse_json_api(self, data: dict, source: DataSourceConfig) -> list[dict]:
        results = []
        now = datetime.now(timezone.utc)

        if source.parser == "cisa_kev":
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities[:20]:
                cve_id = vuln.get("cveID", "")
                product = vuln.get("product", "")
                description = vuln.get("shortDescription", "")
                content = f"CISA KEV: {cve_id} - {product}. {description}"
                metadata = {
                    "threat_level": "high",
                    "category": "vulnerability",
                    "language": "en",
                    "confidence": 0.95,
                    "source_name": source.name,
                    "cve_id": cve_id,
                }
                results.append({
                    "id": uuid.uuid4().hex,
                    "source": source.source_tag,
                    "source_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "content": content,
                    "raw_content": json.dumps(vuln, ensure_ascii=False)[:500],
                    "collected_at": now,
                    "status": "raw",
                    "metadata_json": json.dumps(metadata, ensure_ascii=False),
                })

        elif source.parser == "urlhaus":
            urls = data.get("urls", [])
            for entry in urls[:20]:
                url_value = entry.get("url", "")
                threat = entry.get("threat", "")
                tags = ", ".join(entry.get("tags", []))
                content = f"URLhaus恶意URL: {url_value} 威胁类型: {threat} 标签: {tags}"
                metadata = {
                    "threat_level": "high",
                    "category": "malicious_url",
                    "language": "en",
                    "confidence": 0.9,
                    "source_name": source.name,
                    "urlhaus_threat": threat,
                }
                results.append({
                    "id": uuid.uuid4().hex,
                    "source": source.source_tag,
                    "source_url": url_value,
                    "content": content,
                    "raw_content": json.dumps(entry, ensure_ascii=False)[:500],
                    "collected_at": now,
                    "status": "raw",
                    "metadata_json": json.dumps(metadata, ensure_ascii=False),
                })

        elif source.parser == "malware_bazaar":
            samples = data.get("data", [])
            for sample in samples[:20]:
                sha256 = sample.get("sha256_hash", "")
                malware_name = sample.get("signature", "")
                file_type = sample.get("file_type", "")
                content = f"MalwareBazaar样本: {malware_name} SHA256: {sha256} 类型: {file_type}"
                metadata = {
                    "threat_level": "high",
                    "category": "malware_sample",
                    "language": "en",
                    "confidence": 0.9,
                    "source_name": source.name,
                    "sha256": sha256,
                    "malware_family": malware_name,
                }
                results.append({
                    "id": uuid.uuid4().hex,
                    "source": source.source_tag,
                    "source_url": f"https://bazaar.abuse.ch/sample/{sha256}/",
                    "content": content,
                    "raw_content": json.dumps(sample, ensure_ascii=False)[:500],
                    "collected_at": now,
                    "status": "raw",
                    "metadata_json": json.dumps(metadata, ensure_ascii=False),
                })

        else:
            if isinstance(data, list):
                for item in data[:20]:
                    content = json.dumps(item, ensure_ascii=False)[:500]
                    metadata = {
                        "threat_level": "medium",
                        "category": "generic",
                        "confidence": 0.5,
                        "source_name": source.name,
                    }
                    results.append({
                        "id": uuid.uuid4().hex,
                        "source": source.source_tag,
                        "source_url": source.url,
                        "content": content,
                        "raw_content": content[:200],
                        "collected_at": now,
                        "status": "raw",
                        "metadata_json": json.dumps(metadata, ensure_ascii=False),
                    })

        return results

    def _parse_rss(self, text: str, source: DataSourceConfig) -> list[dict]:
        results = []
        now = datetime.now(timezone.utc)

        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(text)
            channel = root.find("channel")
            if channel is None:
                return results

            for item in channel.findall("item")[:15]:
                title = item.findtext("title", "")
                link = item.findtext("link", "")
                description = item.findtext("description", "")
                pub_date = item.findtext("pubDate", "")

                content = f"{title}"
                if description:
                    clean_desc = re.sub(r'<[^>]+>', '', description)
                    content += f"\n{clean_desc[:500]}"

                if not content.strip():
                    continue

                metadata = {
                    "threat_level": "medium",
                    "category": "security_news",
                    "language": "en",
                    "confidence": 0.7,
                    "source_name": source.name,
                    "original_link": link,
                    "pub_date": pub_date,
                }
                results.append({
                    "id": uuid.uuid4().hex,
                    "source": source.source_tag,
                    "source_url": link or source.url,
                    "content": content[:1000],
                    "raw_content": content[:200],
                    "collected_at": now,
                    "status": "raw",
                    "metadata_json": json.dumps(metadata, ensure_ascii=False),
                })
        except Exception as e:
            logger.warning(f"RSS parse failed for {source.name}: {e}")

        return results

    def _parse_html(self, text: str, source: DataSourceConfig) -> list[dict]:
        results = []
        now = datetime.now(timezone.utc)

        clean = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
        clean = re.sub(r'<style[^>]*>.*?</style>', '', clean, flags=re.DOTALL)
        clean = re.sub(r'<[^>]+>', ' ', clean)
        clean = re.sub(r'\s+', ' ', clean).strip()

        paragraphs = re.split(r'[。！？\.\!\?]', clean)
        for para in paragraphs[:10]:
            para = para.strip()
            if len(para) < 20:
                continue
            metadata = {
                "threat_level": "medium",
                "category": "web_scrape",
                "confidence": 0.4,
                "source_name": source.name,
            }
            results.append({
                "id": uuid.uuid4().hex,
                "source": source.source_tag,
                "source_url": source.url,
                "content": para[:500],
                "raw_content": para[:200],
                "collected_at": now,
                "status": "raw",
                "metadata_json": json.dumps(metadata, ensure_ascii=False),
            })

        return results

    async def _extract_entities_from_recent_intel(self, db_session=None) -> list[dict]:
        results = []
        try:
            from app.core.rule_based_extractor import rule_extractor

            if db_session is not None:
                from sqlalchemy import select
                from app.db.tables import RawIntelligenceTable

                stmt = select(RawIntelligenceTable).order_by(
                    RawIntelligenceTable.collected_at.desc()
                ).limit(20)
                db_result = await db_session.execute(stmt)
                rows = db_result.scalars().all()
            else:
                from app.db.database import async_session_factory
                async with async_session_factory() as session:
                    from sqlalchemy import select
                    from app.db.tables import RawIntelligenceTable

                    stmt = select(RawIntelligenceTable).order_by(
                        RawIntelligenceTable.collected_at.desc()
                    ).limit(20)
                    db_result = await session.execute(stmt)
                    rows = db_result.scalars().all()

            seen_values = set()
            for entity in self.kg._entities.values():
                seen_values.add(entity.value)

            for row in rows:
                if not row.content:
                    continue
                extracted = rule_extractor.extract(row.content)
                for ent in extracted[:5]:
                    val = ent.get("value", "")
                    if val and val not in seen_values and len(val) > 2:
                        results.append({
                            "id": uuid.uuid4().hex,
                            "entity_type": ent.get("type", "unknown"),
                            "value": val,
                            "context": ent.get("context", f"从情报{row.id[:8]}中提取"),
                            "source_ids": [row.id],
                            "confidence": ent.get("confidence", 0.7),
                        })
                        seen_values.add(val)
                        if len(results) >= 10:
                            break
                if len(results) >= 10:
                    break
        except Exception as e:
            logger.debug(f"Entity extraction from recent intel failed: {e}")

        return results

    def _build_relations_from_entities(self, count: int) -> list[dict]:
        results = []
        entity_ids = list(self.kg._entities.keys())
        if len(entity_ids) < 2:
            return results

        for _ in range(count * 3):
            if len(results) >= count:
                break
            source_id = random.choice(entity_ids)
            target_id = random.choice(entity_ids)
            if source_id == target_id:
                continue
            if self.kg.graph.has_edge(source_id, target_id):
                continue

            source_entity = self.kg._entities.get(source_id)
            target_entity = self.kg._entities.get(target_id)
            if not source_entity or not target_entity:
                continue

            rel_type = random.choice(list(RelationType))
            evidence = f"基于情报关联分析：{source_entity.value}与{target_entity.value}存在关联"

            results.append({
                "id": uuid.uuid4().hex,
                "source_id": source_id,
                "target_id": target_id,
                "relation_type": rel_type,
                "evidence": evidence,
                "confidence": round(random.uniform(0.5, 0.9), 2),
            })

        return results

    def start_auto_collection(self, interval_minutes: int = 30):
        if self._running:
            logger.warning("Auto collection is already running")
            return
        self._interval_minutes = interval_minutes
        self._running = True
        logger.info(f"Starting auto collection with interval {interval_minutes} minutes")

        def _run_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                while self._running:
                    try:
                        loop.run_until_complete(self.collect_once())
                    except Exception as e:
                        logger.error(f"Auto collection cycle failed: {e}")
                    if not self._running:
                        break
                    interval_sec = self._interval_minutes * 60
                    for _ in range(interval_sec):
                        if not self._running:
                            break
                        loop.run_until_complete(asyncio.sleep(1))
            finally:
                if self._http_session and not self._http_session.closed:
                    try:
                        loop.run_until_complete(self._http_session.close())
                    except Exception:
                        pass
                    self._http_session = None
                loop.close()
                logger.info("Auto collection loop exited")

        self._timer = threading.Thread(target=_run_loop, daemon=True, name="auto_collector")
        self._timer.start()

    def stop_auto_collection(self):
        if not self._running:
            logger.warning("Auto collection is not running")
            return
        self._running = False
        if self._timer and self._timer.is_alive():
            self._timer.join(timeout=10)
        self._timer = None
        if self._http_session and not self._http_session.closed:
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self._http_session.close())
                loop.close()
            except Exception:
                pass
            self._http_session = None
        logger.info("Auto collection stopped")

    async def close(self):
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
            self._http_session = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def status(self) -> dict:
        return {
            "running": self._running,
            "interval_minutes": self._interval_minutes,
            "collection_count": self._collection_count,
            "last_collection_at": self._last_collection_at.isoformat() if self._last_collection_at else None,
            "sources": [s.to_dict() for s in self._sources],
        }
