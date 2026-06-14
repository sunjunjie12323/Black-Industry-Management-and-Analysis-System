import json

from app.config import settings

DEFAULT_THREAT_KEYWORDS = {
    "跑分": ("TOOL", "跑分平台/洗钱通道"),
    "洗钱": ("SERVICE", "资金清洗服务"),
    "四件套": ("TOOL", "身份证+银行卡+手机卡+U盾"),
    "猫池": ("TOOL", "批量收发短信设备"),
    "杀猪盘": ("SERVICE", "长期感情诈骗"),
    "接码": ("SERVICE", "接收验证码服务"),
    "养号": ("SERVICE", "培育账号提高权重"),
    "料子": ("BLACKTALK", "被盗取的个人信息"),
    "黑料": ("BLACKTALK", "违法数据/隐私信息"),
    "卡商": ("PERSON", "银行卡贩卖者"),
    "料商": ("PERSON", "数据贩卖者"),
    "水房": ("SERVICE", "洗钱环节/资金清洗团队"),
    "车手": ("PERSON", "取款人/ATM取现执行者"),
    "马仔": ("PERSON", "底层执行者"),
    "木马": ("MALWARE", "恶意程序"),
    "钓鱼": ("SERVICE", "钓鱼攻击"),
    "勒索": ("SERVICE", "勒索软件/勒索行为"),
    "DDoS": ("TOOL", "分布式拒绝服务攻击工具"),
    "肉鸡": ("TOOL", "被控制的僵尸主机"),
    "僵尸网络": ("TOOL", "受控主机网络"),
    "暗网": ("SERVICE", "暗网市场/服务"),
    "挖矿": ("MALWARE", "加密货币挖矿木马"),
    "诈骗": ("SERVICE", "诈骗活动"),
    "博彩": ("SERVICE", "网络赌博"),
    "菠菜": ("SERVICE", "网络赌博(谐音)"),
    "色流": ("SERVICE", "色情引流"),
    "引流": ("SERVICE", "为黑产输送用户"),
    "提现": ("SERVICE", "非法提现/资金转移"),
    "套现": ("SERVICE", "非法套现"),
    "代付": ("SERVICE", "代为支付"),
    "黑卡": ("TOOL", "非法银行卡/信用卡"),
    "拦截卡": ("TOOL", "可拦截验证码的手机卡"),
    "实名": ("BLACKTALK", "实名认证相关信息"),
    "话术": ("TOOL", "诈骗话术模板"),
    "资金盘": ("SERVICE", "庞氏骗局/资金盘"),
    "套路贷": ("SERVICE", "欺诈性贷款"),
    "裸贷": ("SERVICE", "以裸照抵押的借贷"),
    "免杀": ("TOOL", "绕过杀毒软件检测技术"),
    "撞库": ("TOOL", "批量尝试登录工具"),
    "社工库": ("TOOL", "社会工程学数据库"),
    "群控": ("TOOL", "批量控制设备系统"),
    "改机": ("TOOL", "修改设备信息工具"),
}


def get_threat_keywords():
    if settings.THREAT_KEYWORDS_JSON:
        try:
            return json.loads(settings.THREAT_KEYWORDS_JSON)
        except (json.JSONDecodeError, ValueError):
            pass
    return DEFAULT_THREAT_KEYWORDS
