import re
from typing import Dict, List, Optional

from loguru import logger

from app.core.seed_data import load_known_orgs


_CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
_IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_DOMAIN_PATTERN = re.compile(
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
)
_URL_PATTERN = re.compile(r'https?://[^\s<>"\'\)\]]+', re.IGNORECASE)
_EMAIL_PATTERN = re.compile(
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
)
_MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
_SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
_BTC_ADDRESS_PATTERN = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
_VENDOR_PRODUCT_PATTERN = re.compile(
    r'\b([A-Za-z][A-Za-z0-9_.\-]{1,30})\s*[:：]\s*([A-Za-z][A-Za-z0-9_.\-]{1,30})\b'
)
_MITRE_ATTACK_PATTERN = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')


_EXCLUDE_DOMAIN_TLDS = {
    "the", "a", "an", "of", "to", "in", "on", "for", "and", "or", "is", "are",
    "was", "were", "be", "been", "being", "have", "has", "had", "do", "does",
    "did", "will", "would", "should", "could", "may", "might", "must", "can",
    "this", "that", "these", "those", "with", "from", "by", "at", "as", "it",
    "its", "we", "you", "they", "he", "she", "i", "me", "my", "our", "your",
    "their", "his", "her",
}

_EXCLUDE_VENDOR_PRODUCT_PREFIXES = {
    "url", "http", "https", "ftp", "ssh", "telnet", "mailto", "file",
    "contact", "email", "phone", "tel", "mobile", "wechat", "qq", "tg",
    "username", "password", "user", "pass", "login", "token", "api",
    "id", "name", "title", "type", "value", "key", "secret", "hash",
    "size", "length", "width", "height", "depth", "color", "price",
    "date", "time", "year", "month", "day", "week", "hour", "minute",
    "page", "site", "host", "port", "path", "dir", "folder", "file",
    "src", "dst", "src_ip", "dst_ip", "source", "target", "victim",
    "attacker", "actor", "group", "team", "org", "company", "vendor",
    "note", "notes", "comment", "comments", "desc", "description",
    "version", "release", "build", "patch", "fix", "bug", "issue",
    "ref", "reference", "see", "also", "note", "warning", "caution",
    "https", "http",
}

_KNOWN_VENDOR_PREFIXES = {
    "Microsoft", "Apple", "Google", "Oracle", "IBM", "Cisco", "Adobe",
    "Intel", "AMD", "NVIDIA", "Dell", "HP", "Lenovo", "Samsung",
    "Huawei", "Lenovo", "Siemens", "SAP", "VMware", "Red Hat", "SUSE",
    "Canonical", "Ubuntu", "Debian", "Fedora", "Mozilla", "Apache",
    "Atlassian", "GitLab", "GitHub", "Jenkins", "Docker", "Kubernetes",
    "WordPress", "Drupal", "Joomla", "Magento", "Shopify", "Salesforce",
    "ServiceNow", "Workday", "Zoom", "Slack", "Teams", "Dropbox",
    "Fortinet", "Palo Alto", "Check Point", "Symantec", "McAfee",
    "Trend Micro", "Sophos", "Kaspersky", "Avast", "Bitdefender",
    "CrowdStrike", "SentinelOne", "Carbon Black", "FireEye", "Mandiant",
    "Ivanti", "Pulse Secure", "F5", "Citrix", "VMware", "Juniper",
    "Aruba", "SonicWall", "WatchGuard", "Barracuda", "Proofpoint",
    "Mimecast", "KnowBe4", "Rapid7", "Qualys", "Tenable", "Nessus",
    "ConnectWise", "Kaseya", "Datto", "NinjaRMM", "Auvik",
    "JetBrains", "Atlassian", "GitLab", "GitHub", "Bitbucket",
    "D-Link", "TP-Link", "Netgear", "Asus", "Linksys", "Belkin",
    "Logitech", "Razer", "Corsair", "Kingston", "Crucial", "Seagate",
    "Western Digital", "SanDisk", "Toshiba", "Hitachi", "Fujitsu",
    "OpenSSH", "OpenSSL", "LibreOffice", "OpenOffice", "Thunderbird",
    "Firefox", "Chrome", "Edge", "Safari", "Opera", "Brave",
    "TensorFlow", "PyTorch", "Keras", "Scikit", "Pandas", "NumPy",
    "NVIDIA", "Qualcomm", "MediaTek", "Broadcom", "Texas Instruments",
    "STMicroelectronics", "Microchip", "NXP", "Renesas", "Infineon",
    "Apple", "Google", "Meta", "Amazon", "Netflix", "Twitter", "X",
    "PayPal", "Stripe", "Square", "Shopify", "eBay", "Etsy",
    "Uber", "Lyft", "Airbnb", "Booking", "Expedia", "TripAdvisor",
    "OpenAI", "Anthropic", "Hugging Face", "Cohere", "Mistral",
}


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part or not part.isdigit():
            return False
        n = int(part)
        if n < 0 or n > 255:
            return False
    return True


def _is_valid_domain(value: str) -> bool:
    if not value or len(value) < 4 or len(value) > 253:
        return False
    if "://" in value:
        return False
    if value.startswith(".") or value.endswith("."):
        return False
    if " " in value:
        return False
    last_dot = value.rfind(".")
    if last_dot == -1:
        return False
    tld = value[last_dot + 1:].lower()
    if not tld or tld in _EXCLUDE_DOMAIN_TLDS:
        return False
    return True


def _is_valid_btc_address(value: str) -> bool:
    return _BTC_ADDRESS_PATTERN.fullmatch(value) is not None


class RuleBasedEntityExtractor:
    def __init__(self, known_orgs: Optional[set] = None):
        self._known_orgs: set = known_orgs if known_orgs is not None else load_known_orgs()
        if not self._known_orgs:
            self._known_orgs = set()

    def extract(self, text: str) -> Dict[str, List[str]]:
        if not text:
            return {}

        results: Dict[str, List[str]] = {}
        seen_per_type: Dict[str, set] = {}

        def _add(entity_type: str, value: str) -> None:
            if not value:
                return
            value = value.strip()
            if not value:
                return
            if entity_type not in seen_per_type:
                seen_per_type[entity_type] = set()
            if value in seen_per_type[entity_type]:
                return
            seen_per_type[entity_type].add(value)
            results.setdefault(entity_type, []).append(value)

        for m in _CVE_PATTERN.finditer(text):
            _add("cve_id", m.group().upper())

        for m in _IPV4_PATTERN.finditer(text):
            ip = m.group()
            if _is_valid_ipv4(ip):
                _add("ip_address", ip)

        for m in _URL_PATTERN.finditer(text):
            url = m.group().rstrip(".,;:!?)")
            _add("url", url)

        for m in _EMAIL_PATTERN.finditer(text):
            _add("email", m.group().lower())

        for m in _MD5_PATTERN.finditer(text):
            _add("hash_md5", m.group().lower())

        for m in _SHA1_PATTERN.finditer(text):
            val = m.group().lower()
            if val not in seen_per_type.get("hash_md5", set()):
                _add("hash_sha1", val)

        for m in _SHA256_PATTERN.finditer(text):
            val = m.group().lower()
            if val not in seen_per_type.get("hash_md5", set()) and val not in seen_per_type.get("hash_sha1", set()):
                _add("hash_sha256", val)

        for m in _BTC_ADDRESS_PATTERN.finditer(text):
            val = m.group()
            if _is_valid_btc_address(val):
                if not _is_valid_ipv4(val):
                    _add("bitcoin_address", val)

        for m in _VENDOR_PRODUCT_PATTERN.finditer(text):
            vendor = m.group(1)
            product = m.group(2)
            vendor_lower = vendor.lower()
            product_lower = product.lower()
            if vendor_lower in _EXCLUDE_DOMAIN_TLDS or product_lower in _EXCLUDE_DOMAIN_TLDS:
                continue
            if vendor_lower in _EXCLUDE_VENDOR_PRODUCT_PREFIXES or product_lower in _EXCLUDE_VENDOR_PRODUCT_PREFIXES:
                continue
            if not (vendor[0].isupper() or vendor in _KNOWN_VENDOR_PREFIXES):
                continue
            if len(vendor) < 2 or len(product) < 2:
                continue
            _add("vendor_product", f"{vendor}:{product}")

        for m in _MITRE_ATTACK_PATTERN.finditer(text):
            _add("mitre_attack_id", m.group().upper())

        for m in _DOMAIN_PATTERN.finditer(text):
            val = m.group().lower().rstrip(".,;:!?)")
            if _is_valid_domain(val) and not val.startswith(("http://", "https://")):
                tld = val.rsplit(".", 1)[-1]
                if tld.lower() not in _EXCLUDE_DOMAIN_TLDS and len(tld) >= 2:
                    if not re.match(r'^\d+$', tld):
                        if val not in seen_per_type.get("url", set()):
                            _add("domain", val)

        if self._known_orgs:
            text_lower = text.lower()
            sorted_orgs = sorted(self._known_orgs, key=len, reverse=True)
            for org in sorted_orgs:
                if not org:
                    continue
                if org.lower() in text_lower:
                    _add("threat_actor", org)

        return results

    def extract_flat(self, text: str) -> List[Dict]:
        out: List[Dict] = []
        grouped = self.extract(text)
        for entity_type, values in grouped.items():
            for v in values:
                out.append({"type": entity_type, "value": v})
        return out


rule_entity_extractor = RuleBasedEntityExtractor()
