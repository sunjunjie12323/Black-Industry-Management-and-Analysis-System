import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from loguru import logger


MITRE_ATTCK_MAPPING = {
    "诈骗": {
        "technique_id": "T1598",
        "technique_name": "Phishing for Information",
        "tactic": "collection",
    },
    "钓鱼": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "initial-access",
    },
    "钓鱼攻击": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "initial-access",
    },
    "恶意软件": {
        "technique_id": "T1587",
        "technique_name": "Develop Capabilities",
        "tactic": "resource-development",
    },
    "木马": {
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "execution",
    },
    "勒索": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "impact",
    },
    "勒索软件": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "impact",
    },
    "洗钱": {
        "technique_id": "T1649",
        "technique_name": "Steal Operational Data",
        "tactic": "collection",
    },
    "DDoS": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "impact",
    },
    "僵尸网络": {
        "technique_id": "T1583",
        "technique_name": "Acquire Infrastructure",
        "tactic": "resource-development",
    },
    "挖矿": {
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
        "tactic": "impact",
    },
    "后门": {
        "technique_id": "T1578",
        "technique_name": "Modify Cloud Compute Infrastructure",
        "tactic": "persistence",
    },
    "数据泄露": {
        "technique_id": "T1567",
        "technique_name": "Exfiltration Over Web Service",
        "tactic": "exfiltration",
    },
    "供应链攻击": {
        "technique_id": "T1195",
        "technique_name": "Supply Chain Compromise",
        "tactic": "initial-access",
    },
    "社工": {
        "technique_id": "T1598",
        "technique_name": "Phishing for Information",
        "tactic": "collection",
    },
    "社会工程": {
        "technique_id": "T1598",
        "technique_name": "Phishing for Information",
        "tactic": "collection",
    },
    "跑分": {
        "technique_id": "T1649",
        "technique_name": "Steal Operational Data",
        "tactic": "collection",
    },
    "杀猪盘": {
        "technique_id": "T1598",
        "technique_name": "Phishing for Information",
        "tactic": "collection",
    },
    "接码": {
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "tactic": "persistence",
    },
    "养号": {
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "tactic": "persistence",
    },
    "引流": {
        "technique_id": "T1598",
        "technique_name": "Phishing for Information",
        "tactic": "collection",
    },
    "肉鸡": {
        "technique_id": "T1583",
        "technique_name": "Acquire Infrastructure",
        "tactic": "resource-development",
    },
    "暗网": {
        "technique_id": "T1589",
        "technique_name": "Gather Victim Identity Information",
        "tactic": "reconnaissance",
    },
}

MALWARE_TYPE_KEYWORDS = {
    "ransomware": ["勒索", "ransomware", "加密文件", "赎金"],
    "trojan": ["木马", "trojan", "后门", "backdoor", "远控"],
    "rat": ["远控", "rat", "远程控制", "remote access"],
    "worm": ["蠕虫", "worm", "自我传播"],
    "downloader": ["下载器", "downloader", "dropper", "释放器"],
    "spyware": ["间谍", "spyware", "监控", "窃密"],
    "miner": ["挖矿", "miner", "cryptominer", "coinhive"],
    "botnet": ["僵尸", "botnet", "肉鸡", "僵尸网络"],
    "keylogger": ["键盘记录", "keylogger", "按键记录"],
    "infostealer": ["窃密", "stealer", "信息窃取", "料子"],
}

SOPHISTICATION_MAP = {
    "critical": "advanced",
    "high": "advanced",
    "medium": "intermediate",
    "low": "minimal",
    "info": "none",
}

RESOURCE_LEVEL_MAP = {
    "critical": "government",
    "high": "organized-crime",
    "medium": "team",
    "low": "individual",
    "info": "individual",
}


class STIXExporter:
    STIX_VERSION = "2.1"

    def __init__(self, namespace_uuid: str = None):
        self._namespace_uuid = namespace_uuid or str(uuid.uuid4())

    def _generate_stix_id(self, stix_type: str) -> str:
        return f"{stix_type}--{uuid.uuid4()}"

    def export_intelligence(self, intel_data: Dict) -> Dict:
        objects = []
        identity = self._create_identity(intel_data)
        objects.append(identity)

        indicator = self._create_indicator(intel_data)
        objects.append(indicator)

        if intel_data.get("threat_actor"):
            threat_actor = self._create_threat_actor(intel_data, identity["id"])
            objects.append(threat_actor)
            objects.append(self._create_relationship(
                indicator["id"], threat_actor["id"], "indicates"
            ))

        content = intel_data.get("content", "")
        attack_patterns = self._create_attack_patterns(content)
        for ap in attack_patterns:
            objects.append(ap)
            objects.append(self._create_relationship(
                indicator["id"], ap["id"], "indicates"
            ))

        cves = re.findall(r'CVE-\d{4}-\d{4,}', content)
        for cve in cves:
            vuln = self._create_vulnerability(cve)
            objects.append(vuln)
            objects.append(self._create_relationship(
                indicator["id"], vuln["id"], "indicates"
            ))

        malware = self._create_malware(intel_data)
        if malware:
            objects.append(malware)
            objects.append(self._create_relationship(
                indicator["id"], malware["id"], "indicates"
            ))

        report = self._create_report(intel_data, [o["id"] for o in objects])
        objects.append(report)

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

    def export_bundle(self, intel_list: List[Dict]) -> Dict:
        all_objects = []
        seen_ids = set()

        for intel in intel_list:
            bundle = self.export_intelligence(intel)
            for obj in bundle.get("objects", []):
                if obj["id"] not in seen_ids:
                    all_objects.append(obj)
                    seen_ids.add(obj["id"])

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": all_objects,
        }

    def export_taxii_envelope(self, intel_list: List[Dict], more: bool = False, next_cursor: str = None) -> Dict:
        bundle = self.export_bundle(intel_list)
        envelope = {
            "more": more,
            "objects": bundle["objects"],
        }
        if next_cursor:
            envelope["next"] = next_cursor
        return envelope

    def export_incremental(self, intel_list: List[Dict], after_timestamp: str = None) -> Dict:
        filtered = intel_list
        if after_timestamp:
            filtered = [
                i for i in intel_list
                if i.get("collected_at", "") > after_timestamp
            ]
        return self.export_bundle(filtered)

    def _create_indicator(self, intel: Dict) -> Dict:
        content = intel.get("content", "")
        threat_level = intel.get("threat_level", "info")
        confidence_map = {"critical": 95, "high": 80, "medium": 60, "low": 40, "info": 20}

        pattern, pattern_type = self._generate_stix_pattern(content)

        return {
            "type": "indicator",
            "spec_version": self.STIX_VERSION,
            "id": self._generate_stix_id("indicator"),
            "created": intel.get("collected_at", datetime.now(timezone.utc).isoformat()),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": content[:80],
            "description": content,
            "confidence": confidence_map.get(threat_level, 50),
            "pattern": pattern,
            "pattern_type": pattern_type,
            "valid_from": intel.get("collected_at", datetime.now(timezone.utc).isoformat()),
            "labels": [intel.get("entity_type", "threat-intelligence"), threat_level],
            "external_references": [
                {
                    "source_name": "threat-intel-agent",
                    "external_id": intel.get("id", ""),
                }
            ],
        }

    def _generate_stix_pattern(self, content: str) -> tuple:
        ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')

        patterns = []

        for ip in ip_pattern.findall(content):
            patterns.append(f"[ipv4-addr:value = '{ip}']")

        for domain in domain_pattern.findall(content):
            if not ip_pattern.match(domain):
                patterns.append(f"[domain-name:value = '{domain}']")

        for url in url_pattern.findall(content):
            patterns.append(f"[url:value = '{url}']")

        for email in email_pattern.findall(content):
            patterns.append(f"[email-addr:value = '{email}']")

        for sha256 in sha256_pattern.findall(content):
            patterns.append(f"[file:hashes.'SHA-256' = '{sha256}']")

        for md5 in md5_pattern.findall(content):
            if not sha256_pattern.match(md5) and not sha1_pattern.match(md5):
                patterns.append(f"[file:hashes.'MD5' = '{md5}']")

        for sha1 in sha1_pattern.findall(content):
            if not sha256_pattern.match(sha1):
                patterns.append(f"[file:hashes.'SHA-1' = '{sha1}']")

        for cve in cve_pattern.findall(content):
            patterns.append(f"[vulnerability:name = '{cve}']")

        if patterns:
            combined = " OR ".join(patterns[:20])
            return combined, "stix"

        return f"[file:hashes.'SHA-256' = 'unknown']", "stix"

    def _create_threat_actor(self, intel: Dict, identity_id: str = None) -> Dict:
        threat_level = intel.get("threat_level", "info")
        content = intel.get("content", "").lower()

        motivations = []
        if any(kw in content for kw in ["洗钱", "跑分", "套现", "提现"]):
            motivations.append("financial-gain")
        if any(kw in content for kw in ["报复", "政治", "意识形态"]):
            motivations.append("ideology")
        if any(kw in content for kw in ["竞争", "商业间谍"]):
            motivations.append("competitive-advantage")
        if not motivations:
            motivations.append("financial-gain")

        return {
            "type": "threat-actor",
            "spec_version": self.STIX_VERSION,
            "id": self._generate_stix_id("threat-actor"),
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": intel.get("threat_actor", "Unknown"),
            "threat_actor_types": ["criminal"],
            "sophistication": SOPHISTICATION_MAP.get(threat_level, "intermediate"),
            "resource_level": RESOURCE_LEVEL_MAP.get(threat_level, "team"),
            "motivation": motivations,
            "confidence": 70,
            "external_references": [],
        }

    def _create_attack_patterns(self, content: str) -> List[Dict]:
        patterns = []
        seen_techniques = set()

        for keyword, mapping in MITRE_ATTCK_MAPPING.items():
            if keyword in content:
                tech_id = mapping["technique_id"]
                if tech_id in seen_techniques:
                    continue
                seen_techniques.add(tech_id)

                patterns.append({
                    "type": "attack-pattern",
                    "spec_version": self.STIX_VERSION,
                    "id": self._generate_stix_id("attack-pattern"),
                    "created": datetime.now(timezone.utc).isoformat(),
                    "modified": datetime.now(timezone.utc).isoformat(),
                    "name": mapping["technique_name"],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": tech_id,
                            "url": f"https://attack.mitre.org/techniques/{tech_id.replace('T', 'T')}/",
                        }
                    ],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": mapping["tactic"],
                        }
                    ],
                })

        return patterns

    def _create_vulnerability(self, cve_id: str) -> Dict:
        return {
            "type": "vulnerability",
            "spec_version": self.STIX_VERSION,
            "id": self._generate_stix_id("vulnerability"),
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": cve_id,
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": cve_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            ],
        }

    def _create_malware(self, intel: Dict) -> Optional[Dict]:
        content = intel.get("content", "").lower()
        detected_types = []

        for mtype, keywords in MALWARE_TYPE_KEYWORDS.items():
            if any(kw in content for kw in keywords):
                detected_types.append(mtype)

        if not detected_types:
            return None

        return {
            "type": "malware",
            "spec_version": self.STIX_VERSION,
            "id": self._generate_stix_id("malware"),
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": intel.get("content", "")[:50],
            "malware_types": detected_types,
            "is_family": False,
        }

    def _create_identity(self, intel: Dict) -> Dict:
        source = intel.get("source", "threat-intel-agent")
        return {
            "type": "identity",
            "spec_version": self.STIX_VERSION,
            "id": self._generate_stix_id("identity"),
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": source,
            "identity_class": "organization",
        }

    def _create_relationship(self, source_id: str, target_id: str, rel_type: str) -> Dict:
        return {
            "type": "relationship",
            "spec_version": self.STIX_VERSION,
            "id": self._generate_stix_id("relationship"),
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "relationship_type": rel_type,
            "source_ref": source_id,
            "target_ref": target_id,
        }

    def _create_report(self, intel: Dict, object_refs: List[str]) -> Dict:
        content = intel.get("content", "")
        threat_level = intel.get("threat_level", "info")

        return {
            "type": "report",
            "spec_version": self.STIX_VERSION,
            "id": self._generate_stix_id("report"),
            "created": intel.get("collected_at", datetime.now(timezone.utc).isoformat()),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": f"Threat Intelligence Report - {content[:60]}",
            "description": content,
            "published": datetime.now(timezone.utc).isoformat(),
            "object_refs": object_refs,
            "labels": [threat_level],
            "confidence": {"critical": 95, "high": 80, "medium": 60, "low": 40, "info": 20}.get(threat_level, 50),
        }

    def to_json(self, bundle: Dict, indent: int = 2) -> str:
        return json.dumps(bundle, ensure_ascii=False, indent=indent)
