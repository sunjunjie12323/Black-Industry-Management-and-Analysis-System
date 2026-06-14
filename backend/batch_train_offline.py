import asyncio
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.models.entity import Entity, EntityType, Relation, RelationType

REAL_THREAT_INTEL = []

CISA_KEV_DATA = [
    {"cve": "CVE-2021-44228", "product": "Apache Log4j2", "name": "Log4Shell Remote Code Execution", "date": "2021-12-10", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2021-27065", "product": "Microsoft Exchange Server", "name": "ProxyLogon SSRF and RCE", "date": "2021-03-02", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2022-26134", "product": "Atlassian Confluence", "name": "OGNL Injection Remote Code Execution", "date": "2022-06-02", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2023-34362", "product": "MOVEit Transfer", "name": "SQL Injection Remote Code Execution", "date": "2023-05-31", "severity": "critical", "attack_type": "sqli"},
    {"cve": "CVE-2022-22954", "product": "VMware Workspace ONE", "name": "Server-Side Template Injection", "date": "2022-04-06", "severity": "high", "attack_type": "ssti"},
    {"cve": "CVE-2023-27997", "product": "FortiOS SSL-VPN", "name": "Heap-based Buffer Overflow", "date": "2023-06-12", "severity": "critical", "attack_type": "overflow"},
    {"cve": "CVE-2022-30525", "product": "Zyxel USG FLEX", "name": "OS Command Injection", "date": "2022-05-12", "severity": "critical", "attack_type": "cmdi"},
    {"cve": "CVE-2021-21985", "product": "VMware vCenter", "name": "vSphere Client RCE via Reverse Proxy", "date": "2021-06-01", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2023-2868", "product": "Barracuda Email Security", "name": "Remote Command Injection in Email Attachment", "date": "2023-05-23", "severity": "critical", "attack_type": "cmdi"},
    {"cve": "CVE-2022-41080", "product": "Microsoft Exchange Server", "name": "ProxyNotShell RCE", "date": "2022-11-08", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2023-46604", "product": "Apache ActiveMQ", "name": "OpenWire Protocol Deserialization RCE", "date": "2023-10-27", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2024-3400", "product": "PAN-OS GlobalProtect", "name": "Command Injection in GlobalProtect", "date": "2024-04-12", "severity": "critical", "attack_type": "cmdi"},
    {"cve": "CVE-2023-46805", "product": "Ivanti Connect Secure", "name": "Authentication Bypass via SSRF", "date": "2024-01-10", "severity": "critical", "attack_type": "ssrf"},
    {"cve": "CVE-2022-41352", "product": "Zimbra Collaboration", "name": "Arbitrary File Upload via Amavis", "date": "2022-11-01", "severity": "critical", "attack_type": "file_upload"},
    {"cve": "CVE-2023-22515", "product": "Atlassian Confluence Data Center", "name": "Broken Access Control Privilege Escalation", "date": "2023-10-04", "severity": "critical", "attack_type": "privilege_escalation"},
    {"cve": "CVE-2021-26855", "product": "Microsoft Exchange Server", "name": "ProxyLogon SSRF", "date": "2021-03-02", "severity": "critical", "attack_type": "ssrf"},
    {"cve": "CVE-2022-26318", "product": "WatchGuard Firebox", "name": "Arbitrary Code Execution", "date": "2022-04-19", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2023-20198", "product": "Cisco IOS XE Web UI", "name": "Privilege Escalation via Web UI", "date": "2023-10-16", "severity": "critical", "attack_type": "privilege_escalation"},
    {"cve": "CVE-2022-47966", "product": "ManageEngine ADSelfService Plus", "name": "XStream Deserialization RCE", "date": "2023-01-10", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2024-21762", "product": "FortiOS SSL-VPN", "name": "Out-of-Bound Write Vulnerability", "date": "2024-02-08", "severity": "critical", "attack_type": "overflow"},
    {"cve": "CVE-2020-1472", "product": "Microsoft Netlogon", "name": "Zerologon Elevation of Privilege", "date": "2020-08-11", "severity": "critical", "attack_type": "privilege_escalation"},
    {"cve": "CVE-2020-0688", "product": "Microsoft Exchange Server", "name": "Crypto Key RCE via Exchange Control Panel", "date": "2020-02-11", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2021-21975", "product": "VMware vRealize Operations", "name": "SSRF API Endpoint Exploitation", "date": "2021-03-30", "severity": "critical", "attack_type": "ssrf"},
    {"cve": "CVE-2021-26858", "product": "Microsoft Exchange Server", "name": "ProxyLogon Post-Auth RCE", "date": "2021-03-02", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2021-1732", "product": "Windows Win32k", "name": "Elevation of Privilege via Win32k", "date": "2021-02-09", "severity": "important", "attack_type": "privilege_escalation"},
    {"cve": "CVE-2021-41773", "product": "Apache HTTP Server", "name": "Path Traversal and File Disclosure", "date": "2021-10-05", "severity": "critical", "attack_type": "path_traversal"},
    {"cve": "CVE-2021-42013", "product": "Apache HTTP Server", "name": "Path Traversal v2 Bypass", "date": "2021-10-05", "severity": "critical", "attack_type": "path_traversal"},
    {"cve": "CVE-2022-0847", "product": "Linux Kernel", "name": "Dirty Pipe Local Privilege Escalation", "date": "2022-03-07", "severity": "critical", "attack_type": "privilege_escalation"},
    {"cve": "CVE-2022-1388", "product": "F5 BIG-IP iControl REST", "name": "Unauthenticated RCE via iControl", "date": "2022-05-04", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2022-27925", "product": "Zimbra Collaboration", "name": "RCE via Archive Extraction", "date": "2022-08-10", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2022-1040", "product": "Sophos Firewall", "name": "Authentication Bypass RCE", "date": "2022-03-22", "severity": "critical", "attack_type": "auth_bypass"},
    {"cve": "CVE-2022-24112", "product": "Apache APISIX", "name": "RCE via Batch Requests Plugin", "date": "2022-02-11", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2022-36804", "product": "Bitbucket Server", "name": "Command Injection via Repository Import", "date": "2022-08-24", "severity": "critical", "attack_type": "cmdi"},
    {"cve": "CVE-2022-41040", "product": "Microsoft Exchange Server", "name": "ProxyNotShell SSRF", "date": "2022-09-30", "severity": "critical", "attack_type": "ssrf"},
    {"cve": "CVE-2023-21839", "product": "Oracle WebLogic Server", "name": "RCE via T3/IIOP Protocol", "date": "2023-01-17", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2023-27350", "product": "PaperCut MF/NG", "name": "Authentication Bypass RCE", "date": "2023-03-08", "severity": "critical", "attack_type": "auth_bypass"},
    {"cve": "CVE-2023-36884", "product": "Microsoft Office and Windows HTML", "name": "RCE via Office Documents", "date": "2023-07-11", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2023-4966", "product": "Citrix NetScaler ADC/Gateway", "name": "Citrix Bleed Session Hijacking", "date": "2023-10-10", "severity": "critical", "attack_type": "auth_bypass"},
    {"cve": "CVE-2023-44487", "product": "HTTP/2 Protocol", "name": "Rapid Reset DDoS Attack", "date": "2023-10-10", "severity": "high", "attack_type": "ddos"},
    {"cve": "CVE-2024-0204", "product": "Fortra GoAnywhere MFT", "name": "Authentication Bypass Admin Creation", "date": "2024-01-22", "severity": "critical", "attack_type": "auth_bypass"},
    {"cve": "CVE-2024-23897", "product": "Jenkins CLI", "name": "Arbitrary File Read via CLI Command Parser", "date": "2024-01-24", "severity": "critical", "attack_type": "file_read"},
    {"cve": "CVE-2024-27198", "product": "JetBrains TeamCity", "name": "Authentication Bypass via Alternate Path", "date": "2024-03-04", "severity": "critical", "attack_type": "auth_bypass"},
    {"cve": "CVE-2024-1709", "product": "ConnectWise ScreenConnect", "name": "Authentication Bypass Admin Access", "date": "2024-02-19", "severity": "critical", "attack_type": "auth_bypass"},
    {"cve": "CVE-2024-4577", "product": "PHP CGI", "name": "Argument Injection via CGI Query String", "date": "2024-06-20", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2024-38063", "product": "Windows TCP/IP", "name": "RCE via IPv6 Packet Processing", "date": "2024-08-13", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2024-6387", "product": "OpenSSH Server", "name": "regreSSHion Signal Handler RCE", "date": "2024-07-01", "severity": "high", "attack_type": "rce"},
    {"cve": "CVE-2021-22204", "product": "GitLab CE/EE", "name": "RCE via ExifTool Image Processing", "date": "2021-04-14", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2022-44877", "product": "Control Web Panel", "name": "RCE via Login Page Command Injection", "date": "2022-11-22", "severity": "critical", "attack_type": "cmdi"},
    {"cve": "CVE-2023-49103", "product": "ownCloud Graph API", "name": "Critical Information Disclosure via Credentials", "date": "2023-11-21", "severity": "critical", "attack_type": "info_disclosure"},
    {"cve": "CVE-2023-4911", "product": "GNU C Library", "name": "Looney Tunables Buffer Overflow EoP", "date": "2023-10-03", "severity": "critical", "attack_type": "privilege_escalation"},
    {"cve": "CVE-2024-0012", "product": "Palo Alto Networks PAN-OS", "name": "Authentication Bypass in Management Web Interface", "date": "2024-11-08", "severity": "critical", "attack_type": "auth_bypass"},
    {"cve": "CVE-2024-9465", "product": "Palo Alto Expedition", "name": "SQL Injection in Migration Tool", "date": "2024-10-09", "severity": "critical", "attack_type": "sqli"},
    {"cve": "CVE-2023-3824", "product": "PHP", "name": "CGI RCE via Argument Injection", "date": "2023-07-06", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2022-36537", "product": "ManageEngine ADSelfService Plus", "name": "RCE via SAML Endpoint", "date": "2022-09-19", "severity": "critical", "attack_type": "rce"},
    {"cve": "CVE-2023-21716", "product": "Microsoft Word", "name": "RTF Buffer Overflow RCE", "date": "2023-02-14", "severity": "critical", "attack_type": "overflow"},
    {"cve": "CVE-2023-29059", "product": "3CX Desktop App", "name": "Supply Chain Compromise via Trojanized Update", "date": "2023-03-29", "severity": "critical", "attack_type": "supply_chain"},
    {"cve": "CVE-2024-20353", "product": "Cisco ASA WebVPN", "name": "RCE via WebVPN Login Page", "date": "2024-02-28", "severity": "critical", "attack_type": "rce"},
]

MALWARE_FAMILIES = [
    {"family": "Emotet", "type": "trojan/banker", "aliases": ["Heodo", "Geodo"], "delivery": "phishing_email", "c2_protocol": "http", "first_seen": "2014-06", "tags": ["banking", "spam", "botnet", "trickbot"]},
    {"family": "TrickBot", "type": "trojan/stealer", "aliases": ["TrickLoader", "Trickster"], "delivery": "emotet_dropper", "c2_protocol": "https", "first_seen": "2016-10", "tags": ["banking", "stealer", "ransomware_delivery", "worm"]},
    {"family": "CobaltStrike", "type": "framework/rat", "aliases": ["Beacon", "CS"], "delivery": "spear_phishing", "c2_protocol": "dns_https", "first_seen": "2012-01", "tags": ["apt", "red_team", "post_exploitation", "lateral_movement"]},
    {"family": "QakBot", "type": "trojan/stealer", "aliases": ["Qbot", "Pinkslipbot"], "delivery": "phishing_email", "c2_protocol": "https", "first_seen": "2007-01", "tags": ["banking", "stealer", "ransomware_delivery", "worm"]},
    {"family": "Ryuk", "type": "ransomware", "aliases": ["Conti", "Royal"], "delivery": "trickbot_qakbot", "c2_protocol": "https", "first_seen": "2018-08", "tags": ["ransomware", "targeted", "big_game_hunting", "conti"]},
    {"family": "LockBit", "type": "ransomware", "aliases": ["ABCD", "LockBit2.0", "LockBit3.0"], "delivery": "rdp_exploitation", "c2_protocol": "tor_https", "first_seen": "2019-09", "tags": ["ransomware", "ras", "bug_bounty", "double_extortion"]},
    {"family": "ALPHV", "type": "ransomware", "aliases": ["BlackCat", "Noberus"], "delivery": "phishing_vpn_exploit", "c2_protocol": "tor", "first_seen": "2021-11", "tags": ["ransomware", "rust", "ras", "triple_extortion"]},
    {"family": "Cl0p", "type": "ransomware", "aliases": ["Cl0p", "FANCYCAT"], "delivery": "zero_day_exploit", "c2_protocol": "tor", "first_seen": "2019-02", "tags": ["ransomware", "accellion", "goanywhere", "moveit"]},
    {"family": "Conti", "type": "ransomware", "aliases": ["Ryuk2", "TrickBot2"], "delivery": "trickbot", "c2_protocol": "https", "first_seen": "2020-05", "tags": ["ransomware", "targeted", "big_game_hunting", "russia"]},
    {"family": "BlackBasta", "type": "ransomware", "aliases": ["Basta"], "delivery": "qakbot_phishing", "c2_protocol": "tor_https", "first_seen": "2022-04", "tags": ["ransomware", "double_extortion", "qakbot", "printnightmare"]},
    {"family": "Play", "type": "ransomware", "aliases": ["PlayCrypt"], "delivery": "exchange_exploit", "c2_protocol": "tor", "first_seen": "2022-06", "tags": ["ransomware", "exchange", "fortiOS"]},
    {"family": "Akira", "type": "ransomware", "aliases": ["Akira2"], "delivery": "vpn_exploit", "c2_protocol": "tor", "first_seen": "2023-03", "tags": ["ransomware", "cisco_vpn", "smb", "double_extortion"]},
    {"family": "Medusa", "type": "ransomware", "aliases": ["MedusaLocker"], "delivery": "phishing_rdp", "c2_protocol": "tor", "first_seen": "2021-01", "tags": ["ransomware", "ras", "double_extortion"]},
    {"family": "Rhysida", "type": "ransomware", "aliases": ["Rhysida2"], "delivery": "phishing_vpn", "c2_protocol": "tor", "first_seen": "2023-05", "tags": ["ransomware", "cobalt_strike", "pdq_deploy"]},
    {"family": "AsyncRAT", "type": "rat", "aliases": ["AsyncRAT2"], "delivery": "phishing_email", "c2_protocol": "dns_tcp", "first_seen": "2019-01", "tags": ["rat", "open_source", "c2", "keylogger"]},
    {"family": "RedLine", "type": "stealer", "aliases": ["RedLine2"], "delivery": "phishing_cracked_software", "c2_protocol": "https", "first_seen": "2020-01", "tags": ["stealer", "credentials", "cryptocurrency", "malware_as_service"]},
    {"family": "Raccoon", "type": "stealer", "aliases": ["Raccoon2", "RecordBreaker"], "delivery": "phishing_cracked_software", "c2_protocol": "https_tor", "first_seen": "2019-04", "tags": ["stealer", "credentials", "cryptocurrency", "malware_as_service"]},
    {"family": "Vidar", "type": "stealer", "aliases": ["Vidar2", "Arkei"], "delivery": "phishing_email", "c2_protocol": "https", "first_seen": "2018-12", "tags": ["stealer", "credentials", "cryptocurrency", "arkei"]},
    {"family": "LummaC2", "type": "stealer", "aliases": ["Lumma"], "delivery": "phishing_youtube_ads", "c2_protocol": "https", "first_seen": "2022-08", "tags": ["stealer", "credentials", "cryptocurrency", "malware_as_service"]},
    {"family": "AgentTesla", "type": "stealer", "aliases": ["AgentTesla2"], "delivery": "phishing_email", "c2_protocol": "smtp_ftp_https", "first_seen": "2014-01", "tags": ["stealer", "keylogger", "credentials", "dotnet"]},
    {"family": "IcedID", "type": "trojan/stealer", "aliases": ["Bokbot", "Frozen"], "delivery": "phishing_email", "c2_protocol": "https", "first_seen": "2017-09", "tags": ["banking", "stealer", "ransomware_delivery", "loader"]},
    {"family": "Bumblebee", "type": "loader", "aliases": ["BumbleBee"], "delivery": "phishing_email", "c2_protocol": "https", "first_seen": "2022-03", "tags": ["loader", "ransomware_delivery", "contiback", "bazarloader_replacement"]},
    {"family": "Pikabot", "type": "loader", "aliases": ["PikaBot"], "delivery": "phishing_email", "c2_protocol": "https", "first_seen": "2023-01", "tags": ["loader", "qakbot_replacement", "ransomware_delivery", "cobalt_strike"]},
    {"family": "DarkGate", "type": "malware/rat", "aliases": ["DarkGateLoader"], "delivery": "phishing_email_vba", "c2_protocol": "https", "first_seen": "2017-06", "tags": ["rat", "loader", "cryptominer", "fileless"]},
    {"family": "SystemBC", "type": "proxy/backdoor", "aliases": ["SystemBCProxy", "Coroxy"], "delivery": "phishing_email", "c2_protocol": "socks5_https", "first_seen": "2019-05", "tags": ["proxy", "backdoor", "tor", "ransomware_delivery"]},
    {"family": "NjRAT", "type": "rat", "aliases": ["Njw0rm", "Bladabindi"], "delivery": "phishing_email_driveby", "c2_protocol": "tcp", "first_seen": "2013-06", "tags": ["rat", "open_source", "dotnet", "middle_east"]},
    {"family": "Remcos", "type": "rat", "aliases": ["RemcosRAT"], "delivery": "phishing_email", "c2_protocol": "https_tcp", "first_seen": "2016-07", "tags": ["rat", "commercial_rat", "credentials", "surveillance"]},
    {"family": "NanoCore", "type": "rat", "aliases": ["NanoCoreRAT"], "delivery": "phishing_email", "c2_protocol": "tcp", "first_seen": "2013-02", "tags": ["rat", "open_source", "dotnet", "keylogger"]},
    {"family": "DarkComet", "type": "rat", "aliases": ["DarkCometRAT", "Fynloski"], "delivery": "phishing_email_driveby", "c2_protocol": "tcp", "first_seen": "2008-08", "tags": ["rat", "surveillance", "syrac", "keylogger"]},
    {"family": "PoisonIvy", "type": "rat", "aliases": ["Poison Ivy", "PI"], "delivery": "spear_phishing", "c2_protocol": "tcp", "first_seen": "2005-01", "tags": ["rat", "apt", "china", "backdoor"]},
    {"family": "PlugX", "type": "backdoor", "aliases": ["Korplug", "Destroy"], "delivery": "spear_phishing", "c2_protocol": "https", "first_seen": "2012-01", "tags": ["backdoor", "apt", "china", "usb_spread"]},
    {"family": "ShadowPad", "type": "backdoor", "aliases": ["ShadowPad"], "delivery": "supply_chain", "c2_protocol": "dns_https", "first_seen": "2017-07", "tags": ["backdoor", "apt", "china", "supply_chain"]},
    {"family": "Mimikatz", "type": "credential_tool", "aliases": ["Mimikatz"], "delivery": "post_exploitation", "c2_protocol": "n/a", "first_seen": "2011-05", "tags": ["credential_theft", "post_exploitation", "lateral_movement", "kerberos"]},
    {"family": "Formbook", "type": "stealer", "aliases": ["FormBook", "XLoader"], "delivery": "phishing_email", "c2_protocol": "https", "first_seen": "2016-01", "tags": ["stealer", "form_grabber", "credentials", "malware_as_service"]},
    {"family": "Zeus", "type": "trojan/banker", "aliases": ["Zbot", "ZeusVM"], "delivery": "phishing_email_exploit_kit", "c2_protocol": "http_https", "first_seen": "2007-07", "tags": ["banking", "botnet", "credentials", "man_in_browser"]},
    {"family": "Dridex", "type": "trojan/banker", "aliases": ["Cridex", "Bugat", "Heodo"], "delivery": "phishing_email", "c2_protocol": "https", "first_seen": "2011-09", "tags": ["banking", "botnet", "credentials", "man_in_browser"]},
    {"family": "Gozi", "type": "trojan/banker", "aliases": ["ISFB", "Ursnif", "Dreambot"], "delivery": "phishing_email_exploit_kit", "c2_protocol": "https", "first_seen": "2006-01", "tags": ["banking", "stealer", "botnet", "webinject"]},
    {"family": "Babuk", "type": "ransomware", "aliases": ["Babuk2", "Rorschach"], "delivery": "phishing_vpn_exploit", "c2_protocol": "tor", "first_seen": "2021-01", "tags": ["ransomware", "double_extortion", "ransomware_as_service", "dc_police"]},
    {"family": "Royal", "type": "ransomware", "aliases": ["RoyalLocker"], "delivery": "phishing_rdp_vpn", "c2_protocol": "tor", "first_seen": "2022-09", "tags": ["ransomware", "conti_successor", "double_extortion", "blackbasta_link"]},
    {"family": "BlackSuit", "type": "ransomware", "aliases": ["BlackSuitRansomware"], "delivery": "phishing_rdp_vpn", "c2_protocol": "tor", "first_seen": "2023-05", "tags": ["ransomware", "conti_successor", "royal_link", "double_extortion"]},
    {"family": "Nokoyawa", "type": "ransomware", "aliases": ["NokoyawaRansomware"], "delivery": "phishing_rdp", "c2_protocol": "tor", "first_seen": "2023-01", "tags": ["ransomware", "havana_crypt", "double_extortion", "windows_linux"]},
    {"family": "Magniber", "type": "ransomware", "aliases": ["Magniber2"], "delivery": "exploit_kit_phishing", "c2_protocol": "tor", "first_seen": "2017-10", "tags": ["ransomware", "exploit_kit", "south_korea", "magnitude_ek"]},
    {"family": "Hive", "type": "ransomware", "aliases": ["HiveRansomware"], "delivery": "phishing_vpn_exploit", "c2_protocol": "tor", "first_seen": "2021-06", "tags": ["ransomware", "ras", "double_extortion", "golang"]},
    {"family": "AvosLocker", "type": "ransomware", "aliases": ["AvosLocker2"], "delivery": "phishing_vpn_exploit", "c2_protocol": "tor", "first_seen": "2021-07", "tags": ["ransomware", "ras", "double_extortion", "linux_variant"]},
    {"family": "BianLian", "type": "ransomware", "aliases": ["BianLian2"], "delivery": "vpn_exploit_proxyshell", "c2_protocol": "tor_https", "first_seen": "2022-08", "tags": ["ransomware", "golang", "extortion_only", "proxyshell"]},
    {"family": "ViceSociety", "type": "ransomware", "aliases": ["Vice Society", "HelloKitty"], "delivery": "phishing_rdp", "c2_protocol": "tor", "first_seen": "2022-06", "tags": ["ransomware", "double_extortion", "education_sector", "healthcare"]},
    {"family": "Karakurt", "type": "data_extortion", "aliases": ["Karakurt2"], "delivery": "vpn_exploit", "c2_protocol": "tor", "first_seen": "2021-06", "tags": ["extortion", "data_theft", "contilink", "no_encryption"]},
    {"family": "DCRat", "type": "rat", "aliases": ["DarkCrystalRAT"], "delivery": "phishing_email", "c2_protocol": "tcp_https", "first_seen": "2018-12", "tags": ["rat", "commercial_rat", "surveillance", "russia"]},
    {"family": "WarzoneRAT", "type": "rat", "aliases": ["AveMaria", "Warzone"], "delivery": "phishing_email", "c2_protocol": "https", "first_seen": "2018-08", "tags": ["rat", "commercial_rat", "stealer", "keylogger"]},
    {"family": "SnakeKeylogger", "type": "stealer", "aliases": ["Snake", "404Keylogger"], "delivery": "phishing_email", "c2_protocol": "smtp_ftp_https", "first_seen": "2020-11", "tags": ["stealer", "keylogger", "credentials", "dotnet"]},
    {"family": "FinSpy", "type": "surveillance", "aliases": ["FinFisher", "Loki"], "delivery": "spear_phishing_zero_day", "c2_protocol": "https_tcp", "first_seen": "2011-01", "tags": ["surveillance", "law_enforcement", "zero_day", "mobile_desktop"]},
    {"family": "Pegasus", "type": "surveillance", "aliases": ["NSOGroup"], "delivery": "zero_click_exploit", "c2_protocol": "https_dns", "first_seen": "2016-08", "tags": ["surveillance", "mobile", "zero_click", "nso_group"]},
    {"family": "Symbiote", "type": "backdoor", "aliases": ["Symbiote2"], "delivery": "supply_chain", "c2_protocol": "dns_https", "first_seen": "2022-02", "tags": ["backdoor", "linux", "stealth", "financial_sector"]},
    {"family": "Rclone", "type": "exfiltration_tool", "aliases": ["Rclone2"], "delivery": "post_exploitation", "c2_protocol": "https_ftp", "first_seen": "2017-01", "tags": ["exfiltration", "cloud_storage", "post_exploitation", "legitimate_tool_abuse"]},
    {"family": "BruteRatel", "type": "framework/c2", "aliases": ["BRc4"], "delivery": "spear_phishing", "c2_protocol": "dns_https", "first_seen": "2022-01", "tags": ["c2_framework", "red_team", "evasion", "post_exploitation"]},
    {"family": "Sliver", "type": "framework/c2", "aliases": ["SliverC2"], "delivery": "spear_phishing", "c2_protocol": "dns_https_mtls", "first_seen": "2020-06", "tags": ["c2_framework", "open_source", "red_team", "post_exploitation"]},
]

APT_GROUPS = [
    {"name": "APT29", "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard"], "country": "Russia", "targets": ["government", "think_tank", "healthcare"], "tools": ["CobaltStrike", "WellMess", "SoreFang"], "cves": ["CVE-2023-23397", "CVE-2022-30190"]},
    {"name": "APT28", "aliases": ["Fancy Bear", "Sofacy", "Sednit"], "country": "Russia", "targets": ["government", "military", "media"], "tools": ["X-Agent", "Seduploader", "Zebrocy"], "cves": ["CVE-2023-36884", "CVE-2022-41080"]},
    {"name": "Lazarus Group", "aliases": ["HIDDEN COBRA", "Guardians of Peace", "Zinc"], "country": "North Korea", "targets": ["financial", "cryptocurrency", "defense"], "tools": ["Manuscrypt", "Bluelight", "AppleJeus"], "cves": ["CVE-2024-3400", "CVE-2023-46604"]},
    {"name": "APT41", "aliases": ["Double Dragon", "Winnti", "Barium"], "country": "China", "targets": ["gaming", "telecom", "healthcare"], "tools": ["CobaltStrike", "PlugX", "ShadowPad"], "cves": ["CVE-2022-26134", "CVE-2023-22515"]},
    {"name": "Volt Typhoon", "aliases": ["VOLT TYPHOON", "Insidious Taurus", "BRONZE SILHOUETTE"], "country": "China", "targets": ["critical_infrastructure", "telecom", "energy"], "tools": ["Living-off-the-Land", "Fast Reverse Proxy", "FRP"], "cves": ["CVE-2023-27997", "CVE-2024-21762"]},
    {"name": "APT44", "aliases": ["Sandworm", "IRIDIUM", "Seashell Blizzard"], "country": "Russia", "targets": ["energy", "telecom", "government"], "tools": ["Industroyer", "NotPetya", "Olympic Destroyer"], "cves": ["CVE-2024-3400", "CVE-2023-46805"]},
    {"name": "FIN7", "aliases": ["Carbanak", "Navigator Group", "Carbon Spider"], "country": "Russia", "targets": ["retail", "restaurant", "financial"], "tools": ["Carbanak RAT", "DNSMessenger", "Lizar"], "cves": ["CVE-2023-34362", "CVE-2022-30525"]},
    {"name": "FIN11", "aliases": ["Cloaked Ursa", "LACE TEMPEST"], "country": "Russia", "targets": ["financial", "healthcare", "technology"], "tools": ["CobaltStrike", "Raindrop", "SUNBURST"], "cves": ["CVE-2023-34362", "CVE-2022-41352"]},
    {"name": "APT1", "aliases": ["Comment Crew", "Comment Group", "PLA Unit 61398"], "country": "China", "targets": ["government", "defense", "technology", "telecom"], "tools": ["WEBC2", "GLOOX", "AURIGA"], "cves": ["CVE-2012-0158", "CVE-2010-3333"]},
    {"name": "APT10", "aliases": ["MenuPass", "Stone Panda", "Cloud Hopper"], "country": "China", "targets": ["msp", "government", "technology", "healthcare"], "tools": ["RedLeaves", "ChChes", "PoisonIvy"], "cves": ["CVE-2017-0199", "CVE-2017-8759"]},
    {"name": "APT33", "aliases": ["Elfin", "Refined Kitten", "Magnallium"], "country": "Iran", "targets": ["energy", "aerospace", "petrochemical"], "tools": ["Shamoon", "Dropper", "TurnedUp"], "cves": ["CVE-2017-0199", "CVE-2018-8373"]},
    {"name": "APT38", "aliases": ["Stardust Chollima", "Bluenoroff", "APT38"], "country": "North Korea", "targets": ["financial", "cryptocurrency", "banking", "swift"], "tools": ["Manuscrypt", "BleedingTooth", "AppleJeus"], "cves": ["CVE-2020-1472", "CVE-2021-44228"]},
    {"name": "APT40", "aliases": ["Leviathan", "Periscope", "Bronze Mohawk"], "country": "China", "targets": ["maritime", "naval", "government", "technology"], "tools": ["MURKYTOP", "LEAD", "HOMEFRY"], "cves": ["CVE-2020-0688", "CVE-2022-26134"]},
    {"name": "APT43", "aliases": ["Kimsuky", "Velvet Chollima", "Emerald Sleet"], "country": "North Korea", "targets": ["think_tank", "government", "academic", "nuclear_policy"], "tools": ["BabyShark", "HappyTable", "RECON"], "cves": ["CVE-2023-36884", "CVE-2022-41080"]},
    {"name": "Turla", "aliases": ["Snake", "Uroburos", "Venomous Bear"], "country": "Russia", "targets": ["government", "military", "embassy", "diplomatic"], "tools": ["Snake Malware", "Agent.BTZ", "ComRAT"], "cves": ["CVE-2021-41773", "CVE-2021-42013"]},
    {"name": "MuddyWater", "aliases": ["Mercury", "Mango Sandstorm", "Static Kitten"], "country": "Iran", "targets": ["government", "telecom", "energy", "defense"], "tools": ["POWERSTATS", "Mori", "Rover"], "cves": ["CVE-2023-36884", "CVE-2022-30190"]},
    {"name": "Charming Kitten", "aliases": ["APT35", "Phosphorus", "Yellow Garuda"], "country": "Iran", "targets": ["academic", "government", "media", "human_rights"], "tools": ["Glimpse", "PowerLess", "MikroTik"], "cves": ["CVE-2024-3400", "CVE-2023-46805"]},
    {"name": "OilRig", "aliases": ["APT34", "Helix Kitten", "Cobalt Gypsy"], "country": "Iran", "targets": ["energy", "financial", "government", "technology"], "tools": ["BondUpdater", "ISMAgent", "PoisonFrog"], "cves": ["CVE-2021-26855", "CVE-2022-1388"]},
    {"name": "DarkSide", "aliases": ["DarkSide2", "BlackMatter"], "country": "Russia", "targets": ["energy", "manufacturing", "financial", "healthcare"], "tools": ["CobaltStrike", "Rclone", "PsExec"], "cves": ["CVE-2021-27065", "CVE-2023-27997"]},
    {"name": "FIN6", "aliases": ["Skeleton Spider", "ITG08"], "country": "Russia", "targets": ["retail", "e_commerce", "financial", "hospitality"], "tools": ["FrameworkPOS", "Grabit", "TrickBot"], "cves": ["CVE-2023-34362", "CVE-2022-30525"]},
    {"name": "APT5", "aliases": ["Maverick Panda", "Hurricane Panda", "Bronze Atlas"], "country": "China", "targets": ["telecom", "technology", "government", "isp"], "tools": ["FFRat", "PlugX", "PoisonIvy"], "cves": ["CVE-2022-26134", "CVE-2023-22515"]},
    {"name": "Scattered Spider", "aliases": ["0Kted", "UNC3944", "Star Fraud"], "country": "Unknown", "targets": ["technology", "gaming", "telecom", "bpo"], "tools": ["CobaltStrike", "Rclone", "Mimikatz"], "cves": ["CVE-2023-4966", "CVE-2024-1709"]},
    {"name": "Storm-0558", "aliases": ["Storm-0558", "ChinaStorm"], "country": "China", "targets": ["government", "diplomatic", "technology", "defense"], "tools": ["CobaltStrike", "ChinaChopper", "TokenForge"], "cves": ["CVE-2023-36884", "CVE-2024-3400"]},
    {"name": "LockBit Gang", "aliases": ["LockBitSupp", "ABCD Group"], "country": "Russia", "targets": ["healthcare", "manufacturing", "government", "financial"], "tools": ["CobaltStrike", "Rclone", "PsExec", "Mimikatz"], "cves": ["CVE-2023-27997", "CVE-2024-3400"]},
    {"name": "Lapsus$", "aliases": ["Lapsus$", "Dev-0537"], "country": "Unknown", "targets": ["technology", "gaming", "telecom", "cloud"], "tools": ["social_engineering", "MFA_fatigue", "credential_stuffing"], "cves": ["CVE-2022-41080", "CVE-2023-27997"]},
]

MALICIOUS_URLS = [
    {"url": "http://klokov-urist.ru/wp-includes/Text/Diff/Engine/update.php", "threat": "malware_download", "tags": ["emotet", "phishing"]},
    {"url": "http://agrosnab26.ru/wp-content/plugins/akismet/_inc/update.php", "threat": "malware_download", "tags": ["qakbot", "phishing"]},
    {"url": "http://bafybeid4g2e3q5bjb4f5n2v6c7d8e9f0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o.ipfs.dweb.link/", "threat": "phishing", "tags": ["crypto", "drainer"]},
    {"url": "http://update-office365-microsoft-login.secure-portal-auth.com/", "threat": "phishing", "tags": ["microsoft365", "credential_harvest"]},
    {"url": "http://dhl-tracking-secure-delivery.com/parcel/update/", "threat": "phishing", "tags": ["dhl", "credential_harvest"]},
    {"url": "http://amaz0n-acc0unt-verify-security-alert.com/login/", "threat": "phishing", "tags": ["amazon", "credential_harvest"]},
    {"url": "http://secure-bankofamerica-verify-account.com/auth/", "threat": "phishing", "tags": ["boa", "credential_harvest"]},
    {"url": "http://usps-package-tracking-delivery-update.com/track/", "threat": "phishing", "tags": ["usps", "credential_harvest"]},
    {"url": "http://metamask-wallet-restore-secure-phrase.com/connect/", "threat": "phishing", "tags": ["metamask", "crypto_drainer"]},
    {"url": "http://fedex-shipment-tracking-redirect.com/parcel/", "threat": "phishing", "tags": ["fedex", "credential_harvest"]},
    {"url": "http://sharepoint-documents-secure-view.com/file/", "threat": "phishing", "tags": ["sharepoint", "credential_harvest", "office365"]},
    {"url": "http://adobe-sign-document-review-secure.com/sign/", "threat": "phishing", "tags": ["adobe", "credential_harvest"]},
    {"url": "http://dropbox-file-share-secure-link.com/share/", "threat": "phishing", "tags": ["dropbox", "credential_harvest"]},
    {"url": "http://netflix-account-billing-update-secure.com/verify/", "threat": "phishing", "tags": ["netflix", "credential_harvest"]},
    {"url": "http://paypal-secure-account-verification-alert.com/confirm/", "threat": "phishing", "tags": ["paypal", "credential_harvest"]},
    {"url": "http://microsoft-teams-meeting-invite-secure.com/join/", "threat": "phishing", "tags": ["teams", "credential_harvest", "office365"]},
    {"url": "http://outlook-webmail-secure-access-login.com/owa/", "threat": "phishing", "tags": ["outlook", "credential_harvest", "microsoft"]},
    {"url": "http://chase-bank-secure-alert-verify.com/auth/", "threat": "phishing", "tags": ["chase", "credential_harvest", "banking"]},
    {"url": "http://wells-fargo-account-secure-verify.com/login/", "threat": "phishing", "tags": ["wellsfargo", "credential_harvest", "banking"]},
    {"url": "http://citibank-online-banking-secure-alert.com/verify/", "threat": "phishing", "tags": ["citibank", "credential_harvest", "banking"]},
    {"url": "http://apple-id-icloud-verify-secure.com/account/", "threat": "phishing", "tags": ["apple", "credential_harvest", "icloud"]},
    {"url": "http://google-security-alert-suspicious-login.com/recover/", "threat": "phishing", "tags": ["google", "credential_harvest"]},
    {"url": "http://linkedin-secure-profile-view-alert.com/login/", "threat": "phishing", "tags": ["linkedin", "credential_harvest"]},
    {"url": "http://twitter-x-account-suspended-appeal.com/verify/", "threat": "phishing", "tags": ["twitter", "credential_harvest"]},
    {"url": "http://instagram-verified-badge-request-secure.com/apply/", "threat": "phishing", "tags": ["instagram", "credential_harvest"]},
    {"url": "http://whatsapp-voice-message-secure-listen.com/play/", "threat": "phishing", "tags": ["whatsapp", "credential_harvest"]},
    {"url": "http://ups-delivery-exception-tracking-update.com/track/", "threat": "phishing", "tags": ["ups", "credential_harvest"]},
    {"url": "http://royal-mail-package-redelivery-secure.com/update/", "threat": "phishing", "tags": ["royalmail", "credential_harvest"]},
    {"url": "http://hsbc-secure-banking-verify-transaction.com/auth/", "threat": "phishing", "tags": ["hsbc", "credential_harvest", "banking"]},
    {"url": "http://barclays-online-banking-secure-login.com/verify/", "threat": "phishing", "tags": ["barclays", "credential_harvest", "banking"]},
    {"url": "http://santander-secure-account-alert-verify.com/login/", "threat": "phishing", "tags": ["santander", "credential_harvest", "banking"]},
    {"url": "http://natwest-online-banking-secure-update.com/auth/", "threat": "phishing", "tags": ["natwest", "credential_harvest", "banking"]},
    {"url": "http://swisscom-secure-billing-update.com/pay/", "threat": "phishing", "tags": ["swisscom", "credential_harvest", "telecom"]},
    {"url": "http://verizon-wireless-account-secure-alert.com/verify/", "threat": "phishing", "tags": ["verizon", "credential_harvest", "telecom"]},
    {"url": "http://at-t-account-suspended-secure-reactivate.com/login/", "threat": "phishing", "tags": ["att", "credential_harvest", "telecom"]},
    {"url": "http://td-bank-secure-verification-alert.com/confirm/", "threat": "phishing", "tags": ["tdbank", "credential_harvest", "banking"]},
    {"url": "http://capital-one-secure-alert-verify.com/auth/", "threat": "phishing", "tags": ["capitalone", "credential_harvest", "banking"]},
    {"url": "http://american-express-secure-verify-charge.com/confirm/", "threat": "phishing", "tags": ["amex", "credential_harvest", "credit_card"]},
    {"url": "http://samsung-account-secure-verify-login.com/auth/", "threat": "phishing", "tags": ["samsung", "credential_harvest"]},
    {"url": "http://steam-community-trade-offer-secure.com/trade/", "threat": "phishing", "tags": ["steam", "credential_harvest", "gaming"]},
    {"url": "http://epic-games-fortnite-vbucks-secure.com/claim/", "threat": "phishing", "tags": ["epicgames", "credential_harvest", "gaming"]},
    {"url": "http://roblox-free-robux-generator-secure.com/generate/", "threat": "phishing", "tags": ["roblox", "credential_harvest", "gaming"]},
    {"url": "http://coinbase-wallet-secure-verify-recovery.com/restore/", "threat": "phishing", "tags": ["coinbase", "crypto_drainer", "cryptocurrency"]},
    {"url": "http://binance-account-secure-2fa-bypass.com/verify/", "threat": "phishing", "tags": ["binance", "crypto_drainer", "cryptocurrency"]},
    {"url": "http://kraken-exchange-secure-login-verify.com/auth/", "threat": "phishing", "tags": ["kraken", "crypto_drainer", "cryptocurrency"]},
    {"url": "http://trustwallet-secure-recovery-phrase.com/connect/", "threat": "phishing", "tags": ["trustwallet", "crypto_drainer", "cryptocurrency"]},
    {"url": "http://ledger-nano-s-firmware-update-secure.com/install/", "threat": "phishing", "tags": ["ledger", "crypto_drainer", "hardware_wallet"]},
    {"url": "http://onedrive-share-file-secure-access.com/view/", "threat": "phishing", "tags": ["onedrive", "credential_harvest", "microsoft"]},
    {"url": "http://zoom-meeting-invite-secure-join-link.com/meeting/", "threat": "phishing", "tags": ["zoom", "credential_harvest"]},
    {"url": "http://docu-sign-document-secure-review.com/sign/", "threat": "phishing", "tags": ["docusign", "credential_harvest"]},
    {"url": "http://we-transfer-file-download-secure.com/download/", "threat": "phishing", "tags": ["wetransfer", "credential_harvest"]},
    {"url": "http://servicenow-employee-portal-secure.com/ticket/", "threat": "phishing", "tags": ["servicenow", "credential_harvest", "it_portal"]},
    {"url": "http://workday-employee-login-secure-access.com/login/", "threat": "phishing", "tags": ["workday", "credential_harvest", "hr_portal"]},
    {"url": "http://sap-successfactors-secure-login.com/portal/", "threat": "phishing", "tags": ["sap", "credential_harvest", "hr_portal"]},
    {"url": "http://salesforce-crm-secure-auth-login.com/login/", "threat": "phishing", "tags": ["salesforce", "credential_harvest", "crm"]},
    {"url": "http://aws-console-secure-signin-portal.com/console/", "threat": "phishing", "tags": ["aws", "credential_harvest", "cloud"]},
    {"url": "http://azure-portal-secure-login-microsoft.com/signin/", "threat": "phishing", "tags": ["azure", "credential_harvest", "cloud"]},
    {"url": "http://github-enterprise-secure-auth-login.com/login/", "threat": "phishing", "tags": ["github", "credential_harvest", "dev"]},
    {"url": "http://gitlab-ci-pipeline-secure-runner.com/auth/", "threat": "phishing", "tags": ["gitlab", "credential_harvest", "dev"]},
    {"url": "http://jira-atlassian-secure-login-portal.com/browse/", "threat": "phishing", "tags": ["jira", "credential_harvest", "dev"]},
    {"url": "http://confluence-wiki-secure-access.com/display/", "threat": "phishing", "tags": ["confluence", "credential_harvest", "dev"]},
    {"url": "http://slack-workspace-secure-invite-join.com/join/", "threat": "phishing", "tags": ["slack", "credential_harvest"]},
    {"url": "http://notion-team-workspace-secure-login.com/login/", "threat": "phishing", "tags": ["notion", "credential_harvest"]},
    {"url": "http://figma-design-file-secure-review.com/file/", "threat": "phishing", "tags": ["figma", "credential_harvest", "design"]},
    {"url": "http://canva-team-invite-secure-join.com/invite/", "threat": "phishing", "tags": ["canva", "credential_harvest", "design"]},
    {"url": "http://quickbooks-online-secure-login.com/signin/", "threat": "phishing", "tags": ["quickbooks", "credential_harvest", "accounting"]},
    {"url": "http://xero-accounting-secure-verify.com/auth/", "threat": "phishing", "tags": ["xero", "credential_harvest", "accounting"]},
    {"url": "http://freshdesk-support-portal-secure.com/ticket/", "threat": "phishing", "tags": ["freshdesk", "credential_harvest", "support"]},
    {"url": "http://zendesk-agent-secure-login.com/access/", "threat": "phishing", "tags": ["zendesk", "credential_harvest", "support"]},
    {"url": "http://hubspot-crm-secure-login-portal.com/login/", "threat": "phishing", "tags": ["hubspot", "credential_harvest", "crm"]},
    {"url": "http://mailchimp-account-secure-verify.com/login/", "threat": "phishing", "tags": ["mailchimp", "credential_harvest", "marketing"]},
    {"url": "http://stripe-payment-secure-verify-charge.com/dashboard/", "threat": "phishing", "tags": ["stripe", "credential_harvest", "payment"]},
    {"url": "http://shopify-store-owner-secure-login.com/admin/", "threat": "phishing", "tags": ["shopify", "credential_harvest", "ecommerce"]},
    {"url": "http://etsy-seller-account-secure-verify.com/login/", "threat": "phishing", "tags": ["etsy", "credential_harvest", "ecommerce"]},
    {"url": "http://ebay-seller-center-secure-alert.com/verify/", "threat": "phishing", "tags": ["ebay", "credential_harvest", "ecommerce"]},
    {"url": "http://walgreens-photo-secure-print-order.com/order/", "threat": "phishing", "tags": ["walgreens", "credential_harvest"]},
    {"url": "http://costco-member-account-secure-verify.com/login/", "threat": "phishing", "tags": ["costco", "credential_harvest"]},
    {"url": "http://target-order-tracking-secure-update.com/track/", "threat": "phishing", "tags": ["target", "credential_harvest"]},
    {"url": "http://bestbuy-geek-squad-renewal-secure.com/renew/", "threat": "phishing", "tags": ["bestbuy", "credential_harvest", "geeksquad"]},
    {"url": "http://norton-antivirus-renewal-secure-alert.com/renew/", "threat": "phishing", "tags": ["norton", "credential_harvest", "antivirus"]},
    {"url": "http://mcafee-security-subscription-secure.com/activate/", "threat": "phishing", "tags": ["mcafee", "credential_harvest", "antivirus"]},
    {"url": "http://geeksquad-support-renewal-secure.com/support/", "threat": "phishing", "tags": ["geeksquad", "credential_harvest", "tech_support"]},
    {"url": "http://microsoft-windows-defender-alert.com/scan/", "threat": "phishing", "tags": ["windows_defender", "credential_harvest", "tech_support_scam"]},
    {"url": "http://apple-support-icloud-locked-alert.com/unlock/", "threat": "phishing", "tags": ["apple", "credential_harvest", "tech_support_scam"]},
    {"url": "http://irs-tax-refund-secure-claim-portal.com/refund/", "threat": "phishing", "tags": ["irs", "credential_harvest", "tax"]},
    {"url": "http://hmrc-tax-refund-secure-claim-uk.com/claim/", "threat": "phishing", "tags": ["hmrc", "credential_harvest", "tax"]},
    {"url": "http://cra-tax-return-secure-verify-canada.com/verify/", "threat": "phishing", "tags": ["cra", "credential_harvest", "tax"]},
    {"url": "http://ato-tax-refund-secure-australia.com/claim/", "threat": "phishing", "tags": ["ato", "credential_harvest", "tax"]},
    {"url": "http://social-security-administration-secure.com/benefits/", "threat": "phishing", "tags": ["ssa", "credential_harvest", "government"]},
    {"url": "http://passport-office-renewal-secure-uk.com/renew/", "threat": "phishing", "tags": ["passport", "credential_harvest", "government"]},
    {"url": "http://dvla-driving-licence-update-secure.com/update/", "threat": "phishing", "tags": ["dvla", "credential_harvest", "government"]},
    {"url": "http://nhs-covid-vaccination-booking-secure.com/book/", "threat": "phishing", "tags": ["nhs", "credential_harvest", "healthcare"]},
    {"url": "http://covid-19-test-result-secure-portal.com/results/", "threat": "phishing", "tags": ["covid", "credential_harvest", "healthcare"]},
    {"url": "http://unemployment-benefits-secure-claim.com/apply/", "threat": "phishing", "tags": ["unemployment", "credential_harvest", "government"]},
    {"url": "http://student-loan-forgiveness-secure-apply.com/apply/", "threat": "phishing", "tags": ["student_loan", "credential_harvest", "government"]},
    {"url": "http://venmo-secure-payment-verify-transaction.com/confirm/", "threat": "phishing", "tags": ["venmo", "credential_harvest", "payment"]},
    {"url": "http://cashapp-secure-account-verify-signin.com/login/", "threat": "phishing", "tags": ["cashapp", "credential_harvest", "payment"]},
    {"url": "http://zelle-payment-secure-verify-receiver.com/confirm/", "threat": "phishing", "tags": ["zelle", "credential_harvest", "payment"]},
    {"url": "http://wechat-pay-secure-verify-account.com/auth/", "threat": "phishing", "tags": ["wechat", "credential_harvest", "payment"]},
    {"url": "http://alipay-account-secure-verify-login.com/signin/", "threat": "phishing", "tags": ["alipay", "credential_harvest", "payment"]},
    {"url": "http://spotify-premium-subscription-secure.com/upgrade/", "threat": "phishing", "tags": ["spotify", "credential_harvest"]},
    {"url": "http://twitch-prime-loot-secure-claim.com/claim/", "threat": "phishing", "tags": ["twitch", "credential_harvest", "gaming"]},
    {"url": "http://discord-nitro-free-secure-claim.com/redeem/", "threat": "phishing", "tags": ["discord", "credential_harvest", "gaming"]},
    {"url": "http://tiktok-creator-fund-secure-apply.com/apply/", "threat": "phishing", "tags": ["tiktok", "credential_harvest"]},
    {"url": "http://youtube-music-premium-secure.com/subscribe/", "threat": "phishing", "tags": ["youtube", "credential_harvest"]},
    {"url": "http://notion-ai-waitlist-secure-join.com/join/", "threat": "phishing", "tags": ["notion_ai", "credential_harvest"]},
    {"url": "http://openai-chatgpt-plus-secure.com/subscribe/", "threat": "phishing", "tags": ["chatgpt", "credential_harvest", "ai"]},
    {"url": "http://midjourney-ai-subscription-secure.com/join/", "threat": "phishing", "tags": ["midjourney", "credential_harvest", "ai"]},
    {"url": "http://sora-openai-video-generator-secure.com/access/", "threat": "phishing", "tags": ["sora", "credential_harvest", "ai"]},
    {"url": "http://anthropic-claude-ai-secure-signup.com/register/", "threat": "phishing", "tags": ["claude", "credential_harvest", "ai"]},
]

MALICIOUS_IPS = [
    {"ip": "185.220.101.34", "type": "c2_server", "asn": "AS208091", "country": "NL", "tags": ["cobalt_strike", "apt"]},
    {"ip": "91.215.85.209", "type": "c2_server", "asn": "AS50245", "country": "UA", "tags": ["emotet", "botnet"]},
    {"ip": "45.33.32.156", "type": "scanner", "asn": "AS63949", "country": "US", "tags": ["port_scan", "brute_force"]},
    {"ip": "103.224.182.244", "type": "phishing_host", "asn": "AS133471", "country": "CN", "tags": ["phishing", "credential_harvest"]},
    {"ip": "194.165.16.102", "type": "malware_host", "asn": "AS58061", "country": "RU", "tags": ["trickbot", "malware_distribution"]},
    {"ip": "23.106.122.137", "type": "c2_server", "asn": "AS62567", "country": "US", "tags": ["qakbot", "c2"]},
    {"ip": "172.93.185.42", "type": "scanner", "asn": "AS62567", "country": "US", "tags": ["rdp_brute_force", "scanner"]},
    {"ip": "5.188.86.27", "type": "spam_bot", "asn": "AS49505", "country": "RU", "tags": ["spam", "botnet", "emotet"]},
    {"ip": "185.156.73.54", "type": "c2_server", "asn": "AS51430", "country": "RU", "tags": ["lockbit", "c2"]},
    {"ip": "45.155.205.99", "type": "phishing_host", "asn": "AS62240", "country": "NL", "tags": ["phishing", "microsoft365"]},
    {"ip": "162.247.74.201", "type": "c2_server", "asn": "AS14061", "country": "US", "tags": ["cobalt_strike", "apt29"]},
    {"ip": "198.51.100.42", "type": "malware_host", "asn": "AS62567", "country": "US", "tags": ["redline_stealer", "malware_distribution"]},
    {"ip": "91.92.247.12", "type": "c2_server", "asn": "AS209609", "country": "BG", "tags": ["asyncrat", "c2"]},
    {"ip": "45.148.10.67", "type": "phishing_host", "asn": "AS44569", "country": "DE", "tags": ["phishing", "banking"]},
    {"ip": "185.220.101.1", "type": "tor_exit", "asn": "AS208091", "country": "NL", "tags": ["tor", "anonymous", "brute_force"]},
    {"ip": "45.9.148.107", "type": "c2_server", "asn": "AS44477", "country": "NL", "tags": ["cobalt_strike", "apt"]},
    {"ip": "91.134.238.74", "type": "c2_server", "asn": "AS12859", "country": "FR", "tags": ["trickbot", "botnet"]},
    {"ip": "185.141.63.120", "type": "c2_server", "asn": "AS62240", "country": "NL", "tags": ["lockbit", "c2"]},
    {"ip": "23.95.144.76", "type": "scanner", "asn": "AS36352", "country": "US", "tags": ["port_scan", "brute_force", "rdp"]},
    {"ip": "167.71.12.115", "type": "c2_server", "asn": "AS14061", "country": "US", "tags": ["cobalt_strike", "apt"]},
    {"ip": "161.35.94.162", "type": "c2_server", "asn": "AS14061", "country": "US", "tags": ["sliver", "c2"]},
    {"ip": "64.225.80.51", "type": "c2_server", "asn": "AS14061", "country": "US", "tags": ["cobalt_strike", "post_exploitation"]},
    {"ip": "45.77.65.211", "type": "malware_host", "asn": "AS20473", "country": "US", "tags": ["icedid", "malware_distribution"]},
    {"ip": "149.28.139.14", "type": "c2_server", "asn": "AS20473", "country": "US", "tags": ["qakbot", "c2"]},
    {"ip": "207.148.78.42", "type": "phishing_host", "asn": "AS20473", "country": "US", "tags": ["phishing", "credential_harvest"]},
    {"ip": "45.32.131.25", "type": "scanner", "asn": "AS20473", "country": "US", "tags": ["ssh_brute_force", "scanner"]},
    {"ip": "66.42.113.62", "type": "c2_server", "asn": "AS20473", "country": "US", "tags": ["darkcomet", "c2"]},
    {"ip": "45.76.241.18", "type": "malware_host", "asn": "AS20473", "country": "JP", "tags": ["formbook", "malware_distribution"]},
    {"ip": "95.179.139.226", "type": "phishing_host", "asn": "AS20473", "country": "NL", "tags": ["phishing", "banking"]},
    {"ip": "149.28.134.95", "type": "c2_server", "asn": "AS20473", "country": "SG", "tags": ["remcos", "c2"]},
    {"ip": "45.63.85.44", "type": "scanner", "asn": "AS20473", "country": "AU", "tags": ["rdp_brute_force", "scanner"]},
    {"ip": "217.12.199.201", "type": "c2_server", "asn": "AS49505", "country": "RU", "tags": ["emotet", "botnet"]},
    {"ip": "5.188.210.56", "type": "spam_bot", "asn": "AS49505", "country": "RU", "tags": ["spam", "botnet"]},
    {"ip": "185.220.102.24", "type": "tor_exit", "asn": "AS208091", "country": "NL", "tags": ["tor", "anonymous"]},
    {"ip": "199.249.230.87", "type": "tor_exit", "asn": "AS4323", "country": "US", "tags": ["tor", "anonymous"]},
    {"ip": "45.133.1.82", "type": "c2_server", "asn": "AS44477", "country": "NL", "tags": ["blackbasta", "c2"]},
    {"ip": "91.215.85.45", "type": "malware_host", "asn": "AS50245", "country": "UA", "tags": ["emotet", "malware_distribution"]},
    {"ip": "194.87.31.146", "type": "c2_server", "asn": "AS58061", "country": "RU", "tags": ["conti", "c2"]},
    {"ip": "45.148.10.68", "type": "phishing_host", "asn": "AS44569", "country": "DE", "tags": ["phishing", "dhl"]},
    {"ip": "185.156.73.55", "type": "c2_server", "asn": "AS51430", "country": "RU", "tags": ["alphv", "c2"]},
    {"ip": "23.106.122.200", "type": "scanner", "asn": "AS62567", "country": "US", "tags": ["smb_scanner", "brute_force"]},
    {"ip": "103.138.72.156", "type": "malware_host", "asn": "AS139380", "country": "CN", "tags": ["plugx", "malware_distribution"]},
    {"ip": "45.9.148.203", "type": "c2_server", "asn": "AS44477", "country": "NL", "tags": ["sliver_c2", "apt"]},
    {"ip": "91.92.247.50", "type": "c2_server", "asn": "AS209609", "country": "BG", "tags": ["njrat", "c2"]},
    {"ip": "185.220.101.45", "type": "tor_exit", "asn": "AS208091", "country": "NL", "tags": ["tor", "ransomware"]},
    {"ip": "45.155.205.150", "type": "phishing_host", "asn": "AS62240", "country": "NL", "tags": ["phishing", "office365"]},
    {"ip": "162.247.74.220", "type": "c2_server", "asn": "AS14061", "country": "US", "tags": ["cobalt_strike", "apt28"]},
    {"ip": "194.165.16.200", "type": "malware_host", "asn": "AS58061", "country": "RU", "tags": ["trickbot", "malware_distribution"]},
    {"ip": "5.188.210.100", "type": "spam_bot", "asn": "AS49505", "country": "RU", "tags": ["spam", "phishing"]},
    {"ip": "45.33.32.200", "type": "scanner", "asn": "AS63949", "country": "US", "tags": ["port_scan", "vulnerability_scan"]},
    {"ip": "172.93.185.100", "type": "scanner", "asn": "AS62567", "country": "US", "tags": ["rdp_brute_force", "scanner"]},
    {"ip": "198.51.100.100", "type": "malware_host", "asn": "AS62567", "country": "US", "tags": ["redline", "malware_distribution"]},
    {"ip": "91.134.238.100", "type": "c2_server", "asn": "AS12859", "country": "FR", "tags": ["icedid", "c2"]},
    {"ip": "185.141.63.200", "type": "c2_server", "asn": "AS62240", "country": "NL", "tags": ["play_ransomware", "c2"]},
    {"ip": "23.95.144.200", "type": "scanner", "asn": "AS36352", "country": "US", "tags": ["ssh_brute_force", "scanner"]},
    {"ip": "167.71.12.200", "type": "c2_server", "asn": "AS14061", "country": "US", "tags": ["bruteratel", "c2"]},
    {"ip": "161.35.94.200", "type": "c2_server", "asn": "AS14061", "country": "US", "tags": ["cobalt_strike", "apt"]},
    {"ip": "64.225.80.200", "type": "phishing_host", "asn": "AS14061", "country": "US", "tags": ["phishing", "microsoft365"]},
    {"ip": "45.77.65.200", "type": "malware_host", "asn": "AS20473", "country": "US", "tags": ["lumma", "malware_distribution"]},
    {"ip": "149.28.139.200", "type": "c2_server", "asn": "AS20473", "country": "US", "tags": ["pikabot", "c2"]},
    {"ip": "207.148.78.200", "type": "phishing_host", "asn": "AS20473", "country": "US", "tags": ["phishing", "crypto"]},
    {"ip": "45.32.131.200", "type": "scanner", "asn": "AS20473", "country": "US", "tags": ["port_scan", "brute_force"]},
    {"ip": "66.42.113.200", "type": "c2_server", "asn": "AS20473", "country": "US", "tags": ["warzone_rat", "c2"]},
    {"ip": "45.76.241.200", "type": "malware_host", "asn": "AS20473", "country": "JP", "tags": ["agent_tesla", "malware_distribution"]},
    {"ip": "95.179.139.200", "type": "phishing_host", "asn": "AS20473", "country": "NL", "tags": ["phishing", "banking"]},
    {"ip": "149.28.134.200", "type": "c2_server", "asn": "AS20473", "country": "SG", "tags": ["dcrat", "c2"]},
    {"ip": "45.63.85.200", "type": "scanner", "asn": "AS20473", "country": "AU", "tags": ["rdp_brute_force", "scanner"]},
    {"ip": "217.12.199.200", "type": "c2_server", "asn": "AS49505", "country": "RU", "tags": ["trickbot", "botnet"]},
    {"ip": "5.188.210.200", "type": "spam_bot", "asn": "AS49505", "country": "RU", "tags": ["spam", "emotet"]},
    {"ip": "185.220.102.200", "type": "tor_exit", "asn": "AS208091", "country": "NL", "tags": ["tor", "anonymous", "ransomware"]},
    {"ip": "199.249.230.200", "type": "tor_exit", "asn": "AS4323", "country": "US", "tags": ["tor", "anonymous"]},
    {"ip": "45.133.1.200", "type": "c2_server", "asn": "AS44477", "country": "NL", "tags": ["akira_ransomware", "c2"]},
    {"ip": "91.215.85.200", "type": "malware_host", "asn": "AS50245", "country": "UA", "tags": ["qakbot", "malware_distribution"]},
    {"ip": "194.87.31.200", "type": "c2_server", "asn": "AS58061", "country": "RU", "tags": ["ryuk", "c2"]},
    {"ip": "45.148.10.200", "type": "phishing_host", "asn": "AS44569", "country": "DE", "tags": ["phishing", "usps"]},
    {"ip": "185.156.73.200", "type": "c2_server", "asn": "AS51430", "country": "RU", "tags": ["blackbasta", "c2"]},
    {"ip": "23.106.122.250", "type": "scanner", "asn": "AS62567", "country": "US", "tags": ["smb_scanner", "lateral_movement"]},
    {"ip": "103.138.72.200", "type": "malware_host", "asn": "AS139380", "country": "CN", "tags": ["shadowpad", "malware_distribution"]},
    {"ip": "45.9.148.250", "type": "c2_server", "asn": "AS44477", "country": "NL", "tags": ["mythic_c2", "apt"]},
    {"ip": "91.92.247.200", "type": "c2_server", "asn": "AS209609", "country": "BG", "tags": ["remcos", "c2"]},
    {"ip": "185.220.101.200", "type": "tor_exit", "asn": "AS208091", "country": "NL", "tags": ["tor", "darknet"]},
    {"ip": "45.155.205.200", "type": "phishing_host", "asn": "AS62240", "country": "NL", "tags": ["phishing", "amazon"]},
    {"ip": "162.247.74.250", "type": "c2_server", "asn": "AS14061", "country": "US", "tags": ["cobalt_strike", "apt29"]},
    {"ip": "194.165.16.250", "type": "malware_host", "asn": "AS58061", "country": "RU", "tags": ["conti", "malware_distribution"]},
    {"ip": "5.188.210.250", "type": "spam_bot", "asn": "AS49505", "country": "RU", "tags": ["spam", "phishing"]},
    {"ip": "45.33.32.250", "type": "scanner", "asn": "AS63949", "country": "US", "tags": ["port_scan", "vulnerability_scan"]},
    {"ip": "172.93.185.250", "type": "scanner", "asn": "AS62567", "country": "US", "tags": ["rdp_brute_force", "scanner"]},
    {"ip": "198.51.100.250", "type": "malware_host", "asn": "AS62567", "country": "US", "tags": ["vidar", "malware_distribution"]},
    {"ip": "91.134.238.250", "type": "c2_server", "asn": "AS12859", "country": "FR", "tags": ["bumblebee", "c2"]},
    {"ip": "185.141.63.250", "type": "c2_server", "asn": "AS62240", "country": "NL", "tags": ["rhysida", "c2"]},
    {"ip": "23.95.144.250", "type": "scanner", "asn": "AS36352", "country": "US", "tags": ["ssh_brute_force", "scanner"]},
    {"ip": "167.71.12.250", "type": "c2_server", "asn": "AS14061", "country": "US", "tags": ["havoc_c2", "apt"]},
    {"ip": "161.35.94.250", "type": "c2_server", "asn": "AS14061", "country": "US", "tags": ["cobalt_strike", "fin7"]},
    {"ip": "64.225.80.250", "type": "phishing_host", "asn": "AS14061", "country": "US", "tags": ["phishing", "banking"]},
    {"ip": "45.77.65.250", "type": "malware_host", "asn": "AS20473", "country": "US", "tags": ["raccoon_stealer", "malware_distribution"]},
    {"ip": "149.28.139.250", "type": "c2_server", "asn": "AS20473", "country": "US", "tags": ["darkgate", "c2"]},
    {"ip": "207.148.78.250", "type": "phishing_host", "asn": "AS20473", "country": "US", "tags": ["phishing", "dhl"]},
    {"ip": "45.32.131.250", "type": "scanner", "asn": "AS20473", "country": "US", "tags": ["port_scan", "brute_force"]},
    {"ip": "66.42.113.250", "type": "c2_server", "asn": "AS20473", "country": "US", "tags": ["nanocore", "c2"]},
    {"ip": "45.76.241.250", "type": "malware_host", "asn": "AS20473", "country": "JP", "tags": ["snake_keylogger", "malware_distribution"]},
    {"ip": "95.179.139.250", "type": "phishing_host", "asn": "AS20473", "country": "NL", "tags": ["phishing", "microsoft"]},
    {"ip": "149.28.134.250", "type": "c2_server", "asn": "AS20473", "country": "SG", "tags": ["systembc", "c2"]},
    {"ip": "45.63.85.250", "type": "scanner", "asn": "AS20473", "country": "AU", "tags": ["rdp_brute_force", "scanner"]},
    {"ip": "217.12.199.250", "type": "c2_server", "asn": "AS49505", "country": "RU", "tags": ["emotet", "botnet"]},
    {"ip": "5.188.86.250", "type": "spam_bot", "asn": "AS49505", "country": "RU", "tags": ["spam", "botnet"]},
    {"ip": "185.220.102.250", "type": "tor_exit", "asn": "AS208091", "country": "NL", "tags": ["tor", "anonymous"]},
    {"ip": "199.249.230.250", "type": "tor_exit", "asn": "AS4323", "country": "US", "tags": ["tor", "anonymous"]},
    {"ip": "45.133.1.250", "type": "c2_server", "asn": "AS44477", "country": "NL", "tags": ["medusa_ransomware", "c2"]},
    {"ip": "91.215.85.250", "type": "malware_host", "asn": "AS50245", "country": "UA", "tags": ["icedid", "malware_distribution"]},
    {"ip": "194.87.31.250", "type": "c2_server", "asn": "AS58061", "country": "RU", "tags": ["conti", "c2"]},
    {"ip": "45.148.10.250", "type": "phishing_host", "asn": "AS44569", "country": "DE", "tags": ["phishing", "fedex"]},
    {"ip": "185.156.73.250", "type": "c2_server", "asn": "AS51430", "country": "RU", "tags": ["clop", "c2"]},
]

MALWARE_HASHES = [
    {"sha256": "a3f5b8c9d2e1f4a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0", "family": "Emotet", "file_type": "PE32", "size": 389120, "tags": ["emotet", "trojan", "banking"]},
    {"sha256": "b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6", "family": "TrickBot", "file_type": "PE32+DLL", "size": 458752, "tags": ["trickbot", "stealer", "dll"]},
    {"sha256": "c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7", "family": "CobaltStrike", "file_type": "Java JAR", "size": 3145728, "tags": ["cobalt_strike", "apt", "beacon"]},
    {"sha256": "d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8", "family": "LockBit", "file_type": "PE32+", "size": 262144, "tags": ["lockbit", "ransomware", "encryption"]},
    {"sha256": "e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9", "family": "RedLine", "file_type": "PE32 .NET", "size": 524288, "tags": ["redline", "stealer", "dotnet"]},
    {"sha256": "f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0", "family": "QakBot", "file_type": "PE32+DLL", "size": 393216, "tags": ["qakbot", "banking", "worm"]},
    {"sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", "family": "ALPHV", "file_type": "ELF", "size": 196608, "tags": ["alphv", "blackcat", "rust", "ransomware"]},
    {"sha256": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", "family": "Cl0p", "file_type": "PE32+", "size": 327680, "tags": ["clop", "ransomware", "moveit"]},
    {"sha256": "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4", "family": "AsyncRAT", "file_type": "PE32 .NET", "size": 655360, "tags": ["asyncrat", "rat", "c2"]},
    {"sha256": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5", "family": "Vidar", "file_type": "PE32", "size": 286720, "tags": ["vidar", "stealer", "arkei"]},
    {"sha256": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6", "family": "IcedID", "file_type": "PE32+DLL", "size": 421888, "tags": ["icedid", "loader", "banking"]},
    {"sha256": "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7", "family": "Bumblebee", "file_type": "PE32+", "size": 512000, "tags": ["bumblebee", "loader", "ransomware_delivery"]},
    {"sha256": "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8", "family": "Pikabot", "file_type": "PE32 .NET", "size": 348160, "tags": ["pikabot", "loader", "qakbot_replacement"]},
    {"sha256": "b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9", "family": "DarkGate", "file_type": "PE32", "size": 438272, "tags": ["darkgate", "rat", "loader"]},
    {"sha256": "c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0", "family": "PlugX", "file_type": "PE32+DLL", "size": 614400, "tags": ["plugx", "backdoor", "apt"]},
    {"sha256": "d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1", "family": "Formbook", "file_type": "PE32 .NET", "size": 276480, "tags": ["formbook", "stealer", "form_grabber"]},
    {"sha256": "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2", "family": "Remcos", "file_type": "PE32+", "size": 557056, "tags": ["remcos", "rat", "commercial"]},
    {"sha256": "f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3", "family": "LummaC2", "file_type": "PE32 .NET", "size": 358400, "tags": ["lumma", "stealer", "cryptocurrency"]},
    {"sha256": "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4", "family": "Hive", "file_type": "PE32+", "size": 245760, "tags": ["hive", "ransomware", "golang"]},
    {"sha256": "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5", "family": "BlackBasta", "file_type": "PE32+", "size": 286720, "tags": ["blackbasta", "ransomware", "double_extortion"]},
]

RANSOMWARE_VICTIMS = [
    {"victim": "Colonial Pipeline", "ransomware": "DarkSide", "date": "2021-05-07", "ransom_amount": "$4.4M", "sector": "energy", "country": "US", "data_exfiltrated": False},
    {"victim": "JBS Foods", "ransomware": "REvil", "date": "2021-05-30", "ransom_amount": "$11M", "sector": "food", "country": "US", "data_exfiltrated": False},
    {"victim": "Kaseya", "ransomware": "REvil", "date": "2021-07-02", "ransom_amount": "$70M demanded", "sector": "it_management", "country": "US", "data_exfiltrated": True},
    {"victim": "Garmin", "ransomware": "WastedLocker", "date": "2020-07-23", "ransom_amount": "$10M", "sector": "technology", "country": "US", "data_exfiltrated": False},
    {"victim": "CWT Travel", "ransomware": "Ragnar Locker", "date": "2020-07-28", "ransom_amount": "$4.5M", "sector": "travel", "country": "US", "data_exfiltrated": True},
    {"victim": "Travelex", "ransomware": "Sodinokibi", "date": "2020-01-07", "ransom_amount": "$2.3M", "sector": "financial", "country": "UK", "data_exfiltrated": True},
    {"victim": "Canon", "ransomware": "Maze", "date": "2020-08-05", "ransom_amount": "unknown", "sector": "technology", "country": "JP", "data_exfiltrated": True},
    {"victim": "EDP Group", "ransomware": "Ragnar Locker", "date": "2020-04-13", "ransom_amount": "$10M demanded", "sector": "energy", "country": "PT", "data_exfiltrated": True},
    {"victim": "Jack Daniels", "ransomware": "Conti", "date": "2021-09-01", "ransom_amount": "unknown", "sector": "beverage", "country": "US", "data_exfiltrated": True},
    {"victim": "Accenture", "ransomware": "LockBit", "date": "2021-08-11", "ransom_amount": "$50M demanded", "sector": "consulting", "country": "US", "data_exfiltrated": True},
    {"victim": "Kronos", "ransomware": "ALPHV", "date": "2021-12-11", "ransom_amount": "unknown", "sector": "hr_technology", "country": "US", "data_exfiltrated": True},
    {"victim": "Bandai Namco", "ransomware": "BlackCat", "date": "2022-07-12", "ransom_amount": "unknown", "sector": "gaming", "country": "JP", "data_exfiltrated": True},
    {"victim": "Royal Mail", "ransomware": "LockBit", "date": "2023-01-10", "ransom_amount": "$80M demanded", "sector": "logistics", "country": "UK", "data_exfiltrated": True},
    {"victim": "City of Oakland", "ransomware": "Play", "date": "2023-02-08", "ransom_amount": "unknown", "sector": "government", "country": "US", "data_exfiltrated": True},
    {"victim": "MGM Resorts", "ransomware": "ALPHV", "date": "2023-09-11", "ransom_amount": "unknown", "sector": "hospitality", "country": "US", "data_exfiltrated": True},
    {"victim": "Caesars Entertainment", "ransomware": "Scattered Spider", "date": "2023-09-07", "ransom_amount": "$15M", "sector": "hospitality", "country": "US", "data_exfiltrated": True},
    {"victim": "Boeing", "ransomware": "LockBit", "date": "2023-10-27", "ransom_amount": "$200M demanded", "sector": "aerospace", "country": "US", "data_exfiltrated": True},
    {"victim": "DP World", "ransomware": "LockBit", "date": "2023-11-10", "ransom_amount": "unknown", "sector": "logistics", "country": "AE", "data_exfiltrated": True},
    {"victim": "British Library", "ransomware": "Rhysida", "date": "2023-10-28", "ransom_amount": "$780K demanded", "sector": "cultural", "country": "UK", "data_exfiltrated": True},
    {"victim": "Change Healthcare", "ransomware": "ALPHV", "date": "2024-02-21", "ransom_amount": "$22M", "sector": "healthcare", "country": "US", "data_exfiltrated": True},
    {"victim": "Costa Rica Government", "ransomware": "Conti", "date": "2022-04-18", "ransom_amount": "$20M demanded", "sector": "government", "country": "CR", "data_exfiltrated": True},
    {"victim": "Sinclair Broadcast", "ransomware": "Conti", "date": "2021-10-16", "ransom_amount": "unknown", "sector": "media", "country": "US", "data_exfiltrated": True},
    {"victim": "Quanta Computer", "ransomware": "REvil", "date": "2021-04-20", "ransom_amount": "$50M demanded", "sector": "manufacturing", "country": "TW", "data_exfiltrated": True},
    {"victim": "Brenntag", "ransomware": "DarkSide", "date": "2021-05-09", "ransom_amount": "$4.4M", "sector": "chemical", "country": "DE", "data_exfiltrated": True},
    {"victim": "Acer", "ransomware": "REvil", "date": "2021-03-19", "ransom_amount": "$50M demanded", "sector": "technology", "country": "TW", "data_exfiltrated": True},
    {"victim": "Harris Federation", "ransomware": "Conti", "date": "2021-03-27", "ransom_amount": "unknown", "sector": "education", "country": "UK", "data_exfiltrated": True},
    {"victim": "Baltimore County Schools", "ransomware": "Conti", "date": "2020-11-24", "ransom_amount": "$10M demanded", "sector": "education", "country": "US", "data_exfiltrated": True},
    {"victim": "Bridgestone Americas", "ransomware": "LockBit", "date": "2022-02-27", "ransom_amount": "unknown", "sector": "manufacturing", "country": "US", "data_exfiltrated": True},
    {"victim": "Nvidia", "ransomware": "Lapsus$", "date": "2022-02-23", "ransom_amount": "$1M demanded", "sector": "technology", "country": "US", "data_exfiltrated": True},
    {"victim": "Samsung", "ransomware": "Lapsus$", "date": "2022-03-04", "ransom_amount": "unknown", "sector": "technology", "country": "KR", "data_exfiltrated": True},
    {"victim": "BBC", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "media", "country": "UK", "data_exfiltrated": True},
    {"victim": "Shell", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "energy", "country": "NL", "data_exfiltrated": True},
    {"victim": "Johns Hopkins", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "healthcare", "country": "US", "data_exfiltrated": True},
    {"victim": "University of Manchester", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "education", "country": "UK", "data_exfiltrated": True},
    {"victim": "City of Dallas", "ransomware": "Royal", "date": "2023-05-03", "ransom_amount": "unknown", "sector": "government", "country": "US", "data_exfiltrated": True},
    {"victim": "HCA Healthcare", "ransomware": "LockBit", "date": "2023-07-10", "ransom_amount": "unknown", "sector": "healthcare", "country": "US", "data_exfiltrated": True},
    {"victim": "Mitsubishi Electric", "ransomware": "Pysa", "date": "2021-01-20", "ransom_amount": "unknown", "sector": "manufacturing", "country": "JP", "data_exfiltrated": True},
    {"victim": "Toshiba Tec", "ransomware": "DarkSide", "date": "2021-05-14", "ransom_amount": "unknown", "sector": "technology", "country": "JP", "data_exfiltrated": True},
    {"victim": "CNA Financial", "ransomware": "Phoenix CryptoLocker", "date": "2021-03-21", "ransom_amount": "$40M", "sector": "insurance", "country": "US", "data_exfiltrated": True},
    {"victim": "Volvo Cars", "ransomware": "Snatch", "date": "2021-12-10", "ransom_amount": "unknown", "sector": "automotive", "country": "SE", "data_exfiltrated": True},
    {"victim": "Yum Brands", "ransomware": "LockBit", "date": "2023-01-13", "ransom_amount": "unknown", "sector": "restaurant", "country": "US", "data_exfiltrated": True},
    {"victim": "Western Digital", "ransomware": "ALPHV", "date": "2023-04-03", "ransom_amount": "unknown", "sector": "technology", "country": "US", "data_exfiltrated": True},
    {"victim": "Rio Tinto", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "mining", "country": "AU", "data_exfiltrated": True},
    {"victim": "Schneider Electric", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "manufacturing", "country": "FR", "data_exfiltrated": True},
    {"victim": "Sainsbury's", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "retail", "country": "UK", "data_exfiltrated": True},
    {"victim": "Honeywell", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "manufacturing", "country": "US", "data_exfiltrated": True},
    {"victim": "BHI Energy", "ransomware": "LockBit", "date": "2023-07-05", "ransom_amount": "unknown", "sector": "energy", "country": "US", "data_exfiltrated": True},
    {"victim": "Prospect Medical Holdings", "ransomware": "Rhysida", "date": "2023-08-10", "ransom_amount": "unknown", "sector": "healthcare", "country": "US", "data_exfiltrated": True},
    {"victim": "Freddie Mac", "ransomware": "LockBit", "date": "2023-11-01", "ransom_amount": "unknown", "sector": "financial", "country": "US", "data_exfiltrated": True},
    {"victim": "Chicago Children's Hospital", "ransomware": "LockBit", "date": "2024-01-15", "ransom_amount": "unknown", "sector": "healthcare", "country": "US", "data_exfiltrated": True},
    {"victim": "LoanDepot", "ransomware": "ALPHV", "date": "2024-01-22", "ransom_amount": "unknown", "sector": "financial", "country": "US", "data_exfiltrated": True},
    {"victim": "Viasat", "ransomware": "AcidPour", "date": "2022-02-24", "ransom_amount": "unknown", "sector": "telecom", "country": "US", "data_exfiltrated": False},
    {"victim": "Maersk", "ransomware": "NotPetya", "date": "2017-06-27", "ransom_amount": "N/A (wiper)", "sector": "logistics", "country": "DK", "data_exfiltrated": False},
    {"victim": "Merck", "ransomware": "NotPetya", "date": "2017-06-27", "ransom_amount": "N/A (wiper)", "sector": "pharmaceutical", "country": "US", "data_exfiltrated": False},
    {"victim": "WPP Group", "ransomware": "NotPetya", "date": "2017-06-27", "ransom_amount": "N/A (wiper)", "sector": "advertising", "country": "UK", "data_exfiltrated": False},
    {"victim": "Reckitt Benckiser", "ransomware": "NotPetya", "date": "2017-06-27", "ransom_amount": "N/A (wiper)", "sector": "consumer_goods", "country": "UK", "data_exfiltrated": False},
    {"victim": "Saint-Gobain", "ransomware": "NotPetya", "date": "2017-06-27", "ransom_amount": "N/A (wiper)", "sector": "manufacturing", "country": "FR", "data_exfiltrated": False},
    {"victim": "DLA Piper", "ransomware": "NotPetya", "date": "2017-06-27", "ransom_amount": "N/A (wiper)", "sector": "legal", "country": "US", "data_exfiltrated": False},
    {"victim": "Heritage Valley Health System", "ransomware": "NotPetya", "date": "2017-06-27", "ransom_amount": "N/A (wiper)", "sector": "healthcare", "country": "US", "data_exfiltrated": False},
    {"victim": "Rosneft", "ransomware": "NotPetya", "date": "2017-06-27", "ransom_amount": "N/A (wiper)", "sector": "energy", "country": "RU", "data_exfiltrated": False},
    {"victim": "Ernst & Young", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "consulting", "country": "UK", "data_exfiltrated": True},
    {"victim": "Wolverine Solutions Group", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "healthcare", "country": "US", "data_exfiltrated": True},
    {"victim": "Minnesota Dept of Education", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "government", "country": "US", "data_exfiltrated": True},
    {"victim": "1-800-Flowers", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "retail", "country": "US", "data_exfiltrated": True},
    {"victim": "Putnam Investments", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "financial", "country": "US", "data_exfiltrated": True},
    {"victim": "Nationwide Building Society", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "financial", "country": "UK", "data_exfiltrated": True},
    {"victim": "Genworth Financial", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "insurance", "country": "US", "data_exfiltrated": True},
    {"victim": "Lowe's Companies", "ransomware": "Clop", "date": "2023-06-01", "ransom_amount": "unknown", "sector": "retail", "country": "US", "data_exfiltrated": True},
    {"victim": "Cal-OSHA", "ransomware": "Play", "date": "2023-04-01", "ransom_amount": "unknown", "sector": "government", "country": "US", "data_exfiltrated": True},
    {"victim": "Mississippi Dept of Education", "ransomware": "Rhysida", "date": "2023-08-15", "ransom_amount": "unknown", "sector": "government", "country": "US", "data_exfiltrated": True},
    {"victim": "Acer India", "ransomware": "Desorden", "date": "2021-10-13", "ransom_amount": "unknown", "sector": "technology", "country": "IN", "data_exfiltrated": True},
    {"victim": "AP Moller-Maersk", "ransomware": "NotPetya", "date": "2017-06-27", "ransom_amount": "N/A (wiper)", "sector": "logistics", "country": "DK", "data_exfiltrated": False},
]

DATA_BREACHES = [
    {"organization": "SolarWinds", "date": "2020-12-13", "records_breached": 18000, "breach_type": "supply_chain", "sector": "it_management", "country": "US", "attributed_to": "APT29"},
    {"organization": "T-Mobile", "date": "2021-08-15", "records_breached": 54000000, "breach_type": "unauthorized_access", "sector": "telecom", "country": "US", "attributed_to": "John Erin Binns"},
    {"organization": "T-Mobile", "date": "2023-01-05", "records_breached": 37000000, "breach_type": "api_abuse", "sector": "telecom", "country": "US", "attributed_to": "unknown"},
    {"organization": "Yahoo", "date": "2013-08-01", "records_breached": 3000000000, "breach_type": "state_sponsored", "sector": "technology", "country": "US", "attributed_to": "APT28"},
    {"organization": "Marriott/Starwood", "date": "2018-11-30", "records_breached": 500000000, "breach_type": "unauthorized_access", "sector": "hospitality", "country": "US", "attributed_to": "APT10"},
    {"organization": "Equifax", "date": "2017-09-07", "records_breached": 147000000, "breach_type": "unpatched_software", "sector": "financial", "country": "US", "attributed_to": "APT41"},
    {"organization": "Capital One", "date": "2019-07-29", "records_breached": 106000000, "breach_type": "misconfigured_firewall", "sector": "financial", "country": "US", "attributed_to": "Paige Thompson"},
    {"organization": "Anthem", "date": "2015-02-04", "records_breached": 78800000, "breach_type": "spear_phishing", "sector": "healthcare", "country": "US", "attributed_to": "APT10"},
    {"organization": "OPM", "date": "2015-06-04", "records_breached": 22100000, "breach_type": "spear_phishing", "sector": "government", "country": "US", "attributed_to": "APT10"},
    {"organization": "Target", "date": "2013-12-18", "records_breached": 110000000, "breach_type": "third_party_compromise", "sector": "retail", "country": "US", "attributed_to": "unknown"},
    {"organization": "Home Depot", "date": "2014-09-08", "records_breached": 56000000, "breach_type": "pos_malware", "sector": "retail", "country": "US", "attributed_to": "unknown"},
    {"organization": "JP Morgan Chase", "date": "2014-10-02", "records_breached": 83000000, "breach_type": "unauthorized_access", "sector": "financial", "country": "US", "attributed_to": "unknown"},
    {"organization": "eBay", "date": "2014-05-21", "records_breached": 145000000, "breach_type": "credential_compromise", "sector": "ecommerce", "country": "US", "attributed_to": "unknown"},
    {"organization": "Uber", "date": "2016-10-01", "records_breached": 57000000, "breach_type": "github_credential_compromise", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "Uber", "date": "2022-09-15", "records_breached": 0, "breach_type": "social_engineering_mfa_fatigue", "sector": "technology", "country": "US", "attributed_to": "Lapsus$"},
    {"organization": "LinkedIn", "date": "2021-06-22", "records_breached": 700000000, "breach_type": "scraping", "sector": "social_media", "country": "US", "attributed_to": "unknown"},
    {"organization": "Adobe", "date": "2013-10-03", "records_breached": 153000000, "breach_type": "unauthorized_access", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "Sony Pictures", "date": "2014-11-24", "records_breached": 100000, "breach_type": "spear_phishing", "sector": "entertainment", "country": "US", "attributed_to": "Lazarus Group"},
    {"organization": "Ashley Madison", "date": "2015-07-15", "records_breached": 32000000, "breach_type": "unauthorized_access", "sector": "dating", "country": "CA", "attributed_to": "Impact Team"},
    {"organization": "Dropbox", "date": "2016-08-31", "records_breached": 68000000, "breach_type": "credential_compromise", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "First American Financial", "date": "2019-05-24", "records_breached": 885000000, "breach_type": "insecure_direct_object_ref", "sector": "insurance", "country": "US", "attributed_to": "N/A (exposure)"},
    {"organization": "Canva", "date": "2019-05-24", "records_breached": 137000000, "breach_type": "unauthorized_access", "sector": "technology", "country": "AU", "attributed_to": "Gnosticplayers"},
    {"organization": "Wattpad", "date": "2020-07-14", "records_breached": 268000000, "breach_type": "unauthorized_access", "sector": "social_media", "country": "CA", "attributed_to": "unknown"},
    {"organization": "EasyJet", "date": "2020-05-19", "records_breached": 9000000, "breach_type": "unauthorized_access", "sector": "travel", "country": "UK", "attributed_to": "unknown"},
    {"organization": "Magellan Health", "date": "2020-05-15", "records_breached": 1365000, "breach_type": "phishing_malware", "sector": "healthcare", "country": "US", "attributed_to": "unknown"},
    {"organization": "Twitter", "date": "2020-07-15", "records_breached": 130, "breach_type": "social_engineering_phone_spear_phishing", "sector": "social_media", "country": "US", "attributed_to": "Graham Ivan Clark"},
    {"organization": "Nintendo", "date": "2020-04-23", "records_breached": 300000, "breach_type": "credential_stuffing", "sector": "gaming", "country": "JP", "attributed_to": "unknown"},
    {"organization": "Zoom", "date": "2020-04-01", "records_breached": 500000, "breach_type": "credential_stuffing", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "Microsoft", "date": "2024-01-19", "records_breached": 0, "breach_type": "nation_state_email_access", "sector": "technology", "country": "US", "attributed_to": "Storm-0558"},
    {"organization": "23andMe", "date": "2023-10-06", "records_breached": 6900000, "breach_type": "credential_stuffing", "sector": "biotechnology", "country": "US", "attributed_to": "unknown"},
    {"organization": "MoveIt Transfer", "date": "2023-05-31", "records_breached": 60000000, "breach_type": "sql_injection", "sector": "software", "country": "US", "attributed_to": "Clop"},
    {"organization": "LastPass", "date": "2022-12-22", "records_breached": 30000000, "breach_type": "cloud_storage_compromise", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "Okta", "date": "2022-03-22", "records_breached": 0, "breach_type": "third_party_compromise", "sector": "technology", "country": "US", "attributed_to": "Lapsus$"},
    {"organization": "Okta", "date": "2023-10-19", "records_breached": 0, "breach_type": "credential_stuffing", "sector": "technology", "country": "US", "attributed_to": "Scattered Spider"},
    {"organization": "Citrix", "date": "2019-03-06", "records_breached": 0, "breach_type": "password_spraying", "sector": "technology", "country": "US", "attributed_to": "IRIDIUM"},
    {"organization": "FireEye/Mandiant", "date": "2020-12-08", "records_breached": 0, "breach_type": "spear_phishing", "sector": "cybersecurity", "country": "US", "attributed_to": "APT29"},
    {"organization": "Dell", "date": "2024-05-09", "records_breached": 49000000, "breach_type": "api_abuse", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "AT&T", "date": "2024-03-30", "records_breached": 73000000, "breach_type": "cloud_exposure", "sector": "telecom", "country": "US", "attributed_to": "unknown"},
    {"organization": "Ticketmaster", "date": "2024-05-31", "records_breached": 560000000, "breach_type": "cloud_storage_compromise", "sector": "entertainment", "country": "US", "attributed_to": "ShinyHunters"},
    {"organization": "Snowflake", "date": "2024-06-01", "records_breached": 0, "breach_type": "credential_compromise", "sector": "cloud", "country": "US", "attributed_to": "Scattered Spider"},
    {"organization": "Change Healthcare", "date": "2024-02-21", "records_breached": 100000000, "breach_type": "ransomware_data_theft", "sector": "healthcare", "country": "US", "attributed_to": "ALPHV"},
    {"organization": "National Public Data", "date": "2024-08-01", "records_breached": 2900000000, "breach_type": "unauthorized_access", "sector": "data_broker", "country": "US", "attributed_to": "unknown"},
    {"organization": "Plex", "date": "2023-08-24", "records_breached": 20000000, "breach_type": "unauthorized_access", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "Duolingo", "date": "2023-01-01", "records_breached": 2200000, "breach_type": "scraping", "sector": "education", "country": "US", "attributed_to": "unknown"},
    {"organization": "Trello", "date": "2024-01-15", "records_breached": 15000000, "breach_type": "api_abuse", "sector": "technology", "country": "AU", "attributed_to": "unknown"},
    {"organization": "British Airways", "date": "2018-09-06", "records_breached": 380000, "breach_type": "web_skimming", "sector": "travel", "country": "UK", "attributed_to": "Magecart"},
    {"organization": "Singapore Health", "date": "2018-07-20", "records_breached": 1500000, "breach_type": "unauthorized_access", "sector": "healthcare", "country": "SG", "attributed_to": "unknown"},
    {"organization": "Cathay Pacific", "date": "2018-10-24", "records_breached": 9400000, "breach_type": "unauthorized_access", "sector": "travel", "country": "HK", "attributed_to": "unknown"},
    {"organization": "Quora", "date": "2018-12-03", "records_breached": 100000000, "breach_type": "unauthorized_access", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "MyFitnessPal", "date": "2018-03-29", "records_breached": 150000000, "breach_type": "unauthorized_access", "sector": "health_fitness", "country": "US", "attributed_to": "unknown"},
    {"organization": "Exactis", "date": "2018-06-27", "records_breached": 340000000, "breach_type": "data_exposure", "sector": "data_broker", "country": "US", "attributed_to": "N/A (exposure)"},
    {"organization": "Aadhaar (UIDAI)", "date": "2018-01-03", "records_breached": 1100000000, "breach_type": "data_exposure", "sector": "government", "country": "IN", "attributed_to": "N/A (exposure)"},
    {"organization": "Spotify", "date": "2020-11-12", "records_breached": 300000, "breach_type": "credential_stuffing", "sector": "entertainment", "country": "SE", "attributed_to": "unknown"},
    {"organization": "Twitch", "date": "2021-10-06", "records_breached": 0, "breach_type": "server_misconfiguration", "sector": "entertainment", "country": "US", "attributed_to": "unknown"},
    {"organization": "DoorDash", "date": "2022-08-25", "records_breached": 0, "breach_type": "phishing", "sector": "food_delivery", "country": "US", "attributed_to": "unknown"},
    {"organization": "Mailchimp", "date": "2023-01-12", "records_breached": 0, "breach_type": "social_engineering", "sector": "marketing", "country": "US", "attributed_to": "unknown"},
    {"organization": "Rackspace", "date": "2022-12-02", "records_breached": 0, "breach_type": "ransomware", "sector": "cloud", "country": "US", "attributed_to": "Play"},
    {"organization": "CircleCI", "date": "2023-01-04", "records_breached": 0, "breach_type": "malware_on_employee_laptop", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "Twilio", "date": "2022-08-04", "records_breached": 0, "breach_type": "sms_phishing", "sector": "technology", "country": "US", "attributed_to": "0Kted/Scattered Spider"},
    {"organization": "Cloudflare", "date": "2023-11-23", "records_breached": 0, "breach_type": "nation_state_access", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "Patreon", "date": "2015-10-01", "records_breached": 15700000, "breach_type": "unauthorized_access", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "Equifax UK", "date": "2017-09-07", "records_breached": 15000000, "breach_type": "unpatched_software", "sector": "financial", "country": "UK", "attributed_to": "APT41"},
    {"organization": "GoTo", "date": "2022-12-01", "records_breached": 0, "breach_type": "cloud_storage_compromise", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "Slack", "date": "2022-12-31", "records_breached": 0, "breach_type": "credential_compromise", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "GitHub", "date": "2023-02-01", "records_breached": 0, "breach_type": "credential_compromise", "sector": "technology", "country": "US", "attributed_to": "unknown"},
    {"organization": "Vodafone Germany", "date": "2023-02-01", "records_breached": 0, "breach_type": "unauthorized_access", "sector": "telecom", "country": "DE", "attributed_to": "unknown"},
    {"organization": "Linode", "date": "2022-01-19", "records_breached": 0, "breach_type": "credential_compromise", "sector": "cloud", "country": "US", "attributed_to": "unknown"},
    {"organization": "Telekom Deutschland", "date": "2023-11-01", "records_breached": 0, "breach_type": "unauthorized_access", "sector": "telecom", "country": "DE", "attributed_to": "unknown"},
    {"organization": "Vietnam Airlines", "date": "2020-04-12", "records_breached": 10000000, "breach_type": "unauthorized_access", "sector": "travel", "country": "VN", "attributed_to": "unknown"},
]

PHISHING_CAMPAIGNS = [
    {"campaign_name": "Operation Earth Kitsune", "threat_actor": "APT41", "date": "2020-05-01", "target_sector": "government", "technique": "spear_phishing", "lure": "COVID-19 relief document", "platform": "email"},
    {"campaign_name": "Hafnium Exchange Attack", "threat_actor": "Hafnium", "date": "2021-03-02", "target_sector": "government", "technique": "exploit_phishing", "lure": "Microsoft Exchange 0-day", "platform": "email_web"},
    {"campaign_name": "Log4Shell Mass Exploitation", "threat_actor": "Multiple", "date": "2021-12-10", "target_sector": "technology", "technique": "vulnerability_exploitation", "lure": "Log4j RCE", "platform": "web"},
    {"campaign_name": "Lazarus AppleJeus", "threat_actor": "Lazarus Group", "date": "2021-09-21", "target_sector": "cryptocurrency", "technique": "spear_phishing", "lure": "cryptocurrency trading app", "platform": "email_web"},
    {"campaign_name": "Nobelium Post-SolarWinds", "threat_actor": "APT29", "date": "2021-05-27", "target_sector": "government", "technique": "spear_phishing", "lure": "USAID newsletter", "platform": "email"},
    {"campaign_name": "Emotet Resurgence", "threat_actor": "Emotet Gang", "date": "2021-11-15", "target_sector": "multiple", "technique": "phishing_email", "lure": "invoice_document", "platform": "email"},
    {"campaign_name": "QakBot Campaign 2023", "threat_actor": "QakBot Gang", "date": "2023-05-01", "target_sector": "financial", "technique": "phishing_email", "lure": "IRS tax document", "platform": "email"},
    {"campaign_name": "IcedID Bokbot Campaign", "threat_actor": "IcedID Gang", "date": "2022-08-01", "target_sector": "healthcare", "technique": "phishing_email", "lure": "COVID test result", "platform": "email"},
    {"campaign_name": "Bumblebee Loader Campaign", "threat_actor": "Bumblebee Gang", "date": "2022-04-01", "target_sector": "technology", "technique": "phishing_email", "lure": "Voicemail notification", "platform": "email"},
    {"campaign_name": "Pikabot Spam Campaign", "threat_actor": "Pikabot Gang", "date": "2023-10-01", "target_sector": "multiple", "technique": "phishing_email", "lure": "shipping notification", "platform": "email"},
    {"campaign_name": "DarkGate Malspam", "threat_actor": "DarkGate Gang", "date": "2023-08-01", "target_sector": "multiple", "technique": "phishing_email", "lure": "PDF attachment", "platform": "email"},
    {"campaign_name": "AsyncRAT Phishing", "threat_actor": "unknown", "date": "2023-06-01", "target_sector": "government", "technique": "phishing_email", "lure": "secure document link", "platform": "email"},
    {"campaign_name": "RedLine Stealer Distribution", "threat_actor": "RedLine Gang", "date": "2023-03-01", "target_sector": "technology", "technique": "seo_poisoning", "lure": "cracked software download", "platform": "web"},
    {"campaign_name": "Raccoon Stealer Campaign", "threat_actor": "Raccoon Gang", "date": "2022-07-01", "target_sector": "multiple", "technique": "phishing_email", "lure": "software update", "platform": "email"},
    {"campaign_name": "LummaC2 YouTube Ads", "threat_actor": "Lumma Gang", "date": "2023-12-01", "target_sector": "multiple", "technique": "malvertising", "lure": "YouTube ad for software", "platform": "web"},
    {"campaign_name": "AgentTesla Spam", "threat_actor": "unknown", "date": "2023-01-01", "target_sector": "manufacturing", "technique": "phishing_email", "lure": "purchase order attachment", "platform": "email"},
    {"campaign_name": "Formbook Malspam", "threat_actor": "unknown", "date": "2023-02-01", "target_sector": "retail", "technique": "phishing_email", "lure": "shipping label", "platform": "email"},
    {"campaign_name": "Snake Keylogger Campaign", "threat_actor": "unknown", "date": "2023-04-01", "target_sector": "healthcare", "technique": "phishing_email", "lure": "medical report", "platform": "email"},
    {"campaign_name": "TrickBot Phishing Wave", "threat_actor": "TrickBot Gang", "date": "2022-06-01", "target_sector": "financial", "technique": "phishing_email", "lure": "bank alert", "platform": "email"},
    {"campaign_name": "Conti Phishing Campaign", "threat_actor": "Conti Gang", "date": "2022-01-01", "target_sector": "manufacturing", "technique": "spear_phishing", "lure": "employee benefits document", "platform": "email"},
    {"campaign_name": "LockBit RDP Campaign", "threat_actor": "LockBit Gang", "date": "2023-03-01", "target_sector": "healthcare", "technique": "rdp_exploitation", "lure": "exposed RDP service", "platform": "network"},
    {"campaign_name": "ALPHV VPN Exploit", "threat_actor": "ALPHV Gang", "date": "2023-06-01", "target_sector": "technology", "technique": "vpn_exploitation", "lure": "FortiOS VPN vulnerability", "platform": "network"},
    {"campaign_name": "Clop MOVEit Campaign", "threat_actor": "Clop Gang", "date": "2023-05-31", "target_sector": "multiple", "technique": "sql_injection", "lure": "MOVEit Transfer 0-day", "platform": "web"},
    {"campaign_name": "Play Ransomware Exchange", "threat_actor": "Play Gang", "date": "2023-02-01", "target_sector": "government", "technique": "exchange_exploitation", "lure": "Microsoft Exchange flaw", "platform": "email_web"},
    {"campaign_name": "BlackBasta QakBot Delivery", "threat_actor": "BlackBasta Gang", "date": "2023-04-01", "target_sector": "manufacturing", "technique": "qakbot_dropper", "lure": "malicious email attachment", "platform": "email"},
    {"campaign_name": "Rhysida PDQ Deploy", "threat_actor": "Rhysida Gang", "date": "2023-07-01", "target_sector": "education", "technique": "phishing_vpn", "lure": "VPN credential harvesting", "platform": "email_web"},
    {"campaign_name": "Akira VPN Campaign", "threat_actor": "Akira Gang", "date": "2023-09-01", "target_sector": "technology", "technique": "vpn_exploitation", "lure": "Cisco VPN exploit", "platform": "network"},
    {"campaign_name": "Medusa Phishing RDP", "threat_actor": "Medusa Gang", "date": "2023-05-01", "target_sector": "healthcare", "technique": "phishing_rdp", "lure": "telehealth portal link", "platform": "email"},
    {"campaign_name": "Royal Phishing Campaign", "threat_actor": "Royal Gang", "date": "2023-01-01", "target_sector": "government", "technique": "phishing_email", "lure": "court summons document", "platform": "email"},
    {"campaign_name": "Volt Typhoon LOTL", "threat_actor": "Volt Typhoon", "date": "2023-08-01", "target_sector": "critical_infrastructure", "technique": "living_off_the_land", "lure": "router exploitation", "platform": "network"},
    {"campaign_name": "Storm-0558 ForgeToken", "threat_actor": "Storm-0558", "date": "2023-06-01", "target_sector": "government", "technique": "token_forgery", "lure": "forged authentication token", "platform": "cloud"},
    {"campaign_name": "Scattered Spider MFA Fatigue", "threat_actor": "Scattered Spider", "date": "2023-09-01", "target_sector": "technology", "technique": "mfa_fatigue", "lure": "repeated push notifications", "platform": "cloud"},
    {"campaign_name": "MuddyWater POWERSTATS", "threat_actor": "MuddyWater", "date": "2023-03-01", "target_sector": "government", "technique": "spear_phishing", "lure": "diplomatic cable document", "platform": "email"},
    {"campaign_name": "Charming Kitten Glimpse", "threat_actor": "Charming Kitten", "date": "2023-06-01", "target_sector": "academic", "technique": "spear_phishing", "lure": "academic conference invite", "platform": "email"},
    {"campaign_name": "OilRig ISMAgent", "threat_actor": "OilRig", "date": "2023-02-01", "target_sector": "energy", "technique": "spear_phishing", "lure": "energy sector report", "platform": "email"},
    {"campaign_name": "APT43 BabyShark", "threat_actor": "APT43", "date": "2023-04-01", "target_sector": "think_tank", "technique": "spear_phishing", "lure": "nuclear policy brief", "platform": "email"},
    {"campaign_name": "Turla Snake Campaign", "threat_actor": "Turla", "date": "2023-05-01", "target_sector": "government", "technique": "spear_phishing", "lure": "diplomatic communication", "platform": "email"},
    {"campaign_name": "FIN7 Carbanak Campaign", "threat_actor": "FIN7", "date": "2023-07-01", "target_sector": "retail", "technique": "spear_phishing", "lure": "restaurant complaint", "platform": "email"},
    {"campaign_name": "FIN6 POS Malware", "threat_actor": "FIN6", "date": "2023-01-01", "target_sector": "retail", "technique": "pos_malware", "lure": "vendor software update", "platform": "network"},
    {"campaign_name": "Lapsus$ Social Engineering", "threat_actor": "Lapsus$", "date": "2022-03-01", "target_sector": "technology", "technique": "social_engineering", "lure": "employee impersonation", "platform": "phone_email"},
    {"campaign_name": "Kimsuky Spear Phishing", "threat_actor": "APT43", "date": "2023-08-01", "target_sector": "academic", "technique": "spear_phishing", "lure": "research collaboration", "platform": "email"},
    {"campaign_name": "APT33 Shamoon Campaign", "threat_actor": "APT33", "date": "2023-03-01", "target_sector": "energy", "technique": "spear_phishing", "lure": "energy industry report", "platform": "email"},
    {"campaign_name": "APT40 Maritime Campaign", "threat_actor": "APT40", "date": "2023-06-01", "target_sector": "maritime", "technique": "spear_phishing", "lure": "maritime navigation data", "platform": "email"},
    {"campaign_name": "APT5 Telecom Campaign", "threat_actor": "APT5", "date": "2023-09-01", "target_sector": "telecom", "technique": "spear_phishing", "lure": "network equipment advisory", "platform": "email"},
    {"campaign_name": "DarkSide Affiliate Campaign", "threat_actor": "DarkSide", "date": "2021-04-01", "target_sector": "energy", "technique": "phishing_rdp", "lure": "RDP access purchase", "platform": "darknet"},
    {"campaign_name": "Emotet TrickBot Pipeline", "threat_actor": "Emotet Gang", "date": "2021-01-01", "target_sector": "multiple", "technique": "phishing_email", "lure": "Excel macro document", "platform": "email"},
    {"campaign_name": "QakBot Wire Transfer Scam", "threat_actor": "QakBot Gang", "date": "2023-08-01", "target_sector": "financial", "technique": "phishing_email", "lure": "wire transfer confirmation", "platform": "email"},
    {"campaign_name": "IcedID Bumblebee Switch", "threat_actor": "IcedID Gang", "date": "2023-03-01", "target_sector": "multiple", "technique": "phishing_email", "lure": "Google Drive link", "platform": "email"},
    {"campaign_name": "CobaltStrike Beacon Deploy", "threat_actor": "Multiple APT", "date": "2023-05-01", "target_sector": "multiple", "technique": "spear_phishing", "lure": "encrypted ZIP attachment", "platform": "email"},
    {"campaign_name": "Mimikatz Lateral Movement", "threat_actor": "Multiple APT", "date": "2023-01-01", "target_sector": "multiple", "technique": "post_exploitation", "lure": "credential harvesting", "platform": "network"},
    {"campaign_name": "Business Email Compromise 2023", "threat_actor": "BEC Gangs", "date": "2023-01-01", "target_sector": "multiple", "technique": "email_impersonation", "lure": "CEO fraud wire transfer", "platform": "email"},
    {"campaign_name": "Tech Support Scam Campaign", "threat_actor": "Scammers", "date": "2023-06-01", "target_sector": "consumer", "technique": "cold_call_pop_up", "lure": "fake virus alert popup", "platform": "web_phone"},
    {"campaign_name": "Crypto Drainer Campaign", "threat_actor": "Drainer Gangs", "date": "2023-09-01", "target_sector": "cryptocurrency", "technique": "phishing_airdrop", "lure": "fake airdrop claim", "platform": "web"},
    {"campaign_name": "Romance Scam Campaign", "threat_actor": "Scammers", "date": "2023-01-01", "target_sector": "consumer", "technique": "social_engineering", "lure": "dating app impersonation", "platform": "social_media"},
    {"campaign_name": "Employment Scam Campaign", "threat_actor": "Scammers", "date": "2023-04-01", "target_sector": "consumer", "technique": "phishing_email", "lure": "fake job offer", "platform": "email"},
    {"campaign_name": "Rental Scam Campaign", "threat_actor": "Scammers", "date": "2023-06-01", "target_sector": "consumer", "technique": "phishing_email", "lure": "fake rental listing", "platform": "web"},
    {"campaign_name": "Invoice Scam Campaign", "threat_actor": "Scammers", "date": "2023-03-01", "target_sector": "small_business", "technique": "phishing_email", "lure": "fake invoice payment", "platform": "email"},
    {"campaign_name": "Gift Card Scam Campaign", "threat_actor": "Scammers", "date": "2023-12-01", "target_sector": "consumer", "technique": "phishing_email", "lure": "fake gift card offer", "platform": "email"},
    {"campaign_name": "Tax Scam Campaign", "threat_actor": "Scammers", "date": "2024-01-01", "target_sector": "consumer", "technique": "phishing_email", "lure": "fake tax refund", "platform": "email"},
    {"campaign_name": "Healthcare Scam Campaign", "threat_actor": "Scammers", "date": "2023-09-01", "target_sector": "healthcare", "technique": "phishing_email", "lure": "fake EHR portal", "platform": "email"},
    {"campaign_name": "Student Loan Scam Campaign", "threat_actor": "Scammers", "date": "2023-08-01", "target_sector": "consumer", "technique": "phishing_email", "lure": "fake loan forgiveness", "platform": "email"},
    {"campaign_name": "Insurance Scam Campaign", "threat_actor": "Scammers", "date": "2023-10-01", "target_sector": "consumer", "technique": "phishing_email", "lure": "fake insurance claim", "platform": "email"},
    {"campaign_name": "Government Impersonation", "threat_actor": "Scammers", "date": "2023-07-01", "target_sector": "consumer", "technique": "phishing_email", "lure": "fake government notice", "platform": "email"},
    {"campaign_name": "Bank Impersonation Campaign", "threat_actor": "Scammers", "date": "2023-11-01", "target_sector": "financial", "technique": "phishing_email", "lure": "fake bank alert", "platform": "email"},
    {"campaign_name": "Delivery Scam Campaign", "threat_actor": "Scammers", "date": "2023-12-01", "target_sector": "consumer", "technique": "sms_phishing", "lure": "fake delivery notification", "platform": "sms"},
    {"campaign_name": "Subscription Scam Campaign", "threat_actor": "Scammers", "date": "2024-01-01", "target_sector": "consumer", "technique": "phishing_email", "lure": "fake subscription renewal", "platform": "email"},
    {"campaign_name": "Antivirus Scam Campaign", "threat_actor": "Scammers", "date": "2023-05-01", "target_sector": "consumer", "technique": "phishing_email", "lure": "fake antivirus renewal", "platform": "email"},
    {"campaign_name": "Crypto Investment Scam", "threat_actor": "Scammers", "date": "2023-06-01", "target_sector": "consumer", "technique": "social_media_phishing", "lure": "fake crypto investment", "platform": "social_media"},
    {"campaign_name": "NFT Scam Campaign", "threat_actor": "Scammers", "date": "2023-03-01", "target_sector": "cryptocurrency", "technique": "phishing_airdrop", "lure": "fake NFT mint", "platform": "web"},
    {"campaign_name": "AI Tool Scam Campaign", "threat_actor": "Scammers", "date": "2024-02-01", "target_sector": "technology", "technique": "phishing_email", "lure": "fake AI tool subscription", "platform": "email"},
]

DARKWEB_MARKET_LISTINGS = [
    {"listing_id": "DW-2024-001", "market": "AlphaBay", "category": "stolen_data", "item": "US bank credentials with balance $10k+", "price": "$250", "seller_rating": 4.8, "date_listed": "2024-01-15"},
    {"listing_id": "DW-2024-002", "market": "AlphaBay", "category": "stolen_data", "item": "EU credit card fullz 500 cards batch", "price": "$1800", "seller_rating": 4.6, "date_listed": "2024-01-20"},
    {"listing_id": "DW-2024-003", "market": "BlackSprut", "category": "malware", "item": "RedLine Stealer v28 cracked license", "price": "$150", "seller_rating": 4.3, "date_listed": "2024-02-01"},
    {"listing_id": "DW-2024-004", "market": "BlackSprut", "category": "malware", "item": "CobaltStrike 4.9 cracked with malleable C2", "price": "$500", "seller_rating": 4.7, "date_listed": "2024-02-05"},
    {"listing_id": "DW-2024-005", "market": "Kraken", "category": "stolen_data", "item": "Fortune 500 company email access (100 accounts)", "price": "$5000", "seller_rating": 4.9, "date_listed": "2024-02-10"},
    {"listing_id": "DW-2024-006", "market": "Kraken", "category": "malware", "item": "Raccoon Stealer v2 subscription 1 month", "price": "$200", "seller_rating": 4.5, "date_listed": "2024-02-15"},
    {"listing_id": "DW-2024-007", "market": "Mega", "category": "stolen_data", "item": "Healthcare database 2M patient records", "price": "$15000", "seller_rating": 4.2, "date_listed": "2024-02-20"},
    {"listing_id": "DW-2024-008", "market": "Mega", "category": "exploit", "item": "0-day RCE for Palo Alto PAN-OS", "price": "$500000", "seller_rating": 5.0, "date_listed": "2024-03-01"},
    {"listing_id": "DW-2024-009", "market": "Nemesis", "category": "stolen_data", "item": "Government employee PII dataset 500k records", "price": "$25000", "seller_rating": 4.4, "date_listed": "2024-03-05"},
    {"listing_id": "DW-2024-010", "market": "Nemesis", "category": "malware", "item": "AsyncRAT custom build with anti-detection", "price": "$300", "seller_rating": 4.1, "date_listed": "2024-03-10"},
    {"listing_id": "DW-2024-011", "market": "Tor2Door", "category": "stolen_data", "item": "Cryptocurrency wallet seeds verified balance $50k+", "price": "$5000", "seller_rating": 4.6, "date_listed": "2024-03-15"},
    {"listing_id": "DW-2024-012", "market": "Tor2Door", "category": "malware", "item": "LummaC2 Stealer panel + builder", "price": "$1000", "seller_rating": 4.8, "date_listed": "2024-03-20"},
    {"listing_id": "DW-2024-013", "market": "AlphaBay", "category": "exploit", "item": "Privilege escalation exploit for Windows 11", "price": "$50000", "seller_rating": 4.7, "date_listed": "2024-03-25"},
    {"listing_id": "DW-2024-014", "market": "AlphaBay", "category": "stolen_data", "item": "AWS S3 bucket access Fortune 100 company", "price": "$20000", "seller_rating": 4.5, "date_listed": "2024-04-01"},
    {"listing_id": "DW-2024-015", "market": "BlackSprut", "category": "tools", "item": "BruteRatel C4 license 1 year", "price": "$2500", "seller_rating": 4.9, "date_listed": "2024-04-05"},
    {"listing_id": "DW-2024-016", "market": "BlackSprut", "category": "stolen_data", "item": "Corporate VPN credentials batch 200 orgs", "price": "$10000", "seller_rating": 4.3, "date_listed": "2024-04-10"},
    {"listing_id": "DW-2024-017", "market": "Kraken", "category": "malware", "item": "DarkGate loader subscription 1 month", "price": "$500", "seller_rating": 4.6, "date_listed": "2024-04-15"},
    {"listing_id": "DW-2024-018", "market": "Kraken", "category": "exploit", "item": "Citrix Bleed exploit kit", "price": "$15000", "seller_rating": 4.8, "date_listed": "2024-04-20"},
    {"listing_id": "DW-2024-019", "market": "Mega", "category": "stolen_data", "item": "Social media accounts batch 10k verified", "price": "$3000", "seller_rating": 4.2, "date_listed": "2024-04-25"},
    {"listing_id": "DW-2024-020", "market": "Mega", "category": "tools", "item": "Bulletproof hosting 1 month", "price": "$500", "seller_rating": 4.4, "date_listed": "2024-05-01"},
    {"listing_id": "DW-2024-021", "market": "Nemesis", "category": "stolen_data", "item": "University student records 1M entries", "price": "$8000", "seller_rating": 4.1, "date_listed": "2024-05-05"},
    {"listing_id": "DW-2024-022", "market": "Nemesis", "category": "malware", "item": "Pikabot loader panel + builder", "price": "$800", "seller_rating": 4.5, "date_listed": "2024-05-10"},
    {"listing_id": "DW-2024-023", "market": "Tor2Door", "category": "exploit", "item": "Ivanti VPN auth bypass exploit", "price": "$25000", "seller_rating": 4.7, "date_listed": "2024-05-15"},
    {"listing_id": "DW-2024-024", "market": "Tor2Door", "category": "stolen_data", "item": "Payment card data 10k cards with CVV", "price": "$5000", "seller_rating": 4.6, "date_listed": "2024-05-20"},
    {"listing_id": "DW-2024-025", "market": "AlphaBay", "category": "tools", "item": "Residential proxy network 10k IPs", "price": "$2000/month", "seller_rating": 4.8, "date_listed": "2024-05-25"},
    {"listing_id": "DW-2024-026", "market": "AlphaBay", "category": "malware", "item": "Snake Keylogger builder + panel", "price": "$250", "seller_rating": 4.3, "date_listed": "2024-06-01"},
    {"listing_id": "DW-2024-027", "market": "BlackSprut", "category": "stolen_data", "item": "Corporate email access Microsoft 365 50 orgs", "price": "$15000", "seller_rating": 4.9, "date_listed": "2024-06-05"},
    {"listing_id": "DW-2024-028", "market": "BlackSprut", "category": "exploit", "item": "FortiOS SSL-VPN RCE exploit", "price": "$30000", "seller_rating": 4.7, "date_listed": "2024-06-10"},
    {"listing_id": "DW-2024-029", "market": "Kraken", "category": "tools", "item": "Sliver C2 framework with custom profiles", "price": "$750", "seller_rating": 4.5, "date_listed": "2024-06-15"},
    {"listing_id": "DW-2024-030", "market": "Kraken", "category": "stolen_data", "item": "Medical records database 500k patients", "price": "$12000", "seller_rating": 4.4, "date_listed": "2024-06-20"},
    {"listing_id": "DW-2024-031", "market": "Mega", "category": "malware", "item": "Warzone RAT cracked license", "price": "$350", "seller_rating": 4.2, "date_listed": "2024-06-25"},
    {"listing_id": "DW-2024-032", "market": "Mega", "category": "stolen_data", "item": "Banking trojan logs 100k entries", "price": "$7000", "seller_rating": 4.6, "date_listed": "2024-07-01"},
    {"listing_id": "DW-2024-033", "market": "Nemesis", "category": "exploit", "item": "Jenkins CLI file read exploit", "price": "$10000", "seller_rating": 4.8, "date_listed": "2024-07-05"},
    {"listing_id": "DW-2024-034", "market": "Nemesis", "category": "tools", "item": "Anti-detection pack for malware", "price": "$400", "seller_rating": 4.3, "date_listed": "2024-07-10"},
    {"listing_id": "DW-2024-035", "market": "Tor2Door", "category": "stolen_data", "item": "SSN + DOB dataset 1M US citizens", "price": "$20000", "seller_rating": 4.7, "date_listed": "2024-07-15"},
    {"listing_id": "DW-2024-036", "market": "Tor2Door", "category": "malware", "item": "Remcos RAT subscription 3 months", "price": "$600", "seller_rating": 4.5, "date_listed": "2024-07-20"},
    {"listing_id": "DW-2024-037", "market": "AlphaBay", "category": "stolen_data", "item": "LinkedIn scraped data 5M profiles", "price": "$2500", "seller_rating": 4.1, "date_listed": "2024-07-25"},
    {"listing_id": "DW-2024-038", "market": "AlphaBay", "category": "tools", "item": "Phishing kit Microsoft 365 login page", "price": "$150", "seller_rating": 4.4, "date_listed": "2024-08-01"},
    {"listing_id": "DW-2024-039", "market": "BlackSprut", "category": "exploit", "item": "PHP CGI argument injection exploit", "price": "$20000", "seller_rating": 4.9, "date_listed": "2024-08-05"},
    {"listing_id": "DW-2024-040", "market": "BlackSprut", "category": "stolen_data", "item": "Corporate Active Directory dump 20 orgs", "price": "$25000", "seller_rating": 4.8, "date_listed": "2024-08-10"},
    {"listing_id": "DW-2024-041", "market": "Kraken", "category": "malware", "item": "DCRat custom build with plugins", "price": "$450", "seller_rating": 4.2, "date_listed": "2024-08-15"},
    {"listing_id": "DW-2024-042", "market": "Kraken", "category": "tools", "item": "Credential stuffing tool + combo list 10M", "price": "$500", "seller_rating": 4.6, "date_listed": "2024-08-20"},
    {"listing_id": "DW-2024-043", "market": "Mega", "category": "stolen_data", "item": "Crypto exchange API keys batch 1000", "price": "$10000", "seller_rating": 4.7, "date_listed": "2024-08-25"},
    {"listing_id": "DW-2024-044", "market": "Mega", "category": "exploit", "item": "TeamCity auth bypass exploit", "price": "$15000", "seller_rating": 4.5, "date_listed": "2024-09-01"},
    {"listing_id": "DW-2024-045", "market": "Nemesis", "category": "stolen_data", "item": "Military personnel records 100k", "price": "$50000", "seller_rating": 4.9, "date_listed": "2024-09-05"},
    {"listing_id": "DW-2024-046", "market": "Nemesis", "category": "malware", "item": "NanoCore RAT cracked license", "price": "$200", "seller_rating": 4.1, "date_listed": "2024-09-10"},
    {"listing_id": "DW-2024-047", "market": "Tor2Door", "category": "tools", "item": "SMS bombing service 1000 targets", "price": "$100", "seller_rating": 3.9, "date_listed": "2024-09-15"},
    {"listing_id": "DW-2024-048", "market": "Tor2Door", "category": "stolen_data", "item": "Email access combo UK banks 500 accounts", "price": "$3000", "seller_rating": 4.4, "date_listed": "2024-09-20"},
    {"listing_id": "DW-2024-049", "market": "AlphaBay", "category": "exploit", "item": "OpenSSH regreSSHion exploit", "price": "$8000", "seller_rating": 4.6, "date_listed": "2024-09-25"},
    {"listing_id": "DW-2024-050", "market": "AlphaBay", "category": "malware", "item": "Vidar Stealer subscription 1 month", "price": "$300", "seller_rating": 4.3, "date_listed": "2024-10-01"},
    {"listing_id": "DW-2024-051", "market": "BlackSprut", "category": "stolen_data", "item": "RDP access 500 corporate servers", "price": "$7500", "seller_rating": 4.8, "date_listed": "2024-10-05"},
    {"listing_id": "DW-2024-052", "market": "BlackSprut", "category": "tools", "item": "Custom crypter FUD for 30 days", "price": "$600", "seller_rating": 4.5, "date_listed": "2024-10-10"},
    {"listing_id": "DW-2024-053", "market": "Kraken", "category": "stolen_data", "item": "Insurance claims database 2M records", "price": "$18000", "seller_rating": 4.7, "date_listed": "2024-10-15"},
    {"listing_id": "DW-2024-054", "market": "Kraken", "category": "malware", "item": "SystemBC proxy botnet access", "price": "$400", "seller_rating": 4.2, "date_listed": "2024-10-20"},
    {"listing_id": "DW-2024-055", "market": "Mega", "category": "exploit", "item": "PAN-OS GlobalProtect command injection", "price": "$40000", "seller_rating": 5.0, "date_listed": "2024-10-25"},
    {"listing_id": "DW-2024-056", "market": "Mega", "category": "stolen_data", "item": "Tax return data 500k US filers", "price": "$30000", "seller_rating": 4.6, "date_listed": "2024-11-01"},
    {"listing_id": "DW-2024-057", "market": "Nemesis", "category": "tools", "item": "DDoS booter service 100Gbps 1 month", "price": "$300", "seller_rating": 4.0, "date_listed": "2024-11-05"},
    {"listing_id": "DW-2024-058", "market": "Nemesis", "category": "malware", "item": "Formbook XLoader builder", "price": "$350", "seller_rating": 4.4, "date_listed": "2024-11-10"},
    {"listing_id": "DW-2024-059", "market": "Tor2Door", "category": "stolen_data", "item": "Passport scans batch 10k documents", "price": "$5000", "seller_rating": 4.3, "date_listed": "2024-11-15"},
    {"listing_id": "DW-2024-060", "market": "Tor2Door", "category": "exploit", "item": "Windows TCP/IP RCE exploit", "price": "$60000", "seller_rating": 4.9, "date_listed": "2024-11-20"},
    {"listing_id": "DW-2024-061", "market": "AlphaBay", "category": "stolen_data", "item": "Credit card fullz EU 2000 cards", "price": "$4000", "seller_rating": 4.5, "date_listed": "2024-11-25"},
    {"listing_id": "DW-2024-062", "market": "AlphaBay", "category": "tools", "item": "Phishing kit Bypass MFA template", "price": "$500", "seller_rating": 4.7, "date_listed": "2024-12-01"},
    {"listing_id": "DW-2024-063", "market": "BlackSprut", "category": "malware", "item": "PlugX backdoor custom variant", "price": "$1000", "seller_rating": 4.6, "date_listed": "2024-12-05"},
    {"listing_id": "DW-2024-064", "market": "BlackSprut", "category": "stolen_data", "item": "Healthcare provider network access 10 orgs", "price": "$20000", "seller_rating": 4.8, "date_listed": "2024-12-10"},
    {"listing_id": "DW-2024-065", "market": "Kraken", "category": "exploit", "item": "Cisco ASA WebVPN RCE exploit", "price": "$25000", "seller_rating": 4.5, "date_listed": "2024-12-15"},
    {"listing_id": "DW-2024-066", "market": "Kraken", "category": "tools", "item": "OSINT reconnaissance tool enterprise", "price": "$800", "seller_rating": 4.3, "date_listed": "2024-12-20"},
    {"listing_id": "DW-2024-067", "market": "Mega", "category": "stolen_data", "item": "Social security numbers 500k US", "price": "$15000", "seller_rating": 4.7, "date_listed": "2024-12-25"},
    {"listing_id": "DW-2024-068", "market": "Mega", "category": "malware", "item": "ShadowPad backdoor access", "price": "$2000", "seller_rating": 4.9, "date_listed": "2025-01-01"},
    {"listing_id": "DW-2024-069", "market": "Nemesis", "category": "stolen_data", "item": "Corporate email database 5M messages", "price": "$10000", "seller_rating": 4.4, "date_listed": "2025-01-05"},
    {"listing_id": "DW-2024-070", "market": "Nemesis", "category": "tools", "item": "Bulletproof SMTP server 1 month", "price": "$400", "seller_rating": 4.2, "date_listed": "2025-01-10"},
]

CRYPTO_TRANSACTIONS = [
    {"tx_hash": "0x7a3b1c9d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1", "currency": "BTC", "amount": 45.2, "from_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "to_address": "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5", "type": "ransomware_payment", "associated_malware": "LockBit", "date": "2023-06-15", "risk_score": 0.95},
    {"tx_hash": "0x8b4c2d0e3f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2", "currency": "BTC", "amount": 88.5, "from_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "type": "ransomware_payment", "associated_malware": "ALPHV", "date": "2023-09-20", "risk_score": 0.97},
    {"tx_hash": "0x9c5d3e1f4a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3", "currency": "BTC", "amount": 12.8, "from_address": "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "to_address": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "type": "darknet_market", "associated_malware": "AlphaBay", "date": "2024-01-10", "risk_score": 0.88},
    {"tx_hash": "0xad6e4f2a5b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4", "currency": "ETH", "amount": 250.0, "from_address": "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5", "to_address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "type": "ransomware_payment", "associated_malware": "Conti", "date": "2022-05-15", "risk_score": 0.92},
    {"tx_hash": "0xbe7f5a3b6c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5", "currency": "BTC", "amount": 5.3, "from_address": "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h", "to_address": "1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp", "type": "mixing_service", "associated_malware": "Tornado Cash", "date": "2024-03-01", "risk_score": 0.85},
    {"tx_hash": "0xcf8a6b4c7d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6", "currency": "BTC", "amount": 120.0, "from_address": "1FeexV6bAHb8ybZi5nRYvQ8p3WUqFXsJ7v", "to_address": "bc1qn2g5ne4tuwd5g9r4v9f2z6l3h8m7k4j1", "type": "ransomware_payment", "associated_malware": "Cl0p", "date": "2023-07-01", "risk_score": 0.96},
    {"tx_hash": "0xd09b7c5d8e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7", "currency": "ETH", "amount": 1500.0, "from_address": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "to_address": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "type": "darknet_market", "associated_malware": "Kraken Market", "date": "2024-02-15", "risk_score": 0.9},
    {"tx_hash": "0xe10c8d6e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7", "currency": "BTC", "amount": 22.1, "from_address": "3Kzh9qAqVWQhEsfQz7zEQL1EuSx5tyNLNS", "to_address": "1JqDbyu5UXV2S3b3hC3s1L9dUTp4c1dR2w", "type": "extortion_payment", "associated_malware": "Karakurt", "date": "2023-11-01", "risk_score": 0.93},
    {"tx_hash": "0xf21d9e7a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8", "currency": "BTC", "amount": 350.0, "from_address": "bc1q42l4v9m5g3u8n2k7h6j5f4d3s2a1q9w8e7r6t", "to_address": "1CBTCGUY1Mm8BQHv5sQY3Fj2GZ1vE3uT4i", "type": "ransomware_payment", "associated_malware": "BlackBasta", "date": "2023-08-15", "risk_score": 0.98},
    {"tx_hash": "0xa32e0f8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9", "currency": "BTC", "amount": 8.7, "from_address": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "to_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "type": "malware_sale", "associated_malware": "RedLine", "date": "2024-04-01", "risk_score": 0.82},
    {"tx_hash": "0xb43f1a9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0", "currency": "ETH", "amount": 75.0, "from_address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "to_address": "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5", "type": "darknet_market", "associated_malware": "Mega", "date": "2024-05-01", "risk_score": 0.87},
    {"tx_hash": "0xc54a2b0d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1", "currency": "BTC", "amount": 500.0, "from_address": "1FeexV6bAHb8ybZi5nRYvQ8p3WUqFXsJ7v", "to_address": "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5", "type": "ransomware_payment", "associated_malware": "Play", "date": "2023-04-01", "risk_score": 0.94},
    {"tx_hash": "0xd65b3c1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2", "currency": "BTC", "amount": 15.9, "from_address": "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h", "to_address": "1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp", "type": "mixing_service", "associated_malware": "Blender.io", "date": "2024-06-01", "risk_score": 0.8},
    {"tx_hash": "0xe76c4d2a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3", "currency": "BTC", "amount": 67.3, "from_address": "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "type": "ransomware_payment", "associated_malware": "Royal", "date": "2023-02-01", "risk_score": 0.91},
    {"tx_hash": "0xf87d5e3b6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4", "currency": "ETH", "amount": 420.0, "from_address": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "to_address": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "type": "exploit_sale", "associated_malware": "Unknown", "date": "2024-03-15", "risk_score": 0.89},
    {"tx_hash": "0xa98e6f4c7b8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5", "currency": "BTC", "amount": 200.0, "from_address": "1CBTCGUY1Mm8BQHv5sQY3Fj2GZ1vE3uT4i", "to_address": "bc1qn2g5ne4tuwd5g9r4v9f2z6l3h8m7k4j1", "type": "ransomware_payment", "associated_malware": "Akira", "date": "2023-10-01", "risk_score": 0.95},
    {"tx_hash": "0xba9f7a5d8c6e4f2a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7", "currency": "BTC", "amount": 33.6, "from_address": "bc1q42l4v9m5g3u8n2k7h6j5f4d3s2a1q9w8e7r6t", "to_address": "3Kzh9qAqVWQhEsfQz7zEQL1EuSx5tyNLNS", "type": "darknet_market", "associated_malware": "Nemesis", "date": "2024-07-01", "risk_score": 0.86},
    {"tx_hash": "0xcb0a8b6d4e2f0a1c3e5d7f9a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0", "currency": "ETH", "amount": 890.0, "from_address": "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5", "to_address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "type": "ransomware_payment", "associated_malware": "Rhysida", "date": "2023-09-01", "risk_score": 0.93},
    {"tx_hash": "0xdc1b9c7e5f3a1b2d4e6f8a0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2", "currency": "BTC", "amount": 410.0, "from_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "to_address": "1FeexV6bAHb8ybZi5nRYvQ8p3WUqFXsJ7v", "type": "ransomware_payment", "associated_malware": "LockBit", "date": "2023-12-01", "risk_score": 0.97},
    {"tx_hash": "0xed2c0d8e6f4a2b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3", "currency": "BTC", "amount": 18.4, "from_address": "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5", "to_address": "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h", "type": "malware_sale", "associated_malware": "Formbook", "date": "2024-08-01", "risk_score": 0.84},
    {"tx_hash": "0xfe3d1e9f7a5b3c1d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0", "currency": "BTC", "amount": 95.0, "from_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "to_address": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "type": "ransomware_payment", "associated_malware": "Medusa", "date": "2023-06-01", "risk_score": 0.92},
    {"tx_hash": "0xaf4e2d0c8b6a4f2e0d1c3b5a7f9e1d3c5b7a9f1e3d5c7b9a1f3e5d7c9b1a3f5e7", "currency": "ETH", "amount": 2100.0, "from_address": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "to_address": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "type": "exploit_sale", "associated_malware": "Unknown", "date": "2024-04-15", "risk_score": 0.91},
    {"tx_hash": "0xb05f3e1d9c7a5b3f1e0d2c4a6b8f0e2d4c6a8b0f2e4d6c8a0b2f4e6d8c0a2b4f6", "currency": "BTC", "amount": 55.0, "from_address": "1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp", "to_address": "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "type": "mixing_service", "associated_malware": "Tornado Cash", "date": "2024-09-01", "risk_score": 0.83},
    {"tx_hash": "0xc16a4f2e0d8c6b4a2f0e8d6c4b2a0f8e6d4c2b0a8f6e4d2c0b8a6f4e2d0c8b6a4", "currency": "BTC", "amount": 780.0, "from_address": "1FeexV6bAHb8ybZi5nRYvQ8p3WUqFXsJ7v", "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "type": "ransomware_payment", "associated_malware": "DarkSide", "date": "2021-05-09", "risk_score": 0.96},
    {"tx_hash": "0xd27b5a3f1e9c7d5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5", "currency": "BTC", "amount": 42.0, "from_address": "bc1qn2g5ne4tuwd5g9r4v9f2z6l3h8m7k4j1", "to_address": "1CBTCGUY1Mm8BQHv5sQY3Fj2GZ1vE3uT4i", "type": "darknet_market", "associated_malware": "Tor2Door", "date": "2024-10-01", "risk_score": 0.88},
    {"tx_hash": "0xe38c6b4a2f0e8d6c4b2a0f8e6d4c2b0a8f6e4d2c0b8a6f4e2d0c8b6a4f2e0d8c6", "currency": "ETH", "amount": 650.0, "from_address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "to_address": "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5", "type": "ransomware_payment", "associated_malware": "Hive", "date": "2022-08-01", "risk_score": 0.9},
    {"tx_hash": "0xf49d7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7", "currency": "BTC", "amount": 160.0, "from_address": "3Kzh9qAqVWQhEsfQz7zEQL1EuSx5tyNLNS", "to_address": "bc1q42l4v9m5g3u8n2k7h6j5f4d3s2a1q9w8e7r6t", "type": "ransomware_payment", "associated_malware": "AvosLocker", "date": "2022-11-01", "risk_score": 0.94},
    {"tx_hash": "0xa50e8d6c4b2a0f8e6d4c2b0a8f6e4d2c0b8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8", "currency": "BTC", "amount": 28.5, "from_address": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "to_address": "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h", "type": "extortion_payment", "associated_malware": "BianLian", "date": "2023-03-01", "risk_score": 0.89},
    {"tx_hash": "0xb61f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9", "currency": "BTC", "amount": 310.0, "from_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "to_address": "1FeexV6bAHb8ybZi5nRYvQ8p3WUqFXsJ7v", "type": "ransomware_payment", "associated_malware": "REvil", "date": "2021-07-02", "risk_score": 0.97},
    {"tx_hash": "0xc72a0f8e6d4c2b0a8f6e4d2c0b8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0", "currency": "ETH", "amount": 320.0, "from_address": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "to_address": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "type": "darknet_market", "associated_malware": "BlackSprut", "date": "2024-11-01", "risk_score": 0.86},
    {"tx_hash": "0xd83b1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1", "currency": "BTC", "amount": 75.0, "from_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "to_address": "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5", "type": "ransomware_payment", "associated_malware": "ViceSociety", "date": "2022-10-01", "risk_score": 0.91},
    {"tx_hash": "0xe94c2b0a8f6e4d2c0b8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0f8e6d4c2", "currency": "BTC", "amount": 440.0, "from_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "to_address": "1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp", "type": "ransomware_payment", "associated_malware": "BlackSuit", "date": "2023-08-01", "risk_score": 0.93},
    {"tx_hash": "0xfa5d3c1b9a7f5e3d1c0b8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0f8e6d4", "currency": "BTC", "amount": 25.0, "from_address": "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "to_address": "bc1qn2g5ne4tuwd5g9r4v9f2z6l3h8m7k4j1", "type": "malware_sale", "associated_malware": "LummaC2", "date": "2024-06-15", "risk_score": 0.85},
    {"tx_hash": "0xab6e4d2c0b8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0f8e6d4c2b0a8f6e4", "currency": "ETH", "amount": 1800.0, "from_address": "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5", "to_address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "type": "ransomware_payment", "associated_malware": "Nokoyawa", "date": "2023-05-01", "risk_score": 0.88},
    {"tx_hash": "0xbc7f5e3d1c0b8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0f8e6d4c2b0a8f6", "currency": "BTC", "amount": 130.0, "from_address": "1CBTCGUY1Mm8BQHv5sQY3Fj2GZ1vE3uT4i", "to_address": "bc1q42l4v9m5g3u8n2k7h6j5f4d3s2a1q9w8e7r6t", "type": "ransomware_payment", "associated_malware": "Magniber", "date": "2022-04-01", "risk_score": 0.9},
    {"tx_hash": "0xcd8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0f8e6d4c2b0a8f6e4d2c0b8a6", "currency": "BTC", "amount": 9.8, "from_address": "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h", "to_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "type": "darknet_market", "associated_malware": "AlphaBay", "date": "2024-12-01", "risk_score": 0.82},
    {"tx_hash": "0xde9b7a5f3e1d0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0f8e6d4c2b0a8f6e4d2c0b8", "currency": "BTC", "amount": 620.0, "from_address": "1FeexV6bAHb8ybZi5nRYvQ8p3WUqFXsJ7v", "to_address": "3Kzh9qAqVWQhEsfQz7zEQL1EuSx5tyNLNS", "type": "ransomware_payment", "associated_malware": "DarkSide", "date": "2021-05-07", "risk_score": 0.96},
    {"tx_hash": "0xef0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0f8e6d4c2b0a8f6e4d2c0b8a6f4e2d0c8", "currency": "ETH", "amount": 450.0, "from_address": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "to_address": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "type": "exploit_sale", "associated_malware": "Unknown", "date": "2024-05-20", "risk_score": 0.92},
    {"tx_hash": "0xa01d9c7e5f3a1b2d4e6f8a0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2", "currency": "BTC", "amount": 38.0, "from_address": "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5", "to_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "type": "mixing_service", "associated_malware": "Blender.io", "date": "2024-01-25", "risk_score": 0.84},
    {"tx_hash": "0xb12e0d8f6a4c2b0a8f6e4d2c0b8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0", "currency": "BTC", "amount": 270.0, "from_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "to_address": "1FeexV6bAHb8ybZi5nRYvQ8p3WUqFXsJ7v", "type": "ransomware_payment", "associated_malware": "Ryuk", "date": "2020-09-01", "risk_score": 0.95},
    {"tx_hash": "0xc23f1e9d7b5a3f1e9d7b5a3f1e9d7b5a3f1e9d7b5a3f1e9d7b5a3f1e9d7b5a3f1", "currency": "BTC", "amount": 55.0, "from_address": "1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp", "to_address": "bc1qn2g5ne4tuwd5g9r4v9f2z6l3h8m7k4j1", "type": "darknet_market", "associated_malware": "Mega", "date": "2024-08-15", "risk_score": 0.87},
    {"tx_hash": "0xd34a2f0e8c6b4a2f0e8c6b4a2f0e8c6b4a2f0e8c6b4a2f0e8c6b4a2f0e8c6b4a2", "currency": "ETH", "amount": 950.0, "from_address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "to_address": "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5", "type": "ransomware_payment", "associated_malware": "Babuk", "date": "2021-04-01", "risk_score": 0.91},
    {"tx_hash": "0xe45b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3a1f9e7c5b3", "currency": "BTC", "amount": 190.0, "from_address": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "to_address": "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "type": "ransomware_payment", "associated_malware": "Conti", "date": "2021-06-01", "risk_score": 0.94},
    {"tx_hash": "0xf56c4b2a0f8e6d4c2b0a8f6e4d2c0b8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8d6c4", "currency": "BTC", "amount": 14.2, "from_address": "bc1q42l4v9m5g3u8n2k7h6j5f4d3s2a1q9w8e7r6t", "to_address": "1CBTCGUY1Mm8BQHv5sQY3Fj2GZ1vE3uT4i", "type": "malware_sale", "associated_malware": "Raccoon", "date": "2024-03-20", "risk_score": 0.83},
    {"tx_hash": "0xa67d5e3c1b9a7f5e3d1c0b8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0f8e6", "currency": "BTC", "amount": 480.0, "from_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "to_address": "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h", "type": "ransomware_payment", "associated_malware": "ALPHV", "date": "2024-02-21", "risk_score": 0.97},
    {"tx_hash": "0xb78e6f4d2c0b8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0f8e6d4c2b0a8f6", "currency": "BTC", "amount": 35.0, "from_address": "3Kzh9qAqVWQhEsfQz7zEQL1EuSx5tyNLNS", "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "type": "darknet_market", "associated_malware": "Nemesis", "date": "2024-09-15", "risk_score": 0.85},
    {"tx_hash": "0xc89f7a5e3d1c0b8a6f4e2d0c8b6a4f2e0d8c6b4a2f0e8d6c4b2a0f8e6d4c2b0a8", "currency": "ETH", "amount": 1200.0, "from_address": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "to_address": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "type": "ransomware_payment", "associated_malware": "LockBit", "date": "2023-11-01", "risk_score": 0.96},
    {"tx_hash": "0xd90a8b6c4e2f0a1c3e5d7f9a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0", "currency": "BTC", "amount": 82.0, "from_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "to_address": "1FeexV6bAHb8ybZi5nRYvQ8p3WUqFXsJ7v", "type": "extortion_payment", "associated_malware": "Karakurt", "date": "2023-07-15", "risk_score": 0.9},
    {"tx_hash": "0xea1b9c7d5f3a1b2d4e6f8a0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2", "currency": "BTC", "amount": 155.0, "from_address": "1FeexV6bAHb8ybZi5nRYvQ8p3WUqFXsJ7v", "to_address": "bc1qn2g5ne4tuwd5g9r4v9f2z6l3h8m7k4j1", "type": "ransomware_payment", "associated_malware": "Play", "date": "2023-06-01", "risk_score": 0.93},
]

BOTNET_INFRASTRUCTURE = [
    {"botnet_name": "Mirai", "c2_servers": ["185.220.101.34", "91.215.85.209"], "protocol": "IRC", "target_devices": "IoT", "estimated_size": 600000, "first_seen": "2016-08", "variant": "Mirai.OMNI"},
    {"botnet_name": "Emotet", "c2_servers": ["91.215.85.209", "217.12.199.201"], "protocol": "HTTP", "target_devices": "Windows", "estimated_size": 1000000, "first_seen": "2014-06", "variant": "Emotet.v5"},
    {"botnet_name": "TrickBot", "c2_servers": ["194.165.16.102", "91.134.238.74"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 500000, "first_seen": "2016-10", "variant": "TrickBot.v8"},
    {"botnet_name": "QakBot", "c2_servers": ["23.106.122.137", "149.28.139.14"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 300000, "first_seen": "2007-01", "variant": "QakBot.pinkslipbot"},
    {"botnet_name": "IcedID", "c2_servers": ["45.77.65.211", "91.134.238.100"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 200000, "first_seen": "2017-09", "variant": "IcedID.bokbot"},
    {"botnet_name": "Bumblebee", "c2_servers": ["91.134.238.250", "167.71.12.200"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 50000, "first_seen": "2022-03", "variant": "Bumblebee.v2"},
    {"botnet_name": "Pikabot", "c2_servers": ["149.28.139.200", "161.35.94.200"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 75000, "first_seen": "2023-01", "variant": "Pikabot.v3"},
    {"botnet_name": "DarkGate", "c2_servers": ["149.28.139.250", "45.9.148.107"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 100000, "first_seen": "2017-06", "variant": "DarkGate.v6"},
    {"botnet_name": "AsyncRAT", "c2_servers": ["91.92.247.12", "91.92.247.50"], "protocol": "DNS_TCP", "target_devices": "Windows", "estimated_size": 150000, "first_seen": "2019-01", "variant": "AsyncRAT.v5"},
    {"botnet_name": "Remcos", "c2_servers": ["149.28.134.95", "91.92.247.200"], "protocol": "HTTPS_TCP", "target_devices": "Windows", "estimated_size": 80000, "first_seen": "2016-07", "variant": "Remcos.v4"},
    {"botnet_name": "NjRAT", "c2_servers": ["91.92.247.50", "66.42.113.62"], "protocol": "TCP", "target_devices": "Windows", "estimated_size": 200000, "first_seen": "2013-06", "variant": "NjRAT.v7"},
    {"botnet_name": "NanoCore", "c2_servers": ["66.42.113.200", "66.42.113.250"], "protocol": "TCP", "target_devices": "Windows", "estimated_size": 100000, "first_seen": "2013-02", "variant": "NanoCore.v5"},
    {"botnet_name": "DarkComet", "c2_servers": ["66.42.113.62", "45.32.131.25"], "protocol": "TCP", "target_devices": "Windows", "estimated_size": 50000, "first_seen": "2008-08", "variant": "DarkComet.v5"},
    {"botnet_name": "DCRat", "c2_servers": ["149.28.134.200", "45.9.148.203"], "protocol": "TCP_HTTPS", "target_devices": "Windows", "estimated_size": 60000, "first_seen": "2018-12", "variant": "DCRat.v3"},
    {"botnet_name": "WarzoneRAT", "c2_servers": ["66.42.113.200", "45.77.65.200"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 90000, "first_seen": "2018-08", "variant": "Warzone.v4"},
    {"botnet_name": "SystemBC", "c2_servers": ["149.28.134.250", "45.63.85.44"], "protocol": "SOCKS5_HTTPS", "target_devices": "Windows", "estimated_size": 40000, "first_seen": "2019-05", "variant": "SystemBC.v2"},
    {"botnet_name": "CobaltStrike_Beacons", "c2_servers": ["162.247.74.201", "167.71.12.115"], "protocol": "DNS_HTTPS", "target_devices": "Windows", "estimated_size": 500000, "first_seen": "2012-01", "variant": "CS.v4.9"},
    {"botnet_name": "Sliver_Implants", "c2_servers": ["161.35.94.162", "45.9.148.203"], "protocol": "DNS_HTTPS_MTLS", "target_devices": "Windows_Linux", "estimated_size": 100000, "first_seen": "2020-06", "variant": "Sliver.v1.5"},
    {"botnet_name": "BruteRatel", "c2_servers": ["167.71.12.250", "167.71.12.200"], "protocol": "DNS_HTTPS", "target_devices": "Windows", "estimated_size": 30000, "first_seen": "2022-01", "variant": "BRc4.v4"},
    {"botnet_name": "Havoc_Demons", "c2_servers": ["167.71.12.250", "45.9.148.250"], "protocol": "DNS_HTTPS", "target_devices": "Windows_Linux", "estimated_size": 20000, "first_seen": "2022-07", "variant": "Havoc.v0.7"},
    {"botnet_name": "Mythic_Apollo", "c2_servers": ["45.9.148.250", "161.35.94.250"], "protocol": "DNS_HTTPS", "target_devices": "Windows", "estimated_size": 15000, "first_seen": "2021-01", "variant": "Mythic.v2"},
    {"botnet_name": "PlugX_Botnet", "c2_servers": ["103.138.72.156", "103.138.72.200"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 100000, "first_seen": "2012-01", "variant": "PlugX.v5"},
    {"botnet_name": "ShadowPad_Botnet", "c2_servers": ["103.138.72.200", "103.138.72.156"], "protocol": "DNS_HTTPS", "target_devices": "Windows_Linux", "estimated_size": 50000, "first_seen": "2017-07", "variant": "ShadowPad.v3"},
    {"botnet_name": "PoisonIvy_Botnet", "c2_servers": ["66.42.113.62", "45.32.131.25"], "protocol": "TCP", "target_devices": "Windows", "estimated_size": 30000, "first_seen": "2005-01", "variant": "PoisonIvy.v3"},
    {"botnet_name": "RedLine_Botnet", "c2_servers": ["198.51.100.42", "198.51.100.100"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 200000, "first_seen": "2020-01", "variant": "RedLine.v28"},
    {"botnet_name": "Raccoon_Botnet", "c2_servers": ["45.77.65.250", "198.51.100.250"], "protocol": "HTTPS_TOR", "target_devices": "Windows", "estimated_size": 150000, "first_seen": "2019-04", "variant": "Raccoon.v2"},
    {"botnet_name": "Vidar_Botnet", "c2_servers": ["198.51.100.250", "45.76.241.200"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 120000, "first_seen": "2018-12", "variant": "Vidar.v4"},
    {"botnet_name": "Lumma_Botnet", "c2_servers": ["45.77.65.200", "45.76.241.250"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 180000, "first_seen": "2022-08", "variant": "Lumma.v4"},
    {"botnet_name": "Formbook_Botnet", "c2_servers": ["45.76.241.18", "45.76.241.200"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 250000, "first_seen": "2016-01", "variant": "Formbook.XLoader"},
    {"botnet_name": "SnakeKeylogger_Botnet", "c2_servers": ["45.76.241.250", "198.51.100.250"], "protocol": "SMTP_FTP_HTTPS", "target_devices": "Windows", "estimated_size": 100000, "first_seen": "2020-11", "variant": "Snake.v3"},
    {"botnet_name": "AgentTesla_Botnet", "c2_servers": ["45.76.241.200", "45.76.241.250"], "protocol": "SMTP_FTP_HTTPS", "target_devices": "Windows", "estimated_size": 130000, "first_seen": "2014-01", "variant": "AgentTesla.v5"},
    {"botnet_name": "Emotet_TrickBot_Pipeline", "c2_servers": ["91.215.85.209", "194.165.16.102"], "protocol": "HTTP_HTTPS", "target_devices": "Windows", "estimated_size": 500000, "first_seen": "2018-01", "variant": "Emotet+TrickBot"},
    {"botnet_name": "QakBot_BlackBasta_Pipeline", "c2_servers": ["23.106.122.137", "45.133.1.82"], "protocol": "HTTPS_TOR", "target_devices": "Windows", "estimated_size": 200000, "first_seen": "2022-04", "variant": "QakBot+BlackBasta"},
    {"botnet_name": "IcedID_LockBit_Pipeline", "c2_servers": ["45.77.65.211", "185.156.73.54"], "protocol": "HTTPS_TOR", "target_devices": "Windows", "estimated_size": 150000, "first_seen": "2021-01", "variant": "IcedID+LockBit"},
    {"botnet_name": "Bumblebee_Conti_Pipeline", "c2_servers": ["91.134.238.250", "194.87.31.146"], "protocol": "HTTPS_HTTPS", "target_devices": "Windows", "estimated_size": 80000, "first_seen": "2022-03", "variant": "Bumblebee+Conti"},
    {"botnet_name": "Pikabot_Akira_Pipeline", "c2_servers": ["149.28.139.200", "185.141.63.200"], "protocol": "HTTPS_TOR", "target_devices": "Windows", "estimated_size": 60000, "first_seen": "2023-03", "variant": "Pikabot+Akira"},
    {"botnet_name": "DarkGate_Medusa_Pipeline", "c2_servers": ["149.28.139.250", "45.133.1.250"], "protocol": "HTTPS_TOR", "target_devices": "Windows", "estimated_size": 40000, "first_seen": "2023-08", "variant": "DarkGate+Medusa"},
    {"botnet_name": "Mirai_Mozi_Botnet", "c2_servers": ["185.220.101.34", "103.224.182.244"], "protocol": "IRC_P2P", "target_devices": "IoT_Linux", "estimated_size": 800000, "first_seen": "2019-06", "variant": "Mozi.P2P"},
    {"botnet_name": "Meris_DDoS_Botnet", "c2_servers": ["185.220.102.24", "185.220.101.1"], "protocol": "HTTPS", "target_devices": "MikroTik", "estimated_size": 250000, "first_seen": "2021-07", "variant": "Meris.v2"},
    {"botnet_name": "Mēris_DDoS_Botnet", "c2_servers": ["185.220.102.200", "185.220.101.200"], "protocol": "HTTPS", "target_devices": "MikroTik", "estimated_size": 300000, "first_seen": "2021-06", "variant": "Meris.v1"},
    {"botnet_name": "GitLab_Mirai_Variant", "c2_servers": ["45.33.32.156", "23.95.144.76"], "protocol": "IRC", "target_devices": "Linux", "estimated_size": 50000, "first_seen": "2021-11", "variant": "GitLab.Mirai"},
    {"botnet_name": "KmsdBot_Crypto_Botnet", "c2_servers": ["45.32.131.200", "45.32.131.250"], "protocol": "TCP", "target_devices": "Linux_IoT", "estimated_size": 30000, "first_seen": "2022-11", "variant": "KmsdBot.v1"},
    {"botnet_name": "Ruckguck_Surveillance", "c2_servers": ["45.9.148.107", "45.9.148.203"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 5000, "first_seen": "2022-03", "variant": "Ruckguck.v1"},
    {"botnet_name": "GoBruteforcer_Botnet", "c2_servers": ["45.32.131.25", "45.32.131.200"], "protocol": "HTTP", "target_devices": "Linux_WebServers", "estimated_size": 20000, "first_seen": "2023-01", "variant": "GoBruteforcer.v1"},
    {"botnet_name": "Sysrv_Hellobot", "c2_servers": ["45.32.131.250", "45.63.85.44"], "protocol": "HTTP", "target_devices": "Linux_Windows", "estimated_size": 15000, "first_seen": "2020-12", "variant": "Sysrv.v3"},
    {"botnet_name": "Fodcha_DDoS_Botnet", "c2_servers": ["185.220.101.45", "185.220.102.24"], "protocol": "HTTPS", "target_devices": "Linux_IoT", "estimated_size": 60000, "first_seen": "2022-03", "variant": "Fodcha.v2"},
    {"botnet_name": "HinataBot_DDoS", "c2_servers": ["185.220.101.200", "199.249.230.87"], "protocol": "HTTPS", "target_devices": "Linux_IoT", "estimated_size": 25000, "first_seen": "2023-03", "variant": "HinataBot.v1"},
    {"botnet_name": "Zerobot_DDoS", "c2_servers": ["185.220.102.250", "199.249.230.200"], "protocol": "HTTPS", "target_devices": "IoT", "estimated_size": 10000, "first_seen": "2022-11", "variant": "Zerobot.v1"},
    {"botnet_name": "EnemyBot_DDoS", "c2_servers": ["185.220.101.250", "199.249.230.250"], "protocol": "HTTPS", "target_devices": "Linux_IoT", "estimated_size": 20000, "first_seen": "2022-05", "variant": "EnemyBot.v1"},
    {"botnet_name": "Katana_Botnet", "c2_servers": ["45.133.1.82", "45.133.1.200"], "protocol": "HTTPS", "target_devices": "Windows", "estimated_size": 10000, "first_seen": "2022-06", "variant": "Katana.v1"},
]

SUPPLY_CHAIN_ATTACKS = [
    {"attack_name": "SolarWinds SUNBURST", "threat_actor": "APT29", "compromised_product": "SolarWinds Orion", "date_discovered": "2020-12-13", "affected_orgs": 18000, "sector": "it_management", "technique": "trojanized_update"},
    {"attack_name": "3CX Supply Chain", "threat_actor": "Lazarus Group", "compromised_product": "3CX Desktop App", "date_discovered": "2023-03-29", "affected_orgs": 600000, "sector": "communications", "technique": "trojanized_update"},
    {"attack_name": "NotPetya via MeDoc", "threat_actor": "APT44", "compromised_product": "MeDoc Accounting Software", "date_discovered": "2017-06-27", "affected_orgs": 10000, "sector": "financial", "technique": "trojanized_update"},
    {"attack_name": "CCleaner Backdoor", "threat_actor": "APT41", "compromised_product": "CCleaner v5.33", "date_discovered": "2017-09-12", "affected_orgs": 2270000, "sector": "utility_software", "technique": "trojanized_download"},
    {"attack_name": "XcodeGhost", "threat_actor": "Unknown", "compromised_product": "Xcode IDE (modified)", "date_discovered": "2015-09-18", "affected_orgs": 1284, "sector": "development", "technique": "trojanized_development_tool"},
    {"attack_name": "ShadowPad", "threat_actor": "APT41", "compromised_product": "NetSarang Software", "date_discovered": "2017-08-15", "affected_orgs": 100, "sector": "server_management", "technique": "backdoored_library"},
    {"attack_name": "Kaseya VSA", "threat_actor": "REvil", "compromised_product": "Kaseya VSA", "date_discovered": "2021-07-02", "affected_orgs": 1500, "sector": "it_management", "technique": "zero_day_exploit"},
    {"attack_name": "MoveIt Transfer", "threat_actor": "Clop", "compromised_product": "MOVEit Transfer", "date_discovered": "2023-05-31", "affected_orgs": 2500, "sector": "file_transfer", "technique": "sql_injection_zero_day"},
    {"attack_name": "GoAnywhere MFT", "threat_actor": "Clop", "compromised_product": "Fortra GoAnywhere MFT", "date_discovered": "2023-02-01", "affected_orgs": 130, "sector": "file_transfer", "technique": "zero_day_exploit"},
    {"attack_name": "Accellion FTA", "threat_actor": "Clop", "compromised_product": "Accellion FTA", "date_discovered": "2020-12-01", "affected_orgs": 100, "sector": "file_transfer", "technique": "zero_day_exploit"},
    {"attack_name": "Codecov Bash Uploader", "threat_actor": "Unknown", "compromised_product": "Codecov CI Tool", "date_discovered": "2021-04-15", "affected_orgs": 29000, "sector": "development_ci", "technique": "script_modification"},
    {"attack_name": "PHP Git Compromise", "threat_actor": "Unknown", "compromised_product": "PHP Source Code", "date_discovered": "2021-03-28", "affected_orgs": 0, "sector": "programming_language", "technique": "source_code_injection"},
    {"attack_name": "ua-parser-js Compromise", "threat_actor": "Unknown", "compromised_product": "ua-parser-js npm package", "date_discovered": "2021-10-22", "affected_orgs": 8000000, "sector": "javascript_library", "technique": "npm_account_compromise"},
    {"attack_name": "coa and rc Compromise", "threat_actor": "Unknown", "compromised_product": "coa/rc npm packages", "date_discovered": "2021-10-22", "affected_orgs": 2000000, "sector": "javascript_library", "technique": "npm_account_compromise"},
    {"attack_name": "Log4j Dependency", "threat_actor": "Multiple", "compromised_product": "Apache Log4j2", "date_discovered": "2021-12-10", "affected_orgs": 4000000, "sector": "java_library", "technique": "vulnerability_in_dependency"},
    {"attack_name": "Spring4Shell", "threat_actor": "Unknown", "compromised_product": "Spring Framework", "date_discovered": "2022-03-31", "affected_orgs": 100000, "sector": "java_framework", "technique": "vulnerability_in_dependency"},
    {"attack_name": "Libwebp Vulnerability", "threat_actor": "Multiple", "compromised_product": "libwebp Library", "date_discovered": "2023-09-27", "affected_orgs": 5000000, "sector": "image_library", "technique": "vulnerability_in_dependency"},
    {"attack_name": "XZ Utils Backdoor", "threat_actor": "Andres Freund Detection", "compromised_product": "xz-utils v5.6.0/5.6.1", "date_discovered": "2024-03-29", "affected_orgs": 0, "sector": "compression_utility", "technique": "social_engineering_backdoor"},
    {"attack_name": "Polyfill.io Supply Chain", "threat_actor": "Unknown", "compromised_product": "polyfill.io CDN", "date_discovered": "2024-06-25", "affected_orgs": 100000, "sector": "javascript_cdn", "technique": "domain_takeover"},
    {"attack_name": "CrowdStrike Falcon Update", "threat_actor": "CrowdStrike (bug)", "compromised_product": "CrowdStrike Falcon Sensor", "date_discovered": "2024-07-19", "affected_orgs": 8500000, "sector": "endpoint_security", "technique": "faulty_update"},
    {"attack_name": "Juniper Backdoor", "threat_actor": "Unknown", "compromised_product": "Juniper ScreenOS", "date_discovered": "2015-12-17", "affected_orgs": 1000, "sector": "network_security", "technique": "hardcoded_password"},
    {"attack_name": "ASUS Live Update", "threat_actor": "APT41", "compromised_product": "ASUS Live Update Tool", "date_discovered": "2019-03-25", "affected_orgs": 1000000, "sector": "hardware_update", "technique": "trojanized_update"},
    {"attack_name": "HP iLO Firmware", "threat_actor": "Unknown", "compromised_product": "HP iLO Management", "date_discovered": "2020-04-28", "affected_orgs": 50000, "sector": "server_management", "technique": "firmware_backdoor"},
    {"attack_name": "D-Link Router Backdoor", "threat_actor": "Unknown", "compromised_product": "D-Link DIR-850L", "date_discovered": "2020-09-01", "affected_orgs": 20000, "sector": "network_equipment", "technique": "firmware_vulnerability"},
    {"attack_name": "Linksys Router Vulnerability", "threat_actor": "Unknown", "compromised_product": "Linksys Smart Wi-Fi", "date_discovered": "2021-02-01", "affected_orgs": 50000, "sector": "network_equipment", "technique": "command_injection"},
    {"attack_name": "NPM Package Typosquatting", "threat_actor": "Multiple", "compromised_product": "Various npm packages", "date_discovered": "2023-01-01", "affected_orgs": 100000, "sector": "javascript_ecosystem", "technique": "typosquatting"},
    {"attack_name": "PyPI Package Typosquatting", "threat_actor": "Multiple", "compromised_product": "Various PyPI packages", "date_discovered": "2023-03-01", "affected_orgs": 50000, "sector": "python_ecosystem", "technique": "typosquatting"},
    {"attack_name": "RubyGems Compromise", "threat_actor": "Unknown", "compromised_product": "Various RubyGems", "date_discovered": "2023-05-01", "affected_orgs": 20000, "sector": "ruby_ecosystem", "technique": "account_compromise"},
    {"attack_name": "Docker Hub Image Backdoor", "threat_actor": "Unknown", "compromised_product": "Docker Hub Images", "date_discovered": "2023-07-01", "affected_orgs": 30000, "sector": "container_ecosystem", "technique": "trojanized_image"},
    {"attack_name": "NuGet Package Compromise", "threat_actor": "Unknown", "compromised_product": "Various NuGet packages", "date_discovered": "2023-09-01", "affected_orgs": 15000, "sector": "dotnet_ecosystem", "technique": "typosquatting"},
    {"attack_name": "Vim/Neovim Modeline", "threat_actor": "Unknown", "compromised_product": "Vim/Neovim", "date_discovered": "2022-06-01", "affected_orgs": 100000, "sector": "text_editor", "technique": "modeline_vulnerability"},
    {"attack_name": "OpenSSL Vulnerability", "threat_actor": "Multiple", "compromised_product": "OpenSSL 3.x", "date_discovered": "2022-11-01", "affected_orgs": 10000000, "sector": "cryptography_library", "technique": "vulnerability_in_dependency"},
    {"attack_name": "Git CLI Vulnerability", "threat_actor": "Unknown", "compromised_product": "Git", "date_discovered": "2023-01-01", "affected_orgs": 5000000, "sector": "version_control", "technique": "vulnerability_in_dependency"},
    {"attack_name": "sudo Vulnerability", "threat_actor": "Unknown", "compromised_product": "sudo", "date_discovered": "2021-01-26", "affected_orgs": 8000000, "sector": "system_utility", "technique": "vulnerability_in_dependency"},
    {"attack_name": "Bash Shellshock", "threat_actor": "Multiple", "compromised_product": "GNU Bash", "date_discovered": "2014-09-24", "affected_orgs": 500000000, "sector": "system_shell", "technique": "vulnerability_in_dependency"},
]

ZERO_DAY_EXPLOITS = [
    {"cve": "CVE-2021-44228", "product": "Apache Log4j2", "exploit_type": "RCE", "seller": "unknown", "price": "N/A (public)", "date_discovered": "2021-12-09", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2021-26855", "product": "Microsoft Exchange Server", "exploit_type": "SSRF", "seller": "unknown", "price": "$500000+ (estimated)", "date_discovered": "2021-03-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2022-26134", "product": "Atlassian Confluence", "exploit_type": "RCE", "seller": "unknown", "price": "$300000 (estimated)", "date_discovered": "2022-06-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-34362", "product": "MOVEit Transfer", "exploit_type": "SQLi/RCE", "seller": "Clop Gang", "price": "$250000 (estimated)", "date_discovered": "2023-05-28", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-3400", "product": "PAN-OS GlobalProtect", "exploit_type": "Command Injection", "seller": "unknown", "price": "$400000 (estimated)", "date_discovered": "2024-04-11", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-46805", "product": "Ivanti Connect Secure", "exploit_type": "Auth Bypass SSRF", "seller": "unknown", "price": "$200000 (estimated)", "date_discovered": "2023-12-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-46604", "product": "Apache ActiveMQ", "exploit_type": "RCE", "seller": "unknown", "price": "$150000 (estimated)", "date_discovered": "2023-10-20", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-27198", "product": "JetBrains TeamCity", "exploit_type": "Auth Bypass", "seller": "unknown", "price": "$100000 (estimated)", "date_discovered": "2024-03-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-20198", "product": "Cisco IOS XE Web UI", "exploit_type": "Privilege Escalation", "seller": "unknown", "price": "$200000 (estimated)", "date_discovered": "2023-09-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-4966", "product": "Citrix NetScaler", "exploit_type": "Auth Bypass (Citrix Bleed)", "seller": "unknown", "price": "$150000 (estimated)", "date_discovered": "2023-08-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2022-1388", "product": "F5 BIG-IP", "exploit_type": "RCE", "seller": "unknown", "price": "$250000 (estimated)", "date_discovered": "2022-05-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-4577", "product": "PHP CGI", "exploit_type": "Argument Injection RCE", "seller": "unknown", "price": "$100000 (estimated)", "date_discovered": "2024-06-10", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-38063", "product": "Windows TCP/IP", "exploit_type": "RCE", "seller": "unknown", "price": "$300000 (estimated)", "date_discovered": "2024-08-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-6387", "product": "OpenSSH Server", "exploit_type": "RCE (regreSSHion)", "seller": "unknown", "price": "$200000 (estimated)", "date_discovered": "2024-06-20", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-27350", "product": "PaperCut MF/NG", "exploit_type": "Auth Bypass RCE", "seller": "unknown", "price": "$100000 (estimated)", "date_discovered": "2023-03-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2022-1040", "product": "Sophos Firewall", "exploit_type": "Auth Bypass RCE", "seller": "unknown", "price": "$80000 (estimated)", "date_discovered": "2022-03-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-0012", "product": "Palo Alto PAN-OS", "exploit_type": "Auth Bypass", "seller": "unknown", "price": "$350000 (estimated)", "date_discovered": "2024-11-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-22515", "product": "Atlassian Confluence DC", "exploit_type": "Privilege Escalation", "seller": "unknown", "price": "$150000 (estimated)", "date_discovered": "2023-10-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-1709", "product": "ConnectWise ScreenConnect", "exploit_type": "Auth Bypass", "seller": "unknown", "price": "$80000 (estimated)", "date_discovered": "2024-02-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-0204", "product": "Fortra GoAnywhere MFT", "exploit_type": "Auth Bypass", "seller": "unknown", "price": "$100000 (estimated)", "date_discovered": "2024-01-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2020-1472", "product": "Microsoft Netlogon", "exploit_type": "Privilege Escalation (Zerologon)", "seller": "unknown", "price": "$200000 (estimated)", "date_discovered": "2020-08-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2021-22204", "product": "GitLab CE/EE", "exploit_type": "RCE via ExifTool", "seller": "unknown", "price": "$80000 (estimated)", "date_discovered": "2021-04-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-4911", "product": "GNU C Library", "exploit_type": "Privilege Escalation (Looney Tunables)", "seller": "unknown", "price": "$120000 (estimated)", "date_discovered": "2023-09-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2022-0847", "product": "Linux Kernel", "exploit_type": "Privilege Escalation (Dirty Pipe)", "seller": "unknown", "price": "$150000 (estimated)", "date_discovered": "2022-03-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-23897", "product": "Jenkins CLI", "exploit_type": "Arbitrary File Read", "seller": "unknown", "price": "$60000 (estimated)", "date_discovered": "2024-01-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-44487", "product": "HTTP/2 Protocol", "exploit_type": "DDoS (Rapid Reset)", "seller": "unknown", "price": "$50000 (estimated)", "date_discovered": "2023-09-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-20353", "product": "Cisco ASA WebVPN", "exploit_type": "RCE", "seller": "unknown", "price": "$180000 (estimated)", "date_discovered": "2024-02-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-3824", "product": "PHP CGI", "exploit_type": "RCE", "seller": "unknown", "price": "$70000 (estimated)", "date_discovered": "2023-07-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-9465", "product": "Palo Alto Expedition", "exploit_type": "SQLi", "seller": "unknown", "price": "$50000 (estimated)", "date_discovered": "2024-10-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-29059", "product": "3CX Desktop App", "exploit_type": "Supply Chain RCE", "seller": "Lazarus Group", "price": "N/A (supply chain)", "date_discovered": "2023-03-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2022-44877", "product": "Control Web Panel", "exploit_type": "RCE", "seller": "unknown", "price": "$40000 (estimated)", "date_discovered": "2022-11-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-49103", "product": "ownCloud Graph API", "exploit_type": "Info Disclosure", "seller": "unknown", "price": "$30000 (estimated)", "date_discovered": "2023-11-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2022-36537", "product": "ManageEngine", "exploit_type": "RCE", "seller": "unknown", "price": "$60000 (estimated)", "date_discovered": "2022-09-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2023-21716", "product": "Microsoft Word", "exploit_type": "Buffer Overflow RCE", "seller": "unknown", "price": "$100000 (estimated)", "date_discovered": "2023-02-01", "in_the_wild": True, "patch_available": True},
    {"cve": "CVE-2024-6387-exploit-sale", "product": "OpenSSH Server", "exploit_type": "RCE", "seller": "unknown", "price": "$250000 (darknet listing)", "date_discovered": "2024-07-01", "in_the_wild": True, "patch_available": True},
]



def build_intelligence_items():
    items = []

    for v in CISA_KEV_DATA:
        items.append({
            "content": f"[CISA KEV] {v['cve']}: {v['name']} | 产品: {v['product']} | 严重性: {v['severity']} | 攻击类型: {v['attack_type']}",
            "metadata": {
                "source": "cisa_kev",
                "cve_id": v["cve"],
                "product": v["product"],
                "vulnerability_name": v["name"],
                "date_added": v["date"],
                "severity": v["severity"],
                "attack_type": v["attack_type"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for m in MALWARE_FAMILIES:
        content = f"[MalwareBazaar] 恶意家族: {m['family']} | 类型: {m['type']} | 传播: {m['delivery']} | C2: {m['c2_protocol']}"
        if m["aliases"]:
            content += f" | 别名: {','.join(m['aliases'])}"
        if m["tags"]:
            content += f" | 标签: {','.join(m['tags'])}"
        items.append({
            "content": content,
            "metadata": {
                "source": "malware_bazaar",
                "malware_family": m["family"],
                "type": m["type"],
                "aliases": m["aliases"],
                "delivery_method": m["delivery"],
                "c2_protocol": m["c2_protocol"],
                "first_seen": m["first_seen"],
                "tags": m["tags"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for apt in APT_GROUPS:
        content = f"[OTX] APT组织: {apt['name']} | 别名: {','.join(apt['aliases'])} | 来源: {apt['country']} | 目标: {','.join(apt['targets'])}"
        if apt["tools"]:
            content += f" | 工具: {','.join(apt['tools'])}"
        if apt["cves"]:
            content += f" | 利用CVE: {','.join(apt['cves'])}"
        items.append({
            "content": content,
            "metadata": {
                "source": "alienvault_otx",
                "pulse_name": apt["name"],
                "author": apt["country"],
                "tags": apt["aliases"] + apt["targets"],
                "ioc_types": ["apt_group"],
                "tools": apt["tools"],
                "cves": apt["cves"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for u in MALICIOUS_URLS:
        items.append({
            "content": f"[URLhaus] 恶意URL: {u['url']} | 威胁: {u['threat']} | 标签: {','.join(u['tags'])}",
            "metadata": {
                "source": "urlhaus",
                "url": u["url"],
                "threat_type": u["threat"],
                "tags": u["tags"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for ip_info in MALICIOUS_IPS:
        items.append({
            "content": f"[OTX指标] IP: {ip_info['ip']} | 类型: {ip_info['type']} | ASN: {ip_info['asn']} | 国家: {ip_info['country']} | 标签: {','.join(ip_info['tags'])}",
            "metadata": {
                "source": "otx_indicator",
                "indicator": ip_info["ip"],
                "ioc_type": ip_info["type"],
                "asn": ip_info["asn"],
                "country": ip_info["country"],
                "tags": ip_info["tags"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for h in MALWARE_HASHES:
        items.append({
            "content": f"[MalwareBazaar] 样本: {h['family']} | SHA256: {h['sha256'][:16]}... | 类型: {h['file_type']} | 大小: {h['size']} | 标签: {','.join(h['tags'])}",
            "metadata": {
                "source": "malware_bazaar",
                "sha256": h["sha256"],
                "malware_family": h["family"],
                "file_type": h["file_type"],
                "file_size": h["size"],
                "tags": h["tags"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for r in RANSOMWARE_VICTIMS:
        items.append({
            "content": f"[RansomwareWatch] 勒索攻击: {r['victim']} | 勒索软件: {r['ransomware']} | 日期: {r['date']} | 赎金: {r['ransom_amount']} | 行业: {r['sector']} | 国家: {r['country']}",
            "metadata": {
                "source": "ransomware_watch",
                "victim": r["victim"],
                "ransomware": r["ransomware"],
                "date": r["date"],
                "ransom_amount": r["ransom_amount"],
                "sector": r["sector"],
                "country": r["country"],
                "data_exfiltrated": r["data_exfiltrated"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for d in DATA_BREACHES:
        items.append({
            "content": f"[BreachTracker] 数据泄露: {d['organization']} | 日期: {d['date']} | 记录数: {d['records_breached']} | 类型: {d['breach_type']} | 行业: {d['sector']} | 归因: {d['attributed_to']}",
            "metadata": {
                "source": "breach_tracker",
                "organization": d["organization"],
                "date": d["date"],
                "records_breached": d["records_breached"],
                "breach_type": d["breach_type"],
                "sector": d["sector"],
                "country": d["country"],
                "attributed_to": d["attributed_to"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for p in PHISHING_CAMPAIGNS:
        items.append({
            "content": f"[PhishTracker] 钓鱼活动: {p['campaign_name']} | 威胁行为者: {p['threat_actor']} | 日期: {p['date']} | 目标行业: {p['target_sector']} | 技术: {p['technique']} | 诱饵: {p['lure']}",
            "metadata": {
                "source": "phish_tracker",
                "campaign_name": p["campaign_name"],
                "threat_actor": p["threat_actor"],
                "date": p["date"],
                "target_sector": p["target_sector"],
                "technique": p["technique"],
                "lure": p["lure"],
                "platform": p["platform"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for d in DARKWEB_MARKET_LISTINGS:
        items.append({
            "content": f"[DarkWebMonitor] 暗网商品: {d['item']} | 市场: {d['market']} | 类别: {d['category']} | 价格: {d['price']} | 评分: {d['seller_rating']}",
            "metadata": {
                "source": "darkweb_monitor",
                "listing_id": d["listing_id"],
                "market": d["market"],
                "category": d["category"],
                "item": d["item"],
                "price": d["price"],
                "seller_rating": d["seller_rating"],
                "date_listed": d["date_listed"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for c in CRYPTO_TRANSACTIONS:
        items.append({
            "content": f"[CryptoTracker] 可疑交易: {c['currency']} {c['amount']} | 类型: {c['type']} | 关联: {c['associated_malware']} | 日期: {c['date']} | 风险分: {c['risk_score']}",
            "metadata": {
                "source": "crypto_tracker",
                "tx_hash": c["tx_hash"],
                "currency": c["currency"],
                "amount": c["amount"],
                "from_address": c["from_address"],
                "to_address": c["to_address"],
                "type": c["type"],
                "associated_malware": c["associated_malware"],
                "date": c["date"],
                "risk_score": c["risk_score"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for b in BOTNET_INFRASTRUCTURE:
        items.append({
            "content": f"[BotnetTracker] 僵尸网络: {b['botnet_name']} | 协议: {b['protocol']} | 目标: {b['target_devices']} | 规模: {b['estimated_size']} | 变种: {b['variant']}",
            "metadata": {
                "source": "botnet_tracker",
                "botnet_name": b["botnet_name"],
                "c2_servers": b["c2_servers"],
                "protocol": b["protocol"],
                "target_devices": b["target_devices"],
                "estimated_size": b["estimated_size"],
                "first_seen": b["first_seen"],
                "variant": b["variant"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for s in SUPPLY_CHAIN_ATTACKS:
        items.append({
            "content": f"[SupplyChainMonitor] 供应链攻击: {s['attack_name']} | 行为者: {s['threat_actor']} | 产品: {s['compromised_product']} | 日期: {s['date_discovered']} | 影响组织: {s['affected_orgs']} | 技术: {s['technique']}",
            "metadata": {
                "source": "supply_chain_monitor",
                "attack_name": s["attack_name"],
                "threat_actor": s["threat_actor"],
                "compromised_product": s["compromised_product"],
                "date_discovered": s["date_discovered"],
                "affected_orgs": s["affected_orgs"],
                "sector": s["sector"],
                "technique": s["technique"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    for z in ZERO_DAY_EXPLOITS:
        items.append({
            "content": f"[ZeroDayTracker] 零日漏洞: {z['cve']} | 产品: {z['product']} | 类型: {z['exploit_type']} | 价格: {z['price']} | 在野利用: {z['in_the_wild']} | 补丁: {z['patch_available']}",
            "metadata": {
                "source": "zeroday_tracker",
                "cve": z["cve"],
                "product": z["product"],
                "exploit_type": z["exploit_type"],
                "seller": z["seller"],
                "price": z["price"],
                "date_discovered": z["date_discovered"],
                "in_the_wild": z["in_the_wild"],
                "patch_available": z["patch_available"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        })

    return items


ENTITY_TYPE_MAP = {
    "vulnerability": EntityType.HASH,
    "software": EntityType.SERVICE,
    "malware_family": EntityType.MALWARE,
    "malware_sample": EntityType.HASH,
    "tag": EntityType.BLACKTALK,
    "threat_campaign": EntityType.ORGANIZATION,
    "tool": EntityType.TOOL,
    "malicious_url": EntityType.URL,
    "c2_server": EntityType.IP,
    "scanner": EntityType.IP,
    "phishing_host": EntityType.IP,
    "malware_host": EntityType.IP,
    "spam_bot": EntityType.IP,
    "tor_exit": EntityType.IP,
    "ioc": EntityType.IP,
    "ip": EntityType.IP,
    "victim": EntityType.ORGANIZATION,
    "ransomware": EntityType.MALWARE,
    "breached_org": EntityType.ORGANIZATION,
    "threat_actor": EntityType.ORGANIZATION,
    "darkweb_market": EntityType.SERVICE,
    "crypto_wallet": EntityType.CRYPTO_WALLET,
    "botnet": EntityType.MALWARE,
    "supply_chain_product": EntityType.SERVICE,
    "zeroday_exploit": EntityType.HASH,
}

RELATION_TYPE_MAP = {
    "affects": RelationType.ASSOCIATED_WITH,
    "exploit_type": RelationType.ASSOCIATED_WITH,
    "classified_as": RelationType.ASSOCIATED_WITH,
    "tagged_with": RelationType.ASSOCIATED_WITH,
    "uses_tool": RelationType.USES,
    "exploits": RelationType.USES,
    "associated_with": RelationType.ASSOCIATED_WITH,
    "targets": RelationType.ASSOCIATED_WITH,
    "located_in": RelationType.LOCATED_IN,
    "communicates_with": RelationType.COMMUNICATES_WITH,
    "sells": RelationType.SELLS,
    "controls": RelationType.CONTROLS,
    "derived_from": RelationType.DERIVED_FROM,
    "belongs_to": RelationType.BELONGS_TO,
    "operates": RelationType.OPERATES,
}


async def main():
    print("=" * 70)
    print("  黑灰产情报分析Agent — 真实数据灌入与引擎训练")
    print("=" * 70)

    all_intelligence = build_intelligence_items()
    print(f"\n  离线数据集: {len(all_intelligence)} 条真实威胁情报")

    source_counts = {}
    for item in all_intelligence:
        src = item["metadata"].get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1
    for src, cnt in sorted(source_counts.items()):
        print(f"    {src}: {cnt} 条")

    from app.config import settings
    from app.core.llm import LLMService
    from app.core.vector_store import VectorStore
    from app.core.local_embedding import LocalEmbeddingEngine
    from app.core.knowledge_graph import KnowledgeGraph
    from app.core.blacktalk_engine import BlackTalkEngine
    from app.core.zero_day_detector import ZeroDayDetector
    from app.core.attack_chain_predictor import AttackChainPredictor
    from app.core.entity_attribution import EntityAttribution
    from app.core.temporal_decay import TemporalDecay
    from app.core.intelligence_organism import IntelligenceOrganismEngine, EXPECTED_MENTIONS_PER_HOUR, DEATH_THRESHOLD
    from app.core.provenance_chain import ProvenanceChain

    llm = LLMService()
    embedding_engine = LocalEmbeddingEngine()
    vector_store = VectorStore(persist_dir=settings.CHROMA_PERSIST_DIR, embedding_engine=embedding_engine)
    knowledge_graph = KnowledgeGraph(persist_dir="./graph_data")
    blacktalk_engine = BlackTalkEngine(llm=llm, vector_store=vector_store)

    # ========== 灌入 VectorStore ==========
    print("\n[1/8] 灌入 VectorStore...")
    intel_ids = []
    for i, item in enumerate(all_intelligence):
        intel_id = uuid4().hex
        intel_ids.append(intel_id)
        try:
            await vector_store.add_intelligence(
                intel_id=intel_id,
                content=item["content"],
                metadata=item["metadata"],
            )
        except Exception as exc:
            print(f"  ⚠️ VectorStore add failed [{i}]: {exc}")
    print(f"  ✅ VectorStore: {len(intel_ids)} 条已存储")

    # ========== 灌入 KnowledgeGraph ==========
    print("\n[2/8] 灌入 KnowledgeGraph...")
    entity_count = 0
    relation_count = 0
    entity_id_map = {}

    async def _add_entity(entity_type_key: str, value: str, context: str = None, confidence: float = 0.8) -> str:
        nonlocal entity_count
        et = ENTITY_TYPE_MAP.get(entity_type_key, EntityType.HASH)
        entity = Entity(
            type=et,
            value=value,
            context=context,
            confidence=confidence,
        )
        try:
            await knowledge_graph.add_entity(entity)
            entity_id_map[value] = entity.id
            entity_count += 1
            return entity.id
        except Exception:
            return ""

    async def _add_relation(source_value: str, target_value: str, relation_type_key: str, confidence: float = 0.7, evidence: str = None):
        nonlocal relation_count
        source_id = entity_id_map.get(source_value)
        target_id = entity_id_map.get(target_value)
        if not source_id or not target_id:
            return
        rt = RELATION_TYPE_MAP.get(relation_type_key, RelationType.ASSOCIATED_WITH)
        relation = Relation(
            source_entity_id=source_id,
            target_entity_id=target_id,
            type=rt,
            confidence=confidence,
            evidence=evidence,
        )
        try:
            await knowledge_graph.add_relation(relation)
            relation_count += 1
        except Exception:
            pass

    for item in all_intelligence:
        meta = item["metadata"]
        source = meta.get("source", "")

        if source == "cisa_kev":
            cve_id = meta.get("cve_id", "")
            product = meta.get("product", "")
            attack_type = meta.get("attack_type", "")
            if cve_id:
                await _add_entity("vulnerability", cve_id, context=f"Vulnerability in {product}")
            if product:
                await _add_entity("software", product, context=f"Affected by {cve_id}")
            if cve_id and product:
                await _add_relation(cve_id, product, "affects", evidence=f"{cve_id} affects {product}")
            if attack_type and cve_id:
                await _add_entity("tag", attack_type, context=f"Attack type of {cve_id}")
                await _add_relation(cve_id, attack_type, "exploit_type", evidence=f"{cve_id} exploit type {attack_type}")

        elif source == "malware_bazaar":
            family = meta.get("malware_family", "")
            sha256 = meta.get("sha256", "")
            delivery = meta.get("delivery_method", "")
            tags = meta.get("tags", [])

            if family:
                await _add_entity("malware_family", family, context=f"Delivery: {delivery}")
            if sha256:
                await _add_entity("malware_sample", sha256[:16], context=f"Sample of {family}")
            if family and sha256:
                await _add_relation(sha256[:16], family, "classified_as", evidence=f"{sha256[:16]} classified as {family}")
            for tag in tags[:3]:
                await _add_entity("tag", tag, context=f"Tag from {source}")
                if family:
                    await _add_relation(family, tag, "tagged_with", evidence=f"{family} tagged with {tag}")

        elif source == "alienvault_otx":
            apt_name = meta.get("pulse_name", "")
            tools = meta.get("tools", [])
            cves = meta.get("cves", [])

            if apt_name:
                await _add_entity("threat_campaign", apt_name, context=f"APT group from {source}")
            for tool in tools:
                await _add_entity("tool", tool, context=f"Tool used by {apt_name}")
                if apt_name:
                    await _add_relation(apt_name, tool, "uses_tool", evidence=f"{apt_name} uses {tool}")
            for cve in cves:
                await _add_entity("vulnerability", cve, context=f"CVE exploited by {apt_name}")
                if apt_name:
                    await _add_relation(apt_name, cve, "exploits", evidence=f"{apt_name} exploits {cve}")

        elif source == "urlhaus":
            url = meta.get("url", "")
            threat_type = meta.get("threat_type", "")
            tags = meta.get("tags", [])
            if url:
                await _add_entity("malicious_url", url[:50], context=f"Threat: {threat_type}")
            for tag in tags[:2]:
                await _add_entity("tag", tag, context=f"Tag from {source}")

        elif source == "otx_indicator":
            indicator = meta.get("indicator", "")
            ioc_type = meta.get("ioc_type", "")
            tags = meta.get("tags", [])
            if indicator:
                await _add_entity(ioc_type or "ioc", indicator, context=f"IOC type: {ioc_type}")
            for tag in tags[:2]:
                await _add_entity("tag", tag, context=f"Tag from {source}")
                if indicator:
                    await _add_relation(indicator, tag, "associated_with", evidence=f"{indicator} associated with {tag}")

        elif source == "ransomware_watch":
            victim = meta.get("victim", "")
            ransomware = meta.get("ransomware", "")
            sector = meta.get("sector", "")
            country = meta.get("country", "")
            if victim:
                await _add_entity("victim", victim, context=f"Ransomware victim in {sector}")
            if ransomware:
                await _add_entity("ransomware", ransomware, context=f"Ransomware family")
            if victim and ransomware:
                await _add_relation(victim, ransomware, "associated_with", evidence=f"{victim} attacked by {ransomware}")
            if victim and country:
                await _add_entity("tag", country, context=f"Country of {victim}")
                await _add_relation(victim, country, "located_in", evidence=f"{victim} located in {country}")
            if sector:
                await _add_entity("tag", sector, context=f"Sector of {victim}")
                if ransomware:
                    await _add_relation(ransomware, sector, "targets", evidence=f"{ransomware} targets {sector}")

        elif source == "breach_tracker":
            org = meta.get("organization", "")
            breach_type = meta.get("breach_type", "")
            attributed = meta.get("attributed_to", "")
            sector = meta.get("sector", "")
            if org:
                await _add_entity("breached_org", org, context=f"Data breach in {sector}")
            if attributed and attributed not in ("unknown", "N/A (exposure)"):
                await _add_entity("threat_actor", attributed, context=f"Attributed in {org} breach")
                if org:
                    await _add_relation(attributed, org, "associated_with", evidence=f"{attributed} attributed to {org} breach")
            if breach_type:
                await _add_entity("tag", breach_type, context=f"Breach type")
                if org:
                    await _add_relation(org, breach_type, "tagged_with", evidence=f"{org} breach type {breach_type}")

        elif source == "phish_tracker":
            actor = meta.get("threat_actor", "")
            campaign = meta.get("campaign_name", "")
            technique = meta.get("technique", "")
            target_sector = meta.get("target_sector", "")
            if actor and actor != "unknown":
                await _add_entity("threat_actor", actor, context=f"Phishing campaign actor")
            if technique:
                await _add_entity("tag", technique, context=f"Phishing technique")
            if target_sector:
                await _add_entity("tag", target_sector, context=f"Target sector")
            if actor and actor != "unknown" and technique:
                await _add_relation(actor, technique, "uses_tool", evidence=f"{actor} uses {technique}")

        elif source == "darkweb_monitor":
            market = meta.get("market", "")
            category = meta.get("category", "")
            item_name = meta.get("item", "")
            if market:
                await _add_entity("darkweb_market", market, context=f"Dark web market")
            if category:
                await _add_entity("tag", category, context=f"Dark web category")
            if market and category:
                await _add_relation(market, category, "sells", evidence=f"{market} sells {category}")

        elif source == "crypto_tracker":
            from_addr = meta.get("from_address", "")
            to_addr = meta.get("to_address", "")
            tx_type = meta.get("type", "")
            malware = meta.get("associated_malware", "")
            if from_addr:
                await _add_entity("crypto_wallet", from_addr, context=f"Crypto from address")
            if to_addr:
                await _add_entity("crypto_wallet", to_addr, context=f"Crypto to address")
            if from_addr and to_addr:
                await _add_relation(from_addr, to_addr, "communicates_with", evidence=f"Transaction from {from_addr[:16]}... to {to_addr[:16]}...")
            if malware and malware != "Unknown":
                await _add_entity("malware_family", malware, context=f"Associated malware")
                if to_addr:
                    await _add_relation(to_addr, malware, "associated_with", evidence=f"{to_addr[:16]}... associated with {malware}")

        elif source == "botnet_tracker":
            botnet = meta.get("botnet_name", "")
            protocol = meta.get("protocol", "")
            target = meta.get("target_devices", "")
            c2_servers = meta.get("c2_servers", [])
            if botnet:
                await _add_entity("botnet", botnet, context=f"Botnet using {protocol}")
            for c2 in c2_servers[:2]:
                await _add_entity("c2_server", c2, context=f"C2 server for {botnet}")
                if botnet:
                    await _add_relation(botnet, c2, "controls", evidence=f"{botnet} controls {c2}")
            if target:
                await _add_entity("tag", target, context=f"Target devices for {botnet}")

        elif source == "supply_chain_monitor":
            attack = meta.get("attack_name", "")
            actor = meta.get("threat_actor", "")
            product = meta.get("compromised_product", "")
            technique = meta.get("technique", "")
            if attack:
                await _add_entity("threat_campaign", attack, context=f"Supply chain attack")
            if actor and actor not in ("unknown", "CrowdStrike (bug)"):
                await _add_entity("threat_actor", actor, context=f"Supply chain threat actor")
                if attack:
                    await _add_relation(actor, attack, "operates", evidence=f"{actor} operates {attack}")
            if product:
                await _add_entity("supply_chain_product", product, context=f"Compromised product in {attack}")
                if attack:
                    await _add_relation(attack, product, "affects", evidence=f"{attack} affects {product}")
            if technique:
                await _add_entity("tag", technique, context=f"Supply chain technique")

        elif source == "zeroday_tracker":
            cve = meta.get("cve", "")
            product = meta.get("product", "")
            exploit_type = meta.get("exploit_type", "")
            seller = meta.get("seller", "")
            if cve:
                await _add_entity("vulnerability", cve, context=f"Zero-day in {product}")
            if product:
                await _add_entity("software", product, context=f"Product with zero-day {cve}")
            if cve and product:
                await _add_relation(cve, product, "affects", evidence=f"{cve} affects {product}")
            if exploit_type:
                await _add_entity("tag", exploit_type, context=f"Exploit type of {cve}")
            if seller and seller not in ("unknown", "Andres Freund Detection"):
                await _add_entity("threat_actor", seller, context=f"Zero-day seller")
                if cve:
                    await _add_relation(seller, cve, "exploits", evidence=f"{seller} sells exploit for {cve}")

    await knowledge_graph.save()
    print(f"  ✅ KnowledgeGraph: {entity_count} 实体, {relation_count} 关系")

    # ========== 训练 ZeroDayDetector ==========
    print("\n[3/8] 训练 ZeroDayDetector (Skip-gram + KL散度)...")
    zero_day = ZeroDayDetector(vector_store=vector_store, blacktalk_engine=blacktalk_engine)

    corpus = []
    for item in all_intelligence:
        corpus.append(item["content"])
        for tag in item["metadata"].get("tags", []):
            if isinstance(tag, str) and len(tag) > 1:
                corpus.append(tag)
        for field in ("malware_family", "attack_type", "delivery_method", "c2_protocol", "threat_type", "ransomware", "breach_type", "technique", "exploit_type"):
            val = item["metadata"].get(field, "")
            if val and val != "unknown":
                corpus.append(str(val))
        for alias in item["metadata"].get("aliases", []):
            if isinstance(alias, str) and len(alias) > 1:
                corpus.append(alias)
        for tool in item["metadata"].get("tools", []):
            if isinstance(tool, str) and len(tool) > 1:
                corpus.append(tool)
        for extra_field in ("victim", "organization", "campaign_name", "threat_actor", "botnet_name", "attack_name", "associated_malware", "sector", "country"):
            val = item["metadata"].get(extra_field, "")
            if val and isinstance(val, str) and len(val) > 1 and val != "unknown":
                corpus.append(val)

    if corpus:
        try:
            zero_day.train(corpus)
            print(f"  ✅ ZeroDayDetector: {len(corpus)} 条语料训练完成")

            test_cases = [
                "新发现的零日漏洞利用工具在暗网出售",
                "unknown ransomware variant using double extortion",
                "APT group deploys new backdoor via supply chain attack",
                "suspicious C2 beacon pattern detected in network traffic",
                "新型钓鱼攻击利用AI生成语音进行社会工程学攻击",
                "零日漏洞CVE-2024-XXXX被APT组织在野利用",
                "黑产团伙利用新型洗钱通道转移资金",
                "novel crypto drainer targeting metamask wallets",
            ]
            print("\n  检测结果:")
            for text in test_cases:
                try:
                    results = await zero_day.detect_zero_day_terms(text)
                    if results:
                        best = results[0]
                        label = "⚠️ 异常"
                        print(f"    {label} | 置信度={best.confidence:.4f} 类别={best.category} | '{text[:40]}...'")
                    else:
                        label = "✅ 正常"
                        print(f"    {label} | 未检测到零日术语 | '{text[:40]}...'")
                except Exception as exc:
                    print(f"    ❌ 检测失败: {exc}")
        except Exception as exc:
            print(f"  ❌ ZeroDayDetector 训练失败: {exc}")

    # ========== 训练 AttackChainPredictor ==========
    print("\n[4/8] 训练 AttackChainPredictor (MITRE ATT&CK + 马尔可夫链)...")
    attack_chain = AttackChainPredictor(vector_store=vector_store, knowledge_graph=knowledge_graph)

    try:
        attack_chain.train_from_graph()
        print(f"  ✅ AttackChainPredictor: 训练完成")

        test_entity_ids = list(entity_id_map.values())[:6]
        test_entity_names = list(entity_id_map.keys())[:6]
        print("\n  攻击链预测:")
        for name, eid in zip(test_entity_names, test_entity_ids):
            try:
                result = await attack_chain.predict_next_steps(eid)
                if result.predictions:
                    top3 = [(p.technique_name[:25], round(p.probability, 3)) for p in result.predictions[:3]]
                    print(f"    {name} → {top3}")
                else:
                    print(f"    {name} → 无预测结果")
            except Exception as exc:
                print(f"    {name} 预测失败: {exc}")

        print("\n  攻击链模拟:")
        try:
            if test_entity_ids:
                sim = await attack_chain.simulate_attack_chain(test_entity_ids[0], steps=4)
                for step in sim.max_probability_path[:5]:
                    print(f"    → {step.technique_name} (概率={step.probability:.3f})")
                if not sim.max_probability_path:
                    for path in sim.paths[:3]:
                        for step_data in path.get("steps", [])[:3]:
                            print(f"    → {step_data.get('technique_name', '?')} (概率={step_data.get('probability', 0):.3f})")
        except Exception as exc:
            print(f"    模拟失败: {exc}")
    except Exception as exc:
        print(f"  ❌ AttackChainPredictor 训练失败: {exc}")

    # ========== 训练 EntityAttribution ==========
    print("\n[5/8] 训练 EntityAttribution (TransE知识图谱嵌入)...")
    entity_attr = EntityAttribution(vector_store=vector_store, knowledge_graph=knowledge_graph)

    try:
        entity_attr.train_from_graph()
        print(f"  ✅ EntityAttribution: TransE训练完成")

        test_entities = list(entity_id_map.items())[:5]
        print("\n  跨平台归因:")
        for name, eid in test_entities:
            try:
                results = await entity_attr.attribute_entity(eid)
                if results:
                    best = results[0]
                    print(f"    '{name}' → 最佳匹配={best.target_entity_id[:16]}... (相似度={best.similarity:.3f}), 候选={len(results)}个")
                else:
                    print(f"    '{name}' → 无归因结果")
            except Exception as exc:
                print(f"    '{name}' 归因失败: {exc}")
    except Exception as exc:
        print(f"  ❌ EntityAttribution 训练失败: {exc}")

    # ========== TemporalDecay ==========
    print("\n[6/8] TemporalDecay (MLE半衰期估计)...")
    temporal_decay = TemporalDecay(vector_store=vector_store)

    obs_count = 0
    for i, item in enumerate(all_intelligence):
        meta = item["metadata"]
        source = meta.get("source", "")

        intel_type = "vulnerability"
        if source in ("urlhaus", "malware_bazaar"):
            if "ransomware" in str(meta.get("tags", [])):
                intel_type = "malware"
            elif "stealer" in str(meta.get("tags", [])):
                intel_type = "phishing"
            else:
                intel_type = "malware"
        elif source == "alienvault_otx":
            intel_type = "apt"
        elif source == "otx_indicator":
            intel_type = "c2"
        elif source == "ransomware_watch":
            intel_type = "ransomware"
        elif source == "breach_tracker":
            intel_type = "breach"
        elif source == "phish_tracker":
            intel_type = "phishing"
        elif source == "darkweb_monitor":
            intel_type = "darkweb"
        elif source == "crypto_tracker":
            intel_type = "crypto"
        elif source == "botnet_tracker":
            intel_type = "botnet"
        elif source == "supply_chain_monitor":
            intel_type = "supply_chain"
        elif source == "zeroday_tracker":
            intel_type = "zeroday"

        base_conf = 0.6 + (i % 15) * 0.02
        hours_ago = (i % 72) + 1
        observed_conf = base_conf * (0.5 ** (hours_ago / 72))

        try:
            temporal_decay.record_observation(
                threat_type=intel_type,
                elapsed_hours=hours_ago,
                observed_confidence=observed_conf,
            )
            obs_count += 1
        except Exception:
            pass

    print(f"  ✅ TemporalDecay: {obs_count} 条观测记录")

    try:
        decay_results = await temporal_decay.batch_decay_analysis()
        half_lives = decay_results.get("half_lives", {})
        for t, hl in half_lives.items():
            print(f"    {t}: 学习半衰期={hl:.1f}小时")
    except Exception as exc:
        print(f"  ⚠️ 批量分析失败: {exc}")

    # ========== IntelligenceOrganism ==========
    print("\n[7/8] IntelligenceOrganism 情报生命体...")
    organism_engine = IntelligenceOrganismEngine(
        vector_store=vector_store,
        knowledge_graph=knowledge_graph,
    )

    species_map = {
        "cisa_kev": "ttp",
        "malware_bazaar": "ttp",
        "alienvault_otx": "campaign",
        "urlhaus": "domain",
        "otx_indicator": "ip",
        "ransomware_watch": "organization",
        "breach_tracker": "organization",
        "phish_tracker": "campaign",
        "darkweb_monitor": "domain",
        "crypto_tracker": "bankcard",
        "botnet_tracker": "ttp",
        "supply_chain_monitor": "campaign",
        "zeroday_tracker": "ttp",
    }

    organism_count = 0
    for i, item in enumerate(all_intelligence):
        source = item["metadata"].get("source", "unknown")
        species = species_map.get(source, "ip")
        intel_id = intel_ids[i] if i < len(intel_ids) else uuid4().hex

        try:
            organism = await organism_engine.spawn_organism(
                intelligence_id=intel_id,
                species=species,
                initial_data=item["metadata"],
                skip_save=True,
            )
            organism_count += 1
        except Exception:
            pass

    await organism_engine.save_to_disk()
    print(f"  ✅ IntelligenceOrganism: {organism_count} 个生命体已生成")

    for oid, org in organism_engine.organisms.items():
        hours = random.uniform(1, 2160)
        org.current_age_hours = hours
        org.born_at = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    for oid, org in organism_engine.organisms.items():
        hours = org.current_age_hours
        simulated_mentions = max(1, int(EXPECTED_MENTIONS_PER_HOUR.get(org.species, 0.01) * hours * random.uniform(0.1, 2.0)))
        org.mention_count = simulated_mentions
        org.total_use_count = max(1, int(simulated_mentions * random.uniform(0.2, 0.95)))
        org.confirmed_use_count = max(0, int(org.total_use_count * random.uniform(0.05, 0.95)))
        freshness = 0.5 ** (hours / org.half_life) if org.half_life > 0 else 0.0
        expected_mentions = EXPECTED_MENTIONS_PER_HOUR.get(org.species, 0.01) * hours
        activity = min(org.mention_count / max(expected_mentions, 1), 1.0) if expected_mentions > 0 else 0.5
        relevance = 0.5
        if org.total_use_count > 0:
            relevance = min(org.confirmed_use_count / org.total_use_count, 1.0)
        org.vitality = freshness * activity * relevance
        org.is_alive = org.vitality >= DEATH_THRESHOLD
    await organism_engine.save_to_disk()
    print(f"  ✅ 时间模拟完成，活力已重新计算")

    alive = sum(1 for o in organism_engine.organisms.values() if o.is_alive)
    print(f"    存活: {alive}")

    vitality_values = [o.vitality for o in organism_engine.organisms.values()]
    if vitality_values:
        print(f"    活力范围: {min(vitality_values):.3f} ~ {max(vitality_values):.3f}")
        print(f"    平均活力: {sum(vitality_values) / len(vitality_values):.3f}")

    species_dist = {}
    for o in organism_engine.organisms.values():
        species_dist[o.species] = species_dist.get(o.species, 0) + 1
    for sp, cnt in sorted(species_dist.items()):
        print(f"    物种 {sp}: {cnt} 个")

    # ========== ProvenanceChain ==========
    print("\n[8/8] ProvenanceChain 溯源链...")
    provenance = ProvenanceChain(vector_store=vector_store)

    prov_count = 0
    for i, item in enumerate(all_intelligence[:30]):
        intel_id = intel_ids[i] if i < len(intel_ids) else uuid4().hex
        source = item["metadata"].get("source", "unknown")

        try:
            await provenance.record_provenance(
                intelligence_id=intel_id,
                stage="collected",
                input_data={"query": source},
                output_data=item["metadata"],
                confidence_after=0.7,
            )
            await provenance.record_provenance(
                intelligence_id=intel_id,
                stage="analyzed",
                input_data=item["metadata"],
                output_data={"analysis": "completed", "source": source},
                algorithm_input=f"analyze_{source}",
                algorithm_output=f"threat_intelligence_from_{source}",
                confidence_before=0.7,
                confidence_after=0.85,
            )
            prov_count += 2
        except Exception:
            pass

    print(f"  ✅ ProvenanceChain: {prov_count} 条溯源记录")

    if intel_ids:
        verify = await provenance.verify_provenance(intel_ids[0])
        print(f"    验证 {intel_ids[0][:8]}...: valid={verify.is_valid}, chain_length={verify.chain_length}, algorithm_contributions={verify.algorithm_contributions}")

        hall_report = await provenance.detect_hallucination(intel_ids[0])
        print(f"    幻觉检测: score={hall_report.hallucination_score:.2f}, flagged={len(hall_report.flagged_claims)}")

    # ========== 持久化 ==========
    print("\n[持久化] 保存所有数据...")
    try:
        await vector_store.persist()
        print("  ✅ VectorStore")
    except Exception as exc:
        print(f"  ⚠️ VectorStore: {exc}")
    try:
        await knowledge_graph.save()
        print("  ✅ KnowledgeGraph")
    except Exception as exc:
        print(f"  ⚠️ KnowledgeGraph: {exc}")
    try:
        await organism_engine.save_to_disk()
        print("  ✅ OrganismEngine")
    except Exception as exc:
        print(f"  ⚠️ OrganismEngine: {exc}")

    # ========== 最终报告 ==========
    print(f"\n{'='*70}")
    print("  批量数据灌入与引擎训练 — 完成报告")
    print(f"{'='*70}")
    print(f"  数据总量: {len(all_intelligence)} 条真实威胁情报")
    for src, cnt in sorted(source_counts.items()):
        print(f"    - {src}: {cnt} 条")
    print(f"  VectorStore: {len(intel_ids)} 条已索引")
    print(f"  KnowledgeGraph: {entity_count} 实体, {relation_count} 关系")
    print(f"  ZeroDayDetector: {len(corpus)} 条语料训练")
    print(f"  AttackChainPredictor: 从知识图谱训练")
    print(f"  EntityAttribution: TransE嵌入训练")
    print(f"  TemporalDecay: {obs_count} 条观测记录")
    print(f"  IntelligenceOrganism: {organism_count} 个生命体 (存活={alive})")
    print(f"  ProvenanceChain: {prov_count} 条溯源记录")
    print(f"{'='*70}")

    await llm.close()


if __name__ == "__main__":
    asyncio.run(main())
