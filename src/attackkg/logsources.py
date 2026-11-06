"""Translate Sigma log source fields into ATT&CK v18+ log source names and platforms.

Sigma describes where a rule's events come from with ``product``, ``category`` and
``service``. ATT&CK analytics name log sources like ``WinEventLog:Sysmon`` with a
channel such as ``EventCode=1``. The tables below are hand-written; each row is a
claim a reviewer can check against the Sigma taxonomy and the ATT&CK data.
"""

from __future__ import annotations

from .kg import LogSourceRef

L = LogSourceRef
SYSMON = "WinEventLog:Sysmon"

WINDOWS_CATEGORY = {
    "process_creation": [L(SYSMON, "EventCode=1"), L("WinEventLog:Security", "EventCode=4688")],
    "file_event": [L(SYSMON, "EventCode=11")],
    "file_change": [L(SYSMON, "EventCode=2")],
    "file_delete": [L(SYSMON, "EventCode=23, 26")],
    "file_access": [L("WinEventLog:Security", "EventCode=4663")],
    "file_rename": [L(SYSMON, "EventCode=11")],
    "registry_set": [L(SYSMON, "EventCode=13")],
    "registry_add": [L(SYSMON, "EventCode=12")],
    "registry_delete": [L(SYSMON, "EventCode=12")],
    "registry_rename": [L(SYSMON, "EventCode=14")],
    "registry_event": [L(SYSMON, "EventCode=12, 13, 14")],
    "image_load": [L(SYSMON, "EventCode=7")],
    "driver_load": [L(SYSMON, "EventCode=6")],
    "network_connection": [L(SYSMON, "EventCode=3")],
    "dns_query": [L(SYSMON, "EventCode=22")],
    "process_access": [L(SYSMON, "EventCode=10")],
    "create_remote_thread": [L(SYSMON, "EventCode=8")],
    "raw_access_thread": [L(SYSMON, "EventCode=9")],
    "pipe_created": [L(SYSMON, "EventCode=17, 18")],
    "create_stream_hash": [L(SYSMON, "EventCode=15")],
    "process_tampering": [L(SYSMON, "EventCode=25")],
    "wmi_event": [L(SYSMON, "EventCode=19, 20, 21")],
    "ps_script": [L("WinEventLog:PowerShell", "EventCode=4104")],
    "ps_module": [L("WinEventLog:PowerShell", "EventCode=4103")],
    "ps_classic_start": [L("WinEventLog:PowerShell", "EventCode=400")],
    "ps_classic_provider_start": [L("WinEventLog:PowerShell", "EventCode=600")],
}

WINDOWS_SERVICE = {
    "security": [L("WinEventLog:Security")],
    "system": [L("WinEventLog:System")],
    "application": [L("WinEventLog:Application")],
    "powershell": [L("WinEventLog:PowerShell")],
    "powershell-classic": [L("WinEventLog:PowerShell")],
    "windefend": [L("WinEventLog:Microsoft-Windows-Windows Defender/Operational")],
    "taskscheduler": [L("WinEventLog:TaskScheduler")],
    "wmi": [L("WinEventLog:WMI")],
    "applocker": [L("WinEventLog:AppLocker")],
    "codeintegrity-operational": [L("WinEventLog:Microsoft-Windows-CodeIntegrity/Operational")],
    "firewall-as": [L("WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall")],
    "smbclient-security": [L("WinEventLog:Microsoft-Windows-SMBClient/Security")],
    "shell-core": [L("WinEventLog:Microsoft-Windows-Shell-Core")],
    "vhdmp": [L("WinEventLog:System")],
    "msexchange-management": [L("Application Log")],
    "dns-server": [L("Application Log")],
    "bits-client": [L("Application Log")],
}

LINUX_CATEGORY = {
    "process_creation": [L("auditd:EXECVE"), L("auditd:SYSCALL", "execve"), L("linux:Sysmon", "EventCode=1")],
    "network_connection": [L("auditd:SYSCALL", "connect"), L("linux:Sysmon", "EventCode=3")],
    "file_event": [L("auditd:PATH"), L("linux:Sysmon", "EventCode=11")],
    "file_delete": [L("auditd:PATH"), L("linux:Sysmon", "EventCode=23")],
}

LINUX_SERVICE = {
    "auditd": [L("auditd:SYSCALL")],
    "syslog": [L("linux:syslog")],
    "auth": [L("linux:auth")],
    "sshd": [L("linux:auth")],
    "sudo": [L("linux:auth")],
    "cron": [L("linux:cron")],
}

MACOS_CATEGORY = {
    "process_creation": [L("macos:endpointsecurity", "ES_EVENT_TYPE_NOTIFY_EXEC"), L("macos:unifiedlog")],
    "file_event": [L("macos:endpointsecurity"), L("fs:fsevents")],
}

# (product, service) for cloud and SaaS sources.
CLOUD = {
    ("aws", "cloudtrail"): ("IaaS", [L("AWS:CloudTrail")]),
    ("azure", "activitylogs"): ("IaaS", [L("azure:activity")]),
    ("azure", "auditlogs"): ("Identity Provider", [L("azure:audit")]),
    ("azure", "signinlogs"): ("Identity Provider", [L("azure:signinlogs")]),
    ("azure", "riskdetection"): ("Identity Provider", [L("azure:signinlogs")]),
    ("azure", "pim"): ("Identity Provider", [L("azure:audit")]),
    ("m365", "threat_management"): ("Office Suite", [L("m365:unified")]),
    ("m365", "audit"): ("Office Suite", [L("m365:unified")]),
    ("gcp", "gcp.audit"): ("IaaS", [L("gcp:audit")]),
    ("gcp", "google_workspace.admin"): ("Office Suite", [L("saas:googleworkspace")]),
    ("okta", "okta"): ("Identity Provider", [L("saas:okta")]),
    ("github", "audit"): ("SaaS", [L("saas:github")]),
    ("bitbucket", "audit"): ("SaaS", [L("saas:audit")]),
    ("kubernetes", "application"): ("Containers", [L("kubernetes:audit")]),
    ("kubernetes", "audit"): ("Containers", [L("kubernetes:audit")]),
    ("cisco", "aaa"): ("Network Devices", [L("networkdevice:cli")]),
}

# Network-level categories carry no single host platform.
NETWORK_CATEGORY = {
    "proxy": [L("NSM:Content"), L("NSM:Flow")],
    "webserver": [L("ApplicationLog:WebServer"), L("apache:access_log"), L("ApplicationLog:IIS")],
    "dns": [L("dns:query")],
    "firewall": [L("NSM:Firewall")],
    "antivirus": [L("EDR:detection")],
    "application": [L("Application Log")],
}

PLATFORM_BY_PRODUCT = {"windows": "Windows", "linux": "Linux", "macos": "macOS"}
CLOUD_PRODUCT_PLATFORM = {
    "aws": "IaaS", "gcp": "IaaS", "azure": "IaaS", "m365": "Office Suite", "okta": "Identity Provider",
    "github": "SaaS", "bitbucket": "SaaS", "kubernetes": "Containers", "cisco": "Network Devices",
}


def from_sigma(logsource: dict) -> tuple[str | None, list[LogSourceRef]]:
    """Map a Sigma ``logsource`` block to (ATT&CK platform, ATT&CK log sources)."""
    product = (logsource.get("product") or "").lower() or None
    category = (logsource.get("category") or "").lower() or None
    service = (logsource.get("service") or "").lower() or None

    if (product, service) in CLOUD:
        return CLOUD[(product, service)]
    platform = PLATFORM_BY_PRODUCT.get(product or "") or CLOUD_PRODUCT_PLATFORM.get(product or "")

    table = {"windows": (WINDOWS_CATEGORY, WINDOWS_SERVICE),
             "linux": (LINUX_CATEGORY, LINUX_SERVICE),
             "macos": (MACOS_CATEGORY, {})}.get(product or "")
    sources: list[LogSourceRef] = []
    if table:
        cats, svcs = table
        sources = cats.get(category or "", []) or svcs.get(service or "", [])
        if not sources and product == "linux" and not category and not service:
            sources = [L("linux:syslog")]
    if not sources and category in NETWORK_CATEGORY:
        sources = NETWORK_CATEGORY[category]
    return platform, list(sources)
