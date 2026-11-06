from attackkg.kg import LogSourceRef
from attackkg.logsources import from_sigma


def test_windows_process_creation():
    platform, sources = from_sigma({"product": "windows", "category": "process_creation"})
    assert platform == "Windows"
    assert LogSourceRef("WinEventLog:Sysmon", "EventCode=1") in sources


def test_windows_service():
    assert from_sigma({"product": "windows", "service": "security"}) == ("Windows", [LogSourceRef("WinEventLog:Security")])


def test_cloud_and_network():
    assert from_sigma({"product": "aws", "service": "cloudtrail"}) == ("IaaS", [LogSourceRef("AWS:CloudTrail")])
    platform, sources = from_sigma({"category": "webserver"})
    assert platform is None and LogSourceRef("ApplicationLog:WebServer") in sources


def test_unknown_source():
    assert from_sigma({"product": "acme", "service": "x"}) == (None, [])
