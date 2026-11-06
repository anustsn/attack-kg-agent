from attackkg.kg import LogSourceRef, logsource_matches
from attackkg.stix2rdf import clean_text, event_codes


def test_basic_facts(kg):
    t = kg.get("t1059.001")
    assert t.name == "PowerShell"
    assert kg.full_name("T1059.001") == "Command and Scripting Interpreter: PowerShell"
    assert t.parent_id == "T1059" and kg.get("T1059").sub_ids == ["T1059.001"]
    assert t.tactics == ["execution"] and t.platforms == ["Windows"]
    assert t.mitigations == [("M1042", "Disable or Remove Feature or Program")]
    assert kg.version == "test-1"


def test_revoked_relationship_is_ignored(kg):
    assert kg.get("T1564.003").used_by == {}
    assert kg.get("T1059.001").used_by["Group"] == [("G9001", "Example Group")]


def test_rule_observable_via(kg):
    labels = {ls.label() for ls in kg.get("T1059.001").observable_via}
    assert labels == {"WinEventLog:Sysmon (EventCode=1)", "WinEventLog:PowerShell (EventCode=4104)"}


def test_rule_parent_inherits_observability(kg):
    assert kg.get("T1059").observable_via == kg.get("T1059.001").observable_via


def test_rule_replacement_chain(kg):
    assert kg.get("T9001").replaced_by == "T1059.001"
    assert kg.get("T9002").replaced_by == "T1059.001"  # two hops: T9002 -> T9001 -> T1059.001


def test_search_ranks_by_text(kg):
    assert kg.search("powershell encoded command", 1)[0][0] == "T1059.001"
    assert all(kg.get(tid).active for tid, _ in kg.search("scripting", 10))


def test_log_source_matching():
    sysmon1 = LogSourceRef("WinEventLog:Sysmon", "EventCode=1")
    assert logsource_matches(LogSourceRef("winEventLog:sysmon", "EventCode=1, 3"), sysmon1)
    assert not logsource_matches(LogSourceRef("WinEventLog:Sysmon", "EventCode=10"), sysmon1)
    assert logsource_matches(LogSourceRef("WinEventLog:Sysmon"), sysmon1)  # no channel: name level
    assert not logsource_matches(LogSourceRef("WinEventLog:Security", "EventCode=1"), sysmon1)


def test_techniques_for_log_source(kg):
    found = kg.techniques_for_log_source(LogSourceRef("WinEventLog:Sysmon", "EventCode=1"), "Windows")
    assert [t.id for t in found] == ["T1059", "T1059.001"]
    assert kg.techniques_for_log_source(LogSourceRef("WinEventLog:Sysmon", "EventCode=1"), "macOS") == []


def test_helpers():
    assert clean_text("Run it.(Citation: X Y)  Now") == "Run it. Now"
    assert event_codes("EventCode=4663, 4670") == [4663, 4670]
    assert event_codes("socket/connect") == []


def test_sparql_passthrough(kg):
    rows = list(kg.sparql("SELECT ?id WHERE { ?t akg:inTactic ?tac . ?tac akg:shortname 'stealth' . ?t akg:attackId ?id }"))
    assert [str(r[0]) for r in rows] == ["T1564.003"]
