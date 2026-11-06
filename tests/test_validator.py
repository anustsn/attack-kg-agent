from attackkg.alerts import Alert
from attackkg.kg import LogSourceRef
from attackkg.validator import check_mapping, check_submission, repair_mapping

ALERT = Alert("a1", "test", "powershell -enc ...", platform="Windows",
              log_sources=[LogSourceRef("WinEventLog:Sysmon", "EventCode=1")])


def good(**over):
    m = {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution",
         "confidence": 0.8, "rationale": "x"}
    return {**m, **over}


def rules(report):
    return [f.rule for f in report.findings]


def test_valid_mapping_passes_and_records_evidence(kg):
    r = check_mapping(kg, good(), ALERT)
    assert r.ok and r.findings == []
    assert r.mapping["observed_via"] == ["WinEventLog:Sysmon (EventCode=1)"]


def test_full_name_and_tactic_forms_are_accepted(kg):
    for tactic in ("execution", "TA0002", "Execution"):
        assert check_mapping(kg, good(technique_name="Command and Scripting Interpreter: PowerShell", tactic=tactic)).ok


def test_unknown_and_malformed_ids(kg):
    assert rules(check_mapping(kg, good(technique_id="T1999"))) == ["unknown_id"]
    assert rules(check_mapping(kg, good(technique_id="T0000.1"))) == ["id_format"]


def test_revoked_id_points_to_replacement(kg):
    r = check_mapping(kg, good(technique_id="T9002"))
    assert rules(r) == ["revoked"] and "T1059.001" in r.findings[0].message


def test_deprecated(kg):
    assert rules(check_mapping(kg, good(technique_id="T9003"))) == ["deprecated"]


def test_name_mismatch(kg):
    assert rules(check_mapping(kg, good(technique_name="Windows Command Shell"))) == ["name_mismatch"]


def test_tactic_checks(kg):
    assert rules(check_mapping(kg, good(tactic="Stealth"))) == ["tactic_mismatch"]
    assert rules(check_mapping(kg, good(tactic="Defense Evasion"))) == ["tactic_renamed"]
    assert rules(check_mapping(kg, good(tactic="Hacking"))) == ["tactic_unknown"]
    assert rules(check_mapping(kg, good(tactic=""))) == ["tactic_missing"]


def test_confidence_range(kg):
    assert rules(check_mapping(kg, good(confidence=7))) == ["confidence_range"]


def test_warnings_do_not_block(kg):
    linux = Alert("a2", "t", "c", platform="Linux", log_sources=[LogSourceRef("auditd:SYSCALL", "execve")])
    r = check_mapping(kg, good(), linux)
    assert r.ok and rules(r) == ["platform_mismatch", "not_observable"]


def test_submission_level_checks(kg):
    assert not check_submission(kg, {"mappings": []}).ok
    dup = check_submission(kg, {"mappings": [good(), good()]})
    assert [p.rule for p in dup.problems] == ["duplicate"]
    many = check_submission(kg, {"mappings": [good(), good(technique_id="T1059", technique_name="Command and Scripting Interpreter"),
                                             good(technique_id="T1564.003", technique_name="Hidden Window", tactic="Stealth"),
                                             good(technique_id="T9001")]})
    assert [p.rule for p in many.problems] == ["too_many"]
    mixed = check_submission(kg, {"mappings": [good(), good(technique_id="T1999")]})
    assert not mixed.ok and [m["technique_id"] for m in mixed.accepted()] == ["T1059.001"]


def test_repair_follows_revocations_and_fixes_names_and_tactics(kg):
    fixed, notes = repair_mapping(kg, good(technique_id="T9002", technique_name="Older Scripting", tactic="Execution"))
    assert fixed["technique_id"] == "T1059.001"
    assert fixed["technique_name"] == "Command and Scripting Interpreter: PowerShell"
    assert fixed["tactic"] == "Execution" and notes == ["T9002 revoked -> T1059.001"]
    assert check_mapping(kg, fixed).ok


def test_repair_maps_renamed_tactic(kg):
    hidden = good(technique_id="T1564.003", technique_name="Hidden Window", tactic="Defense Evasion")
    fixed, notes = repair_mapping(kg, hidden)
    assert fixed["tactic"] == "Stealth" and notes == []
    fixed, notes = repair_mapping(kg, good(tactic="Defense Evasion"))  # PowerShell is not in Stealth
    assert fixed["tactic"] == "Execution" and "tactic" in notes[0]


def test_repair_drops_what_it_cannot_save(kg):
    assert repair_mapping(kg, good(technique_id="T1999"))[0] is None
    assert repair_mapping(kg, good(technique_id="T9003"))[0] is None
    assert repair_mapping(kg, good(technique_id="nonsense"))[0] is None
