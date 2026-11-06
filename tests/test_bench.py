import json
import zipfile

import yaml

from attackkg import bench, evaluate

RULES = {
    "rules/windows/proc_creation_ps_enc.yml": {
        "title": "Encoded PowerShell (T1059.001)", "id": "r1", "status": "test", "author": "A. Author",
        "description": "Detects powershell -enc. See T1059.001.", "references": ["https://attack.mitre.org/techniques/T1059/001"],
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": {"CommandLine|contains": " -enc "}, "condition": "selection"}, "level": "high",
    },
    "rules/windows/old_tag.yml": {
        "title": "Old tag", "id": "r2", "status": "stable", "tags": ["attack.t9002"],
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"sel": {"Image": "x"}, "condition": "sel"},
    },
    "rules/linux/unknown_tag.yml": {
        "title": "Unknown tag", "id": "r3", "status": "test", "tags": ["attack.t1999"],
        "logsource": {"product": "linux", "category": "process_creation"},
        "detection": {"sel": {"Image": "y"}, "condition": "sel"},
    },
    "rules/windows/experimental.yml": {
        "title": "Experimental", "id": "r4", "status": "experimental", "tags": ["attack.t1059.001"],
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"sel": {"Image": "z"}, "condition": "sel"},
    },
}


def make_zip(tmp_path):
    path = tmp_path / "sigma.zip"
    with zipfile.ZipFile(path, "w") as z:
        for name, rule in RULES.items():
            z.writestr(name, yaml.safe_dump(rule))
    return path


def test_build_normalises_gold_and_hides_answers(kg, tmp_path):
    out = tmp_path / "bench.jsonl"
    info = bench.build(kg, make_zip(tmp_path), out, "test", n=10)
    items = {a.meta["rule_id"]: a for a in bench.load(out)}
    assert set(items) == {"r1", "r2"}  # unknown-only tag dropped, experimental rule skipped
    assert items["r2"].gold == ["T1059.001"] and items["r2"].meta["gold_notes"] == {"T9002": "revoked -> T1059.001"}
    r1 = items["r1"]
    assert r1.platform == "Windows" and r1.log_sources[0].name == "WinEventLog:Sysmon"
    assert "T1059" not in r1.render() and "attack.t1059" not in r1.render() and "references" not in r1.content
    assert r1.meta["author"] == "A. Author" and r1.meta["license"] == "DRL-1.1"
    assert info["tag_audit"]["rules_with_a_non_current_tag"] == 2  # T9002 revoked, T1999 unknown


def test_score_and_report(tmp_path):
    def row(system, gold, first, final, calls=1):
        return {"id": gold[0] + first[0][0], "system": system, "gold": gold, "status": "accepted", "llm_calls": calls,
                "first": [{"technique_id": t, "errors": e} for t, e in first], "final": final}

    rows = [row("x", ["T1059.001"], [("T1059.001", [])], ["T1059.001"]),
            row("x", ["T1003.001"], [("T1003", [])], ["T1003"]),
            row("x", ["T1686.003"], [("T1562.004", ["revoked"]), ("T1686", [])], ["T1686"])]
    sc = evaluate.score(rows)
    assert (sc["top1"], sc["top1_parent"], sc["top3"]) == (1, 3, 1)
    assert sc["first_answer_invalid_id"] == 1 and sc["first_answer_mappings"] == 4
    assert sc["first_answer_errors_by_rule"] == {"revoked": 1}

    for system in ("offline", "agent"):
        with open(tmp_path / f"{system}.jsonl", "w") as f:
            for r in rows:
                f.write(json.dumps({**r, "system": system}) + "\n")
    scores, summary = evaluate.report(tmp_path)
    assert set(scores) == {"offline", "agent"} and "| agent | 1/3 (33%)" in summary
    assert (tmp_path / "metrics.json").exists()


def test_wilson_interval():
    lo, hi = evaluate.wilson(50, 100)
    assert 0.40 < lo < 0.41 and 0.59 < hi < 0.60
