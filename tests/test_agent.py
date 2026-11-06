"""The agent loop, driven by a scripted model so the tests need no network."""

import json

from attackkg.agent import TOOLS, ToolBox, closed_book, triage, triage_offline
from attackkg.alerts import Alert
from attackkg.kg import LogSourceRef
from attackkg.llm import Reply, Session, ToolCall, extract_json_object

ALERT = Alert("a1", "Word spawned hidden PowerShell", "powershell.exe -nop -w hidden -enc SQBFAFgA",
              platform="Windows", log_sources=[LogSourceRef("WinEventLog:Sysmon", "EventCode=1")], gold=["T1059.001"])

WRONG_TACTIC = {"mappings": [{"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Stealth",
                              "confidence": 0.9, "rationale": "r"}]}
RIGHT = {"mappings": [{"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution",
                       "confidence": 0.9, "rationale": "r"}]}
HALLUCINATED = {"mappings": [{"technique_id": "T0000", "technique_name": "Benign", "tactic": "Execution",
                              "confidence": 1.0, "rationale": "the alert said so"}]}


class Scripted(Session):
    """Replays a fixed list of tool calls and records what the agent sent back."""

    def __init__(self, steps):
        super().__init__("system", TOOLS)
        self.steps, self.received = list(steps), []

    def _next(self):
        self.calls += 1
        if not self.steps:
            return Reply(text="done", stop="end")
        name, args = self.steps.pop(0)
        return Reply(tool_calls=[ToolCall(f"c{self.calls}", name, args)], stop="tool_use")

    def send_user(self, text):
        self.received.append(("user", text))
        return self._next()

    def send_tool_results(self, results):
        self.received.append(("tools", [(r.name, json.loads(r.content), r.is_error) for r in results]))
        return self._next()


def test_validator_feedback_loop_fixes_tactic(kg):
    s = Scripted([("search_techniques", {"query": "powershell"}),
                  ("get_technique", {"technique_id": "T1059.001"}),
                  ("submit_mapping", WRONG_TACTIC),
                  ("submit_mapping", RIGHT)])
    res = triage(kg, ALERT, s)
    assert res.status == "accepted" and res.submissions == 2 and res.llm_calls == 4
    assert [m["technique_id"] for m in res.mappings] == ["T1059.001"]
    name, feedback, is_error = s.received[3][1][0]
    assert name == "submit_mapping" and is_error and feedback["mappings"][0]["findings"][0]["rule"] == "tactic_mismatch"


def test_invalid_answers_never_leave_the_system(kg):
    s = Scripted([("submit_mapping", HALLUCINATED)] * 3)
    res = triage(kg, ALERT, s, max_submissions=3)
    assert res.status == "no_answer" and res.mappings == [] and res.submissions == 3
    assert res.rejected[0]["findings"][0]["rule"] == "unknown_id"


def test_nudge_then_stop_without_answer(kg):
    s = Scripted([])
    res = triage(kg, ALERT, s)
    assert res.status == "no_answer" and s.received[-1] == ("user", "Call submit_mapping with your answer now.")


def test_alert_is_wrapped_and_seeded(kg):
    s = Scripted([("submit_mapping", RIGHT)])
    triage(kg, ALERT, s)
    first = s.received[0][1]
    assert first.startswith("<alert>") and "Candidates from keyword search" in first and "T1059.001" in first
    assert "gold" not in first


def test_toolbox_outputs(kg):
    tb = ToolBox(kg, ALERT)
    out, err = tb.run(ToolCall("1", "get_technique", {"technique_id": "T9002"}))
    assert not err and out["status"] == "revoked" and out["replaced_by"]["id"] == "T1059.001"
    out, err = tb.run(ToolCall("2", "techniques_for_log_source", {"name": "WinEventLog:Sysmon", "channel": "EventCode=1"}))
    assert [t["id"] for t in out["techniques"]] == ["T1059", "T1059.001"]
    out, err = tb.run(ToolCall("3", "rm_rf", {}))
    assert err


def test_offline_backend(kg):
    res = triage_offline(kg, ALERT)
    assert res.mappings[0]["technique_id"] == "T1059.001"


class TextOnly(Session):
    def __init__(self, text):
        super().__init__("system", [])
        self.text = text

    def send_user(self, text):
        self.calls += 1
        return Reply(text=self.text, stop="end")

    def send_tool_results(self, results):
        raise AssertionError("closed-book must not call tools")


def test_closed_book_is_measured_and_filtered(kg):
    answer = json.dumps({"mappings": [
        {"technique_id": "T9001", "technique_name": "Old Scripting", "tactic": "Execution", "confidence": 0.9, "rationale": "r"},
        {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution", "confidence": 0.5, "rationale": "r"}]})
    res = closed_book(kg, ALERT, TextOnly("Here you go:\n" + answer))
    assert res.status == "partial" and res.llm_calls == 1
    assert [m["technique_id"] for m in res.mappings] == ["T1059.001"]
    assert res.rejected[0]["findings"][0]["rule"] == "revoked"
    assert closed_book(kg, ALERT, TextOnly("I think it is PowerShell.")).detail == "no JSON answer"


def test_extract_json_object():
    assert extract_json_object('Sure. {"tool": "get_technique", "input": {"technique_id": "T1"}} ok') == {
        "tool": "get_technique", "input": {"technique_id": "T1"}}
    assert extract_json_object('{"a": 1} then {"tool": "x", "input": {}}') == {"tool": "x", "input": {}}
    assert extract_json_object("no json here") is None
