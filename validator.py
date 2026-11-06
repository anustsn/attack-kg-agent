"""Symbolic checks of a proposed ATT&CK mapping against the knowledge graph.

Errors mean the mapping is wrong as written and must not leave the system:
an ID that does not exist, a revoked or deprecated ID, a name that belongs to a
different ID, or a tactic the technique does not belong to.

Warnings mean the mapping may be right but the graph does not support it:
the technique does not run on the alert's platform, or no ATT&CK analytic for it
reads the alert's log source. ATT&CK's detection coverage is incomplete, so these
lower confidence instead of blocking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .alerts import Alert
from .kg import KnowledgeGraph

ERROR, WARNING = "error", "warning"
_TID = re.compile(r"^T\d{4}(\.\d{3})?$")

# Tactic names that ATT&CK has since changed. The ID stayed; the name did not.
RENAMED_TACTICS = {"defense evasion": "TA0005", "defense-evasion": "TA0005"}


@dataclass
class Finding:
    rule: str
    severity: str
    message: str

    def to_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "message": self.message}


@dataclass
class MappingReport:
    mapping: dict
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.severity == ERROR for f in self.findings)

    def to_dict(self) -> dict:
        return {"mapping": self.mapping, "ok": self.ok, "findings": [f.to_dict() for f in self.findings]}


@dataclass
class SubmissionReport:
    reports: list[MappingReport]
    problems: list[Finding] = field(default_factory=list)  # about the submission as a whole

    @property
    def ok(self) -> bool:
        return not self.problems and bool(self.reports) and all(r.ok for r in self.reports)

    def accepted(self) -> list[dict]:
        return [r.mapping for r in self.reports if r.ok]

    def feedback(self) -> dict:
        """What the agent sees after submit_mapping."""
        return {
            "accepted": self.ok,
            "problems": [p.to_dict() for p in self.problems],
            "mappings": [r.to_dict() for r in self.reports],
            "next_step": "Done." if self.ok else "Fix every error and call submit_mapping again.",
        }


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()


def check_mapping(kg: KnowledgeGraph, mapping: dict, alert: Alert | None = None) -> MappingReport:
    report = MappingReport(mapping)
    add = lambda rule, sev, msg: report.findings.append(Finding(rule, sev, msg))  # noqa: E731

    tid = str(mapping.get("technique_id", "")).strip().upper()
    if not _TID.match(tid):
        add("id_format", ERROR, f"'{tid}' is not an ATT&CK technique ID (expected T1234 or T1234.001).")
        return report
    t = kg.get(tid)
    if t is None:
        add("unknown_id", ERROR, f"{tid} does not exist in ATT&CK {kg.version}.")
        return report
    if t.revoked:
        hint = f" Use {t.replaced_by} ({kg.full_name(t.replaced_by)}) instead." if t.replaced_by else ""
        add("revoked", ERROR, f"{tid} ({t.name}) is revoked in ATT&CK {kg.version}.{hint}")
        return report
    if t.deprecated:
        add("deprecated", ERROR, f"{tid} ({t.name}) is deprecated in ATT&CK {kg.version}.")
        return report

    name = str(mapping.get("technique_name", "")).strip()
    if name and _norm(name) not in {_norm(t.name), _norm(kg.full_name(tid))}:
        add("name_mismatch", ERROR, f"{tid} is named '{kg.full_name(tid)}', not '{name}'.")

    valid = ", ".join(kg.tactics[s].name for s in t.tactics)
    tactic_text = str(mapping.get("tactic", "")).strip()
    tactic = kg.resolve_tactic(tactic_text) if tactic_text else None
    if not tactic_text:
        add("tactic_missing", ERROR, f"No tactic given. {tid} belongs to: {valid}.")
    elif tactic is None:
        renamed = RENAMED_TACTICS.get(tactic_text.lower())
        if renamed:
            current = next(tac for tac in kg.tactics.values() if tac.id == renamed)
            add("tactic_renamed", ERROR,
                f"'{tactic_text}' is the old name of {renamed}; ATT&CK {kg.version} calls it '{current.name}'. "
                f"{tid} belongs to: {valid}.")
        else:
            add("tactic_unknown", ERROR, f"'{tactic_text}' is not an ATT&CK tactic. {tid} belongs to: {valid}.")
    elif tactic.shortname not in t.tactics:
        add("tactic_mismatch", ERROR, f"{tid} is not in tactic '{tactic.name}'. It belongs to: {valid}.")

    conf = mapping.get("confidence")
    if conf is not None and not (isinstance(conf, (int, float)) and 0 <= conf <= 1):
        add("confidence_range", ERROR, f"confidence must be a number from 0 to 1, got {conf!r}.")

    if alert is not None:
        if alert.platform and alert.platform.lower() not in {p.lower() for p in t.platforms}:
            add("platform_mismatch", WARNING,
                f"{tid} is listed for {', '.join(t.platforms)}, not for the alert's platform {alert.platform}.")
        if alert.log_sources:
            matches = kg.observable_matches(tid, alert.log_sources)
            if matches:
                report.mapping = {**mapping, "observed_via": [m.label() for m in matches]}
            else:
                add("not_observable", WARNING,
                    f"No ATT&CK analytic for {tid} reads the alert's log source "
                    f"({', '.join(ls.label() for ls in alert.log_sources)}).")
    return report


def check_submission(kg: KnowledgeGraph, submission: dict, alert: Alert | None = None,
                     max_mappings: int = 3) -> SubmissionReport:
    mappings = submission.get("mappings")
    if not isinstance(mappings, list) or not mappings:
        return SubmissionReport([], [Finding("empty", ERROR, "Submit at least one mapping.")])
    problems = []
    if len(mappings) > max_mappings:
        problems.append(Finding("too_many", ERROR, f"Submit at most {max_mappings} mappings, most likely first."))
    ids = [str(m.get("technique_id", "")).upper() for m in mappings if isinstance(m, dict)]
    if len(ids) != len(set(ids)):
        problems.append(Finding("duplicate", ERROR, "Each technique may appear only once."))
    reports = [check_mapping(kg, m, alert) if isinstance(m, dict)
               else MappingReport({"raw": m}, [Finding("not_object", ERROR, "Each mapping must be an object.")])
               for m in mappings]
    return SubmissionReport(reports, problems)
