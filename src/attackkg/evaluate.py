"""Run systems over the benchmark and score them.

Systems
  offline             BM25 over the graph, re-ranked with graph facts. No model.
  closed-book         The model alone: no tools, no candidates, no validator feedback.
  closed-book+repair  The closed-book answers, repaired with the graph afterwards
                      (revoked ID -> replacement, wrong tactic -> a valid one). It is
                      derived from closed-book.jsonl and makes no model calls.
  agent               The model with the graph tools, candidates and validator feedback.

For every system the validator is applied to the final answer, and only mappings
without errors count. The *first* answer (before any feedback) is kept as well, to
measure how often a system produces invalid IDs on its own.
"""

from __future__ import annotations

import json
import math
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .agent import CLOSED_BOOK_PROMPT, SYSTEM_PROMPT, TOOLS, closed_book, triage, triage_offline
from .alerts import Alert
from .kg import KnowledgeGraph
from .llm import UsageLimitReached, make_session
from .validator import check_submission, repair_mapping

SYSTEMS = ("offline", "closed-book", "closed-book+repair", "agent")
ID_ERRORS = {"id_format", "unknown_id", "revoked", "deprecated"}


def _row(alert: Alert, system: str, res) -> dict:
    first = next((t["validation"]["mappings"] for t in res.trace if "validation" in t), [])
    return {
        "id": alert.id,
        "system": system,
        "gold": alert.gold,
        "status": res.status,
        "detail": res.detail,
        "llm_calls": res.llm_calls,
        "submissions": res.submissions,
        "first": [{"technique_id": m["mapping"].get("technique_id"),
                   "errors": [f["rule"] for f in m["findings"] if f["severity"] == "error"]} for m in first],
        "final": [m["technique_id"] for m in res.mappings],
        "warnings": [w["rule"] for w in res.warnings],
        "trace": res.trace,
    }


def derive_repaired(kg: KnowledgeGraph, run_dir: Path) -> int:
    """Write closed-book+repair.jsonl from closed-book.jsonl. Deterministic, no model calls."""
    src = run_dir / "closed-book.jsonl"
    if not src.exists():
        raise SystemExit(f"{src} not found. Run the closed-book system first.")
    rows = []
    for line in src.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        raw = next((t["validation"]["mappings"] for t in r["trace"] if "validation" in t), [])
        repaired, notes = [], []
        for m in raw:
            fixed, n = repair_mapping(kg, m["mapping"])
            notes += n
            if fixed and fixed["technique_id"] not in {x["technique_id"] for x in repaired}:
                repaired.append(fixed)
        report = check_submission(kg, {"mappings": repaired[:3]}) if repaired else None
        rows.append({**r, "system": "closed-book+repair", "repairs": notes,
                     "final": [m["technique_id"] for m in report.accepted()] if report else [],
                     "trace": [{"repaired": repaired[:3]}]})
    out = run_dir / "closed-book+repair.jsonl"
    out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return len(rows)


def run(kg: KnowledgeGraph, items: list[Alert], system: str, out_path: Path, backend: str = "claude-cli",
        model: str | None = None, effort: str | None = None, workers: int = 1) -> int:
    """Append one JSON line per item to ``out_path``; items already there are skipped."""
    if system == "closed-book+repair":
        return derive_repaired(kg, out_path.parent)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if out_path.exists():
        done = {json.loads(line)["id"] for line in out_path.read_text(encoding="utf-8").splitlines() if line.strip()}
    todo = [a for a in items if a.id not in done]
    lock = threading.Lock()
    opts = {k: v for k, v in (("model", model), ("effort", effort)) if v}

    def one(alert: Alert) -> None:
        if system == "offline":
            res = triage_offline(kg, alert)
        elif system == "closed-book":
            res = closed_book(kg, alert, make_session(backend, CLOSED_BOOK_PROMPT.format(version=kg.version), [], **opts))
        elif system == "agent":
            res = triage(kg, alert, make_session(backend, SYSTEM_PROMPT.format(version=kg.version), TOOLS, **opts))
        else:
            raise ValueError(f"unknown system '{system}'")
        row = _row(alert, system, res)
        with lock:
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
            done.add(alert.id)
            hit = "hit" if row["final"][:1] and row["final"][0] in alert.gold else "miss"
            print(f"[{system}] {len(done)}/{len(items)} {alert.id}: {res.status}, {hit}", flush=True)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(one, a) for a in todo]
        try:
            for fut in as_completed(futures):
                fut.result()
        except UsageLimitReached:
            pool.shutdown(wait=True, cancel_futures=True)
            raise
    return len(todo)


# ----------------------------------------------------------------------------- scoring


def _parent(tid: str) -> str:
    return tid.split(".")[0]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, centre - half), min(1.0, centre + half))


def score(rows: list[dict]) -> dict:
    n = len(rows)
    top1 = sum(bool(r["final"]) and r["final"][0] in r["gold"] for r in rows)
    top1_parent = sum(bool(r["final"]) and _parent(r["final"][0]) in {_parent(g) for g in r["gold"]} for r in rows)
    top3 = sum(bool(set(r["final"][:3]) & set(r["gold"])) for r in rows)
    first_top1 = sum(bool(r["first"]) and r["first"][0]["technique_id"] in r["gold"] for r in rows)
    first = [m for r in rows for m in r["first"]]
    by_error: dict[str, int] = {}
    for m in first:
        for e in set(m["errors"]):
            by_error[e] = by_error.get(e, 0) + 1
    return {
        "n": n,
        "top1": top1, "top1_ci95": wilson(top1, n),
        "top1_parent": top1_parent,
        "top3": top3,
        "first_answer_top1": first_top1,
        "first_answer_mappings": len(first),
        "first_answer_invalid_id": sum(bool(set(m["errors"]) & ID_ERRORS) for m in first),
        "first_answer_any_error": sum(bool(m["errors"]) for m in first),
        "first_answer_errors_by_rule": dict(sorted(by_error.items())),
        "no_answer": sum(not r["final"] for r in rows),
        "refusal_or_error": sum(r["status"] in ("refusal", "error") for r in rows),
        "llm_calls_mean": round(sum(r["llm_calls"] for r in rows) / n, 2) if n else 0,
    }


def load_rows(run_dir: Path) -> dict[str, list[dict]]:
    out = {}
    for system in SYSTEMS:
        path = run_dir / f"{system}.jsonl"
        if path.exists():
            out[system] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return out


def report(run_dir: Path) -> tuple[dict, str]:
    rows = load_rows(run_dir)
    if not rows:
        raise SystemExit(f"no results in {run_dir}")
    common = set.intersection(*({r["id"] for r in rs} for rs in rows.values()))
    scores = {s: score([r for r in rs if r["id"] in common]) for s, rs in rows.items()}

    def pct(k, n):
        return f"{k}/{n} ({100 * k / n:.0f}%)" if n else "-"

    lines = [f"Items scored by every system: {len(common)}", "",
             "| System | Top-1 | 95% CI | Top-1, parent technique | Top-3 | Invalid IDs in first answer | "
             "Any error in first answer | Model calls per item |",
             "|---|---|---|---|---|---|---|---|"]
    for s, sc in scores.items():
        lo, hi = sc["top1_ci95"]
        lines.append(f"| {s} | {pct(sc['top1'], sc['n'])} | {100 * lo:.0f}–{100 * hi:.0f}% | "
                     f"{pct(sc['top1_parent'], sc['n'])} | {pct(sc['top3'], sc['n'])} | "
                     f"{pct(sc['first_answer_invalid_id'], sc['first_answer_mappings'])} | "
                     f"{pct(sc['first_answer_any_error'], sc['first_answer_mappings'])} | {sc['llm_calls_mean']} |")
    lines += ["", "Errors in first answers, by validator rule (count of mappings):", ""]
    for s, sc in scores.items():
        lines.append(f"- {s}: " + (", ".join(f"{k} {v}" for k, v in sc["first_answer_errors_by_rule"].items()) or "none"))
    summary = "\n".join(lines) + "\n"
    (run_dir / "summary.md").write_text(summary, encoding="utf-8")
    (run_dir / "metrics.json").write_text(json.dumps({"common_items": len(common), "systems": scores}, indent=2),
                                          encoding="utf-8")
    return scores, summary
