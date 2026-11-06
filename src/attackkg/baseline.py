"""Retrieval without an LLM: BM25 over the graph's text, re-ranked with graph facts.

It seeds the agent with candidates, and it is the ``offline`` backend, which runs
with no model at all.
"""

from __future__ import annotations

from .alerts import Alert
from .kg import KnowledgeGraph

OBSERVABLE_BOOST = 1.5  # an ATT&CK analytic for the technique reads the alert's log source
PLATFORM_PENALTY = 0.5  # the technique is not listed for the alert's platform


def rank(kg: KnowledgeGraph, alert: Alert, k: int = 10, pool: int = 60) -> list[tuple[str, float]]:
    scored = []
    for tid, score in kg.search(alert.query_text(), pool):
        t = kg.get(tid)
        if alert.log_sources and kg.observable_matches(tid, alert.log_sources):
            score *= OBSERVABLE_BOOST
        if alert.platform and alert.platform.lower() not in {p.lower() for p in t.platforms}:
            score *= PLATFORM_PENALTY
        scored.append((tid, score))
    return sorted(scored, key=lambda kv: -kv[1])[:k]


def offline_mappings(kg: KnowledgeGraph, alert: Alert, k: int = 3) -> list[dict]:
    ranked = rank(kg, alert, k)
    top = ranked[0][1] if ranked else 1.0
    out = []
    for tid, score in ranked:
        t = kg.get(tid)
        out.append({
            "technique_id": tid,
            "technique_name": kg.full_name(tid),
            "tactic": kg.tactics[t.tactics[0]].name if t.tactics else "",
            "confidence": round(score / top * 0.5, 2),  # retrieval scores are not probabilities; keep them low
            "rationale": "Keyword match with the technique's ATT&CK text, re-ranked by platform and log source.",
        })
    return out
