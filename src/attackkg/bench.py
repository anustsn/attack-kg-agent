"""Build an evaluation set from SigmaHQ detection rules.

Each Sigma rule carries ATT&CK tags written by its author. A benchmark item shows a
system the rule as an analyst sees an alert's rule context (title, description, log
source, detection logic, false positives, level) with the tags and references
removed, and keeps the tags as the expected answer.

Tags are normalised to the pinned ATT&CK version: a revoked ID is replaced by its
current technique through the graph (rule 2); an ID that is unknown, or deprecated
without a replacement, is dropped. Items are sampled round-robin across log source
types so that Windows process creation, which is ~40 % of Sigma, does not dominate.

Sigma rules are © their authors under the Detection Rule License 1.1. Each item keeps
the rule's author, ID, path and licence.
"""

from __future__ import annotations

import json
import random
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from .alerts import Alert
from .kg import KnowledgeGraph
from .logsources import from_sigma

_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
SHOWN_FIELDS = ("title", "description", "logsource", "detection", "falsepositives", "level")


def read_rules(zip_path: Path) -> list[tuple[str, dict]]:
    rules = []
    with zipfile.ZipFile(zip_path) as z:
        for name in sorted(z.namelist()):
            if not name.endswith(".yml"):
                continue
            try:
                rule = yaml.safe_load(z.read(name))
            except yaml.YAMLError:
                continue
            if isinstance(rule, dict) and rule.get("detection") and rule.get("title"):
                rules.append((name, rule))
    return rules


def technique_tags(rule: dict) -> list[str]:
    out = []
    for tag in rule.get("tags") or []:
        if m := _TAG.match(str(tag).strip().lower()):
            out.append(m.group(1).upper())
    return out


def normalise(kg: KnowledgeGraph, ids: list[str]) -> tuple[list[str], dict[str, str]]:
    """Map tagged IDs to current IDs. Returns (current IDs, {original: what happened})."""
    current, notes = [], {}
    for tid in ids:
        t = kg.get(tid)
        if t is None:
            notes[tid] = "unknown"
        elif t.active:
            current.append(tid)
        elif t.replaced_by:
            current.append(t.replaced_by)
            notes[tid] = f"revoked -> {t.replaced_by}"
        else:
            notes[tid] = "deprecated"
    return list(dict.fromkeys(current)), notes


def to_item(kg: KnowledgeGraph, name: str, rule: dict, release: str) -> Alert | None:
    original = technique_tags(rule)
    if not 1 <= len(original) <= 2:
        return None
    gold, notes = normalise(kg, original)
    if not gold:
        return None
    logsource = rule.get("logsource") or {}
    platform, sources = from_sigma(logsource)
    shown = {k: rule[k] for k in SHOWN_FIELDS if k in rule}
    content = _TID.sub("[ID removed]", yaml.safe_dump(shown, sort_keys=False, allow_unicode=True, width=100))
    stem = Path(name).stem
    return Alert(
        id=f"sigma-{stem}",
        title=_TID.sub("[ID removed]", str(rule["title"])),
        content=content,
        platform=platform,
        log_sources=sources,
        gold=gold,
        meta={
            "source": f"SigmaHQ sigma_core {release}",
            "path": name,
            "rule_id": rule.get("id"),
            "author": rule.get("author"),
            "license": "DRL-1.1",
            "gold_original": original,
            "gold_notes": notes,
            "stratum": f"{logsource.get('product') or '-'}/{logsource.get('category') or logsource.get('service') or '-'}",
        },
    )


def tag_audit(kg: KnowledgeGraph, rules: list[tuple[str, dict]]) -> dict:
    """How current are the ATT&CK tags across all Sigma rules?"""
    tagged = [(n, technique_tags(r)) for n, r in rules if technique_tags(r)]
    status = Counter()
    rules_with_stale = 0
    for _, ids in tagged:
        stale = False
        for tid in ids:
            t = kg.get(tid)
            kind = "unknown" if t is None else "active" if t.active else "revoked" if t.revoked else "deprecated"
            status[kind] += 1
            stale |= kind != "active"
        rules_with_stale += stale
    return {"rules": len(rules), "rules_with_technique_tags": len(tagged),
            "rules_with_a_non_current_tag": rules_with_stale, "tags_by_status": dict(status)}


def build(kg: KnowledgeGraph, zip_path: Path, out_path: Path, release: str, n: int = 300, seed: int = 13) -> dict:
    rules = read_rules(zip_path)
    strata: dict[str, list[Alert]] = defaultdict(list)
    for name, rule in rules:
        if str(rule.get("status", "")).lower() not in ("stable", "test"):
            continue
        item = to_item(kg, name, rule, release)
        if item is not None:
            strata[item.meta["stratum"]].append(item)
    rng = random.Random(seed)
    keys = sorted(strata)
    for k in keys:
        rng.shuffle(strata[k])
    rng.shuffle(keys)
    picked: list[Alert] = []
    while len(picked) < n and any(strata[k] for k in keys):
        for k in keys:
            if strata[k] and len(picked) < n:
                picked.append(strata[k].pop())
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for item in picked:
            f.write(json.dumps(item.to_dict(), ensure_ascii=False) + "\n")
    return {
        "output": str(out_path),
        "items": len(picked),
        "strata": len(keys),
        "items_with_revoked_gold_remapped": sum(any("revoked" in v for v in a.meta["gold_notes"].values()) for a in picked),
        "tag_audit": tag_audit(kg, rules),
    }


def load(path: Path, n: int | None = None) -> list[Alert]:
    items = [Alert.from_dict(json.loads(line)) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    return items[:n] if n else items
