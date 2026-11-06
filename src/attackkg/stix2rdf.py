"""Convert a MITRE ATT&CK STIX 2.1 bundle into an RDF knowledge graph.

The graph keeps the parts of ATT&CK that matter for alert triage: techniques and
sub-techniques, tactics, platforms, detection strategies, analytics with their log
sources, data components, mitigations, and the groups, software and campaigns that
use each technique. Revocations are kept so that out-of-date IDs can be resolved.

After loading, the SPARQL rules in ``rules/`` add derived facts (for example which
log sources can observe a technique). They are plain files so the reasoning is
inspectable and can be changed without touching Python code.
"""

from __future__ import annotations

import hashlib
import json
import re
from importlib import resources
from pathlib import Path

from rdflib import RDF, RDFS, XSD, Graph, Literal, Namespace, URIRef

AKG = Namespace("https://example.org/attack-kg/ontology#")
LOGSRC = Namespace("https://example.org/attack-kg/logsource/")

CLASS_BY_STIX_TYPE = {
    "attack-pattern": AKG.Technique,
    "x-mitre-tactic": AKG.Tactic,
    "x-mitre-detection-strategy": AKG.DetectionStrategy,
    "x-mitre-analytic": AKG.Analytic,
    "x-mitre-data-component": AKG.DataComponent,
    "course-of-action": AKG.Mitigation,
    "intrusion-set": AKG.Group,
    "malware": AKG.Malware,
    "tool": AKG.Tool,
    "campaign": AKG.Campaign,
}

PREDICATE_BY_RELATIONSHIP = {
    "uses": AKG.uses,
    "mitigates": AKG.mitigates,
    "detects": AKG.detects,
    "subtechnique-of": AKG.subTechniqueOf,
    "revoked-by": AKG.revokedBy,
    "attributed-to": AKG.attributedTo,
}

_CITATION = re.compile(r"\(Citation:[^)]*\)")
_EVENT_CODES = re.compile(r"\d+")


def clean_text(text: str | None) -> str:
    """Drop ATT&CK citation markers and collapse whitespace."""
    if not text:
        return ""
    text = _CITATION.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def event_codes(channel: str | None) -> list[int]:
    """Parse 'EventCode=4663, 4670' into [4663, 4670]. Other channel strings give []."""
    if not channel or "eventcode" not in channel.lower():
        return []
    return [int(n) for n in _EVENT_CODES.findall(channel.split("=", 1)[-1])]


def _attack_ref(obj: dict) -> dict | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref
    return None


def _iri(obj: dict) -> URIRef:
    ref = _attack_ref(obj)
    if ref and ref.get("url"):
        return URIRef(ref["url"])
    return URIRef(f"urn:stix:{obj['id']}")


def logsource_iri(name: str, channel: str | None) -> URIRef:
    key = f"{name}|{channel or ''}".encode()
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()
    return LOGSRC[f"{slug}-{hashlib.sha1(key).hexdigest()[:10]}"]


def stix_to_graph(bundle: dict) -> Graph:
    g = Graph()
    g.bind("akg", AKG)
    g.bind("ls", LOGSRC)

    objects = bundle["objects"]
    iri_by_stix: dict[str, URIRef] = {}
    tactic_by_shortname: dict[str, URIRef] = {}

    for obj in objects:
        if obj["type"] == "x-mitre-collection":
            g.add((AKG.dataset, AKG.attackVersion, Literal(obj.get("x_mitre_version", "unknown"))))
            g.add((AKG.dataset, RDFS.label, Literal(obj.get("name", "ATT&CK"))))
        cls = CLASS_BY_STIX_TYPE.get(obj["type"])
        if cls is None:
            continue
        iri = _iri(obj)
        iri_by_stix[obj["id"]] = iri
        if obj["type"] == "x-mitre-tactic":
            tactic_by_shortname[obj["x_mitre_shortname"]] = iri

    for obj in objects:
        cls = CLASS_BY_STIX_TYPE.get(obj["type"])
        if cls is None:
            continue
        s = iri_by_stix[obj["id"]]
        g.add((s, RDF.type, cls))
        g.add((s, AKG.stixId, Literal(obj["id"])))
        if ref := _attack_ref(obj):
            g.add((s, AKG.attackId, Literal(ref["external_id"])))
        if name := obj.get("name"):
            g.add((s, RDFS.label, Literal(name)))
        if desc := clean_text(obj.get("description")):
            g.add((s, AKG.description, Literal(desc)))
        g.add((s, AKG.revoked, Literal(bool(obj.get("revoked", False)))))
        g.add((s, AKG.deprecated, Literal(bool(obj.get("x_mitre_deprecated", False)))))
        for platform in obj.get("x_mitre_platforms", []):
            g.add((s, AKG.platform, Literal(platform)))

        t = obj["type"]
        if t == "attack-pattern":
            if obj.get("x_mitre_is_subtechnique"):
                g.add((s, RDF.type, AKG.SubTechnique))
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack" and phase["phase_name"] in tactic_by_shortname:
                    g.add((s, AKG.inTactic, tactic_by_shortname[phase["phase_name"]]))
        elif t == "x-mitre-tactic":
            g.add((s, AKG.shortname, Literal(obj["x_mitre_shortname"])))
        elif t == "x-mitre-detection-strategy":
            for ref in obj.get("x_mitre_analytic_refs", []):
                if ref in iri_by_stix:
                    g.add((s, AKG.hasAnalytic, iri_by_stix[ref]))
        elif t == "x-mitre-analytic":
            for src in obj.get("x_mitre_log_source_references", []):
                ls = _add_logsource(g, src["name"], src.get("channel"))
                g.add((s, AKG.usesLogSource, ls))
                if dc := iri_by_stix.get(src.get("x_mitre_data_component_ref", "")):
                    g.add((ls, AKG.ofDataComponent, dc))
        elif t == "x-mitre-data-component":
            for src in obj.get("x_mitre_log_sources", []):
                ls = _add_logsource(g, src["name"], src.get("channel"))
                g.add((ls, AKG.ofDataComponent, s))
        elif t in ("malware", "tool"):
            g.add((s, RDF.type, AKG.Software))

    for obj in objects:
        if obj["type"] != "relationship" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        pred = PREDICATE_BY_RELATIONSHIP.get(obj["relationship_type"])
        src, dst = iri_by_stix.get(obj["source_ref"]), iri_by_stix.get(obj["target_ref"])
        if pred is not None and src is not None and dst is not None:
            g.add((src, pred, dst))

    return g


def _add_logsource(g: Graph, name: str, channel: str | None) -> URIRef:
    name = name.strip()
    channel = (channel or "").strip() or None
    if channel and channel.lower() == "none":
        channel = None
    ls = logsource_iri(name, channel)
    g.add((ls, RDF.type, AKG.LogSource))
    g.add((ls, AKG.logSourceName, Literal(name)))
    if channel:
        g.add((ls, AKG.channel, Literal(channel)))
    for code in event_codes(channel):
        g.add((ls, AKG.eventCode, Literal(code, datatype=XSD.integer)))
    return ls


def rule_files() -> list[tuple[str, str]]:
    folder = resources.files("attackkg") / "rules"
    return sorted((p.name, p.read_text(encoding="utf-8")) for p in folder.iterdir() if p.name.endswith(".rq"))


def apply_rules(g: Graph, max_rounds: int = 20) -> dict[str, int]:
    """Forward chaining: run the SPARQL UPDATE rules in file-name order, and repeat the
    whole set until a round adds no triple. Every rule only inserts, so this terminates
    at the fixpoint. Returns the number of triples each rule added."""
    rules = rule_files()
    added = {name: 0 for name, _ in rules}
    for _ in range(max_rounds):
        changed = False
        for name, text in rules:
            before = len(g)
            g.update(text, initNs={"akg": AKG, "rdfs": RDFS, "rdf": RDF})
            if len(g) > before:
                added[name] += len(g) - before
                changed = True
        if not changed:
            return added
    raise RuntimeError(f"rules did not reach a fixpoint in {max_rounds} rounds")


def build(stix_path: Path, out_path: Path) -> dict:
    bundle = json.loads(Path(stix_path).read_text(encoding="utf-8"))
    g = stix_to_graph(bundle)
    base = len(g)
    added = apply_rules(g)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    g.serialize(destination=str(out_path), format="turtle")
    return {"asserted_triples": base, "inferred_triples": added, "total_triples": len(g), "output": str(out_path)}
