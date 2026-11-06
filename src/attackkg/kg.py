"""Query layer over the ATT&CK knowledge graph.

The RDF graph is the source of truth. At load time a few SPARQL queries pull out the
facts the agent and the validator need, into plain Python objects, so that tool calls
and checks run in microseconds. Ad hoc SPARQL still works through ``KnowledgeGraph.sparql``.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from rdflib import RDFS, Graph

from .bm25 import BM25
from .stix2rdf import AKG, event_codes

PREFIXES = {"akg": AKG, "rdfs": RDFS}


@dataclass(frozen=True)
class LogSourceRef:
    """A log source as ATT&CK names it, e.g. ("WinEventLog:Sysmon", "EventCode=1")."""

    name: str
    channel: str | None = None

    @property
    def codes(self) -> frozenset[int]:
        return frozenset(event_codes(self.channel))

    def label(self) -> str:
        return f"{self.name} ({self.channel})" if self.channel else self.name


def logsource_matches(alert_ls: LogSourceRef, kg_ls: LogSourceRef) -> bool:
    """True when the alert's log source is one the graph's analytic reads.

    Names must match (case-insensitive). If both sides list Windows event codes, the
    codes must overlap. Free-text channels are not compared, because ATT&CK often
    describes them in prose ("Unusual kinit or klist activity").
    """
    if alert_ls.name.strip().lower() != kg_ls.name.strip().lower():
        return False
    a, k = alert_ls.codes, kg_ls.codes
    return bool(a & k) if (a and k) else True


@dataclass
class Analytic:
    id: str
    platforms: list[str]
    description: str
    log_sources: list[LogSourceRef]


@dataclass
class Technique:
    id: str
    name: str
    iri: str
    is_sub: bool
    revoked: bool
    deprecated: bool
    description: str = ""
    parent_id: str | None = None
    replaced_by: str | None = None
    tactics: list[str] = field(default_factory=list)  # tactic shortnames
    platforms: list[str] = field(default_factory=list)
    detection_ids: list[str] = field(default_factory=list)
    analytics: list[Analytic] = field(default_factory=list)
    observable_via: set[LogSourceRef] = field(default_factory=set)
    mitigations: list[tuple[str, str]] = field(default_factory=list)
    used_by: dict[str, list[tuple[str, str]]] = field(default_factory=lambda: defaultdict(list))
    sub_ids: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return not (self.revoked or self.deprecated)


@dataclass
class Tactic:
    id: str
    name: str
    shortname: str


class KnowledgeGraph:
    def __init__(self, graph: Graph):
        self.graph = graph
        self.version = self._scalar("SELECT ?v WHERE { akg:dataset akg:attackVersion ?v }") or "unknown"
        self.tactics: dict[str, Tactic] = {}
        self.techniques: dict[str, Technique] = {}
        self._load()
        self.index = BM25({t.id: self._search_text(t) for t in self.techniques.values() if t.active})

    # ------------------------------------------------------------------ loading

    @classmethod
    def from_turtle(cls, path: Path | str) -> "KnowledgeGraph":
        g = Graph()
        g.parse(str(path), format="turtle")
        return cls(g)

    def sparql(self, query: str):
        return self.graph.query(query, initNs=PREFIXES)

    def _rows(self, query: str):
        for row in self.sparql(query):
            yield tuple(None if v is None else v.toPython() if hasattr(v, "toPython") else v for v in row)

    def _scalar(self, query: str):
        for row in self._rows(query):
            return row[0]
        return None

    def _load(self) -> None:
        tactic_by_iri = {}
        for iri, tid, name, short in self._rows(
            "SELECT ?t ?id ?name ?short WHERE { ?t a akg:Tactic ; akg:attackId ?id ; rdfs:label ?name ; akg:shortname ?short }"
        ):
            self.tactics[short] = tactic_by_iri[str(iri)] = Tactic(tid, name, short)

        by_iri: dict[str, Technique] = {}
        for iri, tid, name, revoked, deprecated in self._rows(
            "SELECT ?t ?id ?name ?rev ?dep WHERE { ?t a akg:Technique ; akg:attackId ?id ; rdfs:label ?name ; "
            "akg:revoked ?rev ; akg:deprecated ?dep }"
        ):
            t = Technique(tid, name, str(iri), is_sub="." in tid, revoked=bool(revoked), deprecated=bool(deprecated))
            self.techniques[tid] = by_iri[str(iri)] = t

        def each(query):
            for row in self._rows(query):
                t = by_iri.get(str(row[0]))
                if t is not None:
                    yield (t, *row[1:])

        for t, desc in each("SELECT ?t ?d WHERE { ?t a akg:Technique ; akg:description ?d }"):
            t.description = desc
        for t, tac in each("SELECT ?t ?tac WHERE { ?t akg:inTactic ?tac }"):
            t.tactics.append(tactic_by_iri[str(tac)].shortname)
        for t, p in each("SELECT ?t ?p WHERE { ?t a akg:Technique ; akg:platform ?p }"):
            t.platforms.append(p)
        for t, pid in each("SELECT ?t ?pid WHERE { ?t akg:subTechniqueOf ?p . ?p akg:attackId ?pid }"):
            t.parent_id = pid
        for t, rid in each("SELECT ?t ?rid WHERE { ?t akg:currentReplacement ?r . ?r a akg:Technique ; akg:attackId ?rid }"):
            t.replaced_by = rid
        for t, did in each("SELECT ?t ?did WHERE { ?d akg:detects ?t ; akg:attackId ?did }"):
            t.detection_ids.append(did)
        for t, name, channel in each(
            "SELECT ?t ?n ?c WHERE { ?t akg:observableVia ?ls . ?ls akg:logSourceName ?n . OPTIONAL { ?ls akg:channel ?c } }"
        ):
            t.observable_via.add(LogSourceRef(name, channel))
        for t, mid, mname in each(
            "SELECT ?t ?mid ?mn WHERE { ?m akg:mitigates ?t ; akg:attackId ?mid ; rdfs:label ?mn ; akg:deprecated false }"
        ):
            t.mitigations.append((mid, mname))
        for t, kind, uid, uname in each(
            "SELECT ?t ?kind ?uid ?un WHERE { ?u akg:uses ?t ; a ?kind ; akg:attackId ?uid ; rdfs:label ?un ; akg:revoked false . "
            "VALUES ?kind { akg:Group akg:Software akg:Campaign } }"
        ):
            t.used_by[str(kind).rsplit("#", 1)[-1]].append((uid, uname))

        analytics: dict[str, Analytic] = {}
        for aid, desc in self._rows("SELECT ?id ?d WHERE { ?a a akg:Analytic ; akg:attackId ?id . OPTIONAL { ?a akg:description ?d } }"):
            analytics[aid] = Analytic(aid, [], desc or "", [])
        for aid, p in self._rows("SELECT ?id ?p WHERE { ?a a akg:Analytic ; akg:attackId ?id ; akg:platform ?p }"):
            analytics[aid].platforms.append(p)
        for aid, name, channel in self._rows(
            "SELECT ?id ?n ?c WHERE { ?a a akg:Analytic ; akg:attackId ?id ; akg:usesLogSource ?ls . "
            "?ls akg:logSourceName ?n . OPTIONAL { ?ls akg:channel ?c } }"
        ):
            analytics[aid].log_sources.append(LogSourceRef(name, channel))
        for t, aid in each("SELECT ?t ?aid WHERE { ?d akg:detects ?t ; akg:hasAnalytic ?a . ?a akg:attackId ?aid }"):
            t.analytics.append(analytics[aid])

        for t in self.techniques.values():
            t.tactics.sort()
            t.platforms.sort()
            t.analytics.sort(key=lambda a: a.id)
            t.mitigations.sort()
            if t.parent_id and t.parent_id in self.techniques:
                self.techniques[t.parent_id].sub_ids.append(t.id)
        for t in self.techniques.values():
            t.sub_ids.sort()

    def _search_text(self, t: Technique) -> str:
        parts = [t.name] * 3 + [self.full_name(t.id), t.description]
        parts += [a.description for a in t.analytics]
        parts += [ls.label() for ls in t.observable_via]
        return " ".join(parts)

    # ------------------------------------------------------------------ lookups

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id.strip().upper())

    def full_name(self, technique_id: str) -> str:
        t = self.get(technique_id)
        if t is None:
            return ""
        parent = self.get(t.parent_id) if t.parent_id else None
        return f"{parent.name}: {t.name}" if parent else t.name

    def resolve_tactic(self, text: str) -> Tactic | None:
        """Accept a tactic ID (TA0002), name (Execution) or shortname (execution)."""
        key = text.strip().lower().replace("_", "-")
        for tac in self.tactics.values():
            if key in (tac.id.lower(), tac.name.lower(), tac.shortname, tac.name.lower().replace(" ", "-")):
                return tac
        return None

    def search(self, query: str, k: int = 10) -> list[tuple[str, float]]:
        return self.index.top(query, k)

    def observable_matches(self, technique_id: str, log_sources: list[LogSourceRef]) -> list[LogSourceRef]:
        t = self.get(technique_id)
        if t is None:
            return []
        return sorted({kl for kl in t.observable_via for al in log_sources if logsource_matches(al, kl)},
                      key=LogSourceRef.label)

    def techniques_for_log_source(self, ls: LogSourceRef, platform: str | None = None) -> list[Technique]:
        out = []
        for t in self.techniques.values():
            if not t.active:
                continue
            if platform and not _platform_ok(platform, t.platforms):
                continue
            if any(logsource_matches(ls, kl) for kl in t.observable_via):
                out.append(t)
        return sorted(out, key=lambda t: t.id)

    def stats(self) -> dict:
        active = [t for t in self.techniques.values() if t.active]
        return {
            "attack_version": self.version,
            "triples": len(self.graph),
            "tactics": len(self.tactics),
            "techniques_active": sum(not t.is_sub for t in active),
            "subtechniques_active": sum(t.is_sub for t in active),
            "techniques_revoked_or_deprecated": len(self.techniques) - len(active),
            "techniques_with_detection_strategy": sum(bool(t.detection_ids) for t in active),
            "distinct_log_source_names": len({ls.name.lower() for t in active for ls in t.observable_via}),
        }


def _platform_ok(platform: str, platforms: list[str]) -> bool:
    return platform.strip().lower() in {p.lower() for p in platforms}
