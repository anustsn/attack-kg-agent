import json
from pathlib import Path

import pytest

from attackkg.kg import KnowledgeGraph
from attackkg.stix2rdf import apply_rules, stix_to_graph

FIXTURE = Path(__file__).parent / "fixtures" / "mini_bundle.json"


@pytest.fixture(scope="session")
def graph():
    g = stix_to_graph(json.loads(FIXTURE.read_text()))
    apply_rules(g)
    return g


@pytest.fixture(scope="session")
def kg(graph):
    return KnowledgeGraph(graph)
