"""A small Okapi BM25 index, so keyword retrieval needs no extra dependency."""

from __future__ import annotations

import math
import re
from collections import Counter

_TOKEN = re.compile(r"[a-z0-9]+(?:\.[0-9]+)?")
STOPWORDS = frozenset(
    "a an and are as at be by can for from has have in into is it its may of on or that the their "
    "this to use used uses using via was were which with adversaries adversary".split()
)


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if len(t) > 1 and t not in STOPWORDS]


class BM25:
    def __init__(self, docs: dict[str, str], k1: float = 1.4, b: float = 0.75):
        self.k1, self.b = k1, b
        self.ids = list(docs)
        self.tf = [Counter(tokenize(docs[i])) for i in self.ids]
        self.len = [sum(tf.values()) for tf in self.tf]
        self.avg = sum(self.len) / max(len(self.len), 1)
        df = Counter(term for tf in self.tf for term in tf)
        n = len(self.ids)
        self.idf = {term: math.log(1 + (n - f + 0.5) / (f + 0.5)) for term, f in df.items()}

    def scores(self, query: str) -> dict[str, float]:
        terms = set(tokenize(query))
        out = {}
        for i, (tf, length) in enumerate(zip(self.tf, self.len)):
            s = 0.0
            for term in terms:
                f = tf.get(term)
                if f:
                    s += self.idf[term] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * length / self.avg))
            if s > 0:
                out[self.ids[i]] = s
        return out

    def top(self, query: str, k: int = 10) -> list[tuple[str, float]]:
        return sorted(self.scores(query).items(), key=lambda kv: -kv[1])[:k]
