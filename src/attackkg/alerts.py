"""The alert format the agent, the baselines and the benchmark share."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .kg import LogSourceRef


@dataclass
class Alert:
    id: str
    title: str
    content: str
    platform: str | None = None
    log_sources: list[LogSourceRef] = field(default_factory=list)
    gold: list[str] = field(default_factory=list)  # expected technique IDs; never shown to a model
    meta: dict = field(default_factory=dict)  # provenance; never shown to a model

    @classmethod
    def from_dict(cls, d: dict) -> "Alert":
        return cls(
            id=str(d["id"]),
            title=d.get("title", ""),
            content=d["content"] if isinstance(d["content"], str) else json.dumps(d["content"], indent=2),
            platform=d.get("platform"),
            log_sources=[LogSourceRef(ls["name"], ls.get("channel")) for ls in d.get("log_sources", [])],
            gold=list(d.get("gold", [])),
            meta=dict(d.get("meta", {})),
        )

    @classmethod
    def load(cls, path: Path | str) -> "Alert":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "platform": self.platform,
            "log_sources": [{"name": ls.name, "channel": ls.channel} for ls in self.log_sources],
            "content": self.content,
            "gold": self.gold,
            "meta": self.meta,
        }

    def query_text(self) -> str:
        """Text for keyword retrieval."""
        return f"{self.title}\n{self.content}"

    def render(self) -> str:
        """What a model sees. Gold labels and provenance are left out."""
        sources = ", ".join(ls.label() for ls in self.log_sources) or "unknown"
        return (
            "<alert>\n"
            f"title: {self.title}\n"
            f"platform: {self.platform or 'unknown'}\n"
            f"log sources: {sources}\n"
            "content:\n"
            f"{self.content.strip()}\n"
            "</alert>"
        )
