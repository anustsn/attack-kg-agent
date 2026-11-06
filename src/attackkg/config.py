"""Pinned data versions and file locations."""

from __future__ import annotations

import os
from pathlib import Path

ATTACK_VERSION = "20.0"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)

SIGMA_RELEASE = "r2026-07-01"
SIGMA_URL = "https://github.com/SigmaHQ/sigma/releases/download/{release}/sigma_core.zip"

DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_EFFORT = "medium"


def data_dir() -> Path:
    """Root of downloaded and generated data. Override with ATTACKKG_DATA."""
    return Path(os.environ.get("ATTACKKG_DATA", "data")).resolve()


def raw_dir() -> Path:
    return data_dir() / "raw"


def attack_json_path(version: str = ATTACK_VERSION) -> Path:
    return raw_dir() / f"enterprise-attack-{version}.json"


def sigma_zip_path(release: str = SIGMA_RELEASE) -> Path:
    return raw_dir() / f"sigma_core-{release}.zip"


def kg_path(version: str = ATTACK_VERSION) -> Path:
    return data_dir() / "kg" / f"enterprise-attack-{version}.ttl"


def benchmark_path(release: str = SIGMA_RELEASE) -> Path:
    return data_dir() / "benchmark" / f"sigma-{release}-attack-{ATTACK_VERSION}.jsonl"
