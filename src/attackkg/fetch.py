"""Download the pinned MITRE ATT&CK STIX bundle and the SigmaHQ core rule set."""

from __future__ import annotations

import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import config

USER_AGENT = "attack-kg-agent/0.1 (+research prototype)"


def _download(url: str, dest: Path) -> str:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    sha = hashlib.sha256()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
        while chunk := resp.read(1 << 20):
            sha.update(chunk)
            out.write(chunk)
    tmp.replace(dest)
    return sha.hexdigest()


def fetch_all(attack_version: str = config.ATTACK_VERSION, sigma_release: str = config.SIGMA_RELEASE,
              force: bool = False) -> dict:
    """Download both sources unless present. Returns the provenance record written to SOURCES.json."""
    targets = {
        "attack": (config.ATTACK_URL.format(version=attack_version), config.attack_json_path(attack_version)),
        "sigma": (config.SIGMA_URL.format(release=sigma_release), config.sigma_zip_path(sigma_release)),
    }
    record_path = config.raw_dir() / "SOURCES.json"
    record = json.loads(record_path.read_text()) if record_path.exists() else {}
    for key, (url, dest) in targets.items():
        if dest.exists() and not force:
            print(f"[fetch] {dest.name} already present")
            continue
        print(f"[fetch] {url}")
        digest = _download(url, dest)
        record[key] = {
            "url": url,
            "file": dest.name,
            "sha256": digest,
            "retrieved": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(json.dumps(record, indent=2))
    return record
