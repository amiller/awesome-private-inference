"""Record the actual local observation code and lockfile, including uncommitted code."""
from __future__ import annotations
import hashlib
import json
import subprocess
from pathlib import Path


def revision(directory):
    try:
        return subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"],
                                       stderr=subprocess.DEVNULL, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def capture(root: Path, upstream_path: str = "") -> dict:
    files = sorted([*root.glob("verifiers/*.py"), *root.glob("probes/*.py"),
                    root / "uv.lock", root / "data/instrument.json"])
    manifest = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in files if path.is_file()}
    spec = json.loads((root / "data/instrument.json").read_text())
    payload = {"files": manifest, "upstream_expected_revision": spec["nearai_verifier_revision"],
               "upstream_actual_revision": revision(upstream_path) if upstream_path else "not_configured"}
    fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**payload, "revision": fingerprint, "repository_commit": revision(root),
            "scope": "Exact source and lockfile bytes; does not attest installed packages or runtime integrity"}
