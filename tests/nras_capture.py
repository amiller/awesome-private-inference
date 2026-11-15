"""NVIDIA JWKS captured 2026-11-05 (only the kids the captured NRAS responses
use) and a clock pinned to a capture's time, for hermetic NRAS replays."""
import datetime
import json
from pathlib import Path

from verifiers import nvidia_nras

FIXTURES = Path(__file__).resolve().parent / "fixtures"
JWKS = json.loads((FIXTURES / "nras_jwks.json").read_text())["jwks"]


def pin_clock(monkeypatch, iso: str) -> None:
    now = datetime.datetime.fromisoformat(iso)
    monkeypatch.setattr(nvidia_nras, "_now", lambda: now)
