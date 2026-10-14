"""Run the labeled deterministic continuity corpus and save its actual result."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from replay_cases import CASES, evaluate


def main() -> int:
    results = [evaluate(case) for case in CASES]
    document = {
        "kind": "deterministic_continuity_replay",
        "scope": "Seeded observation/change detection only; no agent review evaluation or live provider claim",
        "run_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "case_count": len(results), "passed": sum(r["passed"] for r in results),
        "failed": sum(not r["passed"] for r in results), "cases": results,
    }
    output = Path(__file__).with_name("replay-results.json")
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"{document['passed']}/{document['case_count']} deterministic replay cases passed: {output}")
    return 1 if document["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
