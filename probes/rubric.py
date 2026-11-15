"""Site-quality rubric (research/site-quality-rubric.md) as build-failing checks.

Implements R1, R2, R3, R4, R6, R7 and R9 from issue #9. R5, R8 and R10 are
tracked in the rubric document and are out of scope here. Every check grades
what the rendered page actually shows: the row model is built with
``probes.render._rows`` so a check cannot drift from the renderer, and template
prose is read from ``site/templates`` so R7 grades the maintained source, not
generated HTML.

Detection limits that are semantic, not mechanical, are stated per check and
must not be papered over: R7 can only recognise claims whose subject is in the
provider lexicon or whose sentence carries a price/rate; R3 compares the two
ranking layers that exist on the current site (adapter outcomes vs assessment
axis states).

Usage:
    python -m probes.rubric            # print report; exit 1 on any failure
"""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

from probes import render
from probes.quality import TRANSPORT, compute as compute_quality
from verifiers.common import REQUIRED_LAYERS_BY_SHAPE

REPO_ROOT = Path(__file__).resolve().parents[1]

# R1: every mark a None value renders as (render.NONE_MARKS) counts as one
# unchecked state, so relabeling empty cells cannot pass the check. A tie for
# most common still counts.
REJECT_MARK = "×"
REVIEW_PENDING_MARK = "○"

# R4: shapes that explicitly claim no architecture. Anything else a row emits
# must have a required-layer set, or the required-but-missing semantics vanish.
SHAPE_SENTINELS = {"", "skipped", "error", "retired", "missing"}

# R9 thresholds from the rubric, derived from the measured ~4.2-day deploy
# cadence: a 14-day-old ledger means at least three unreviewed builds.
R9_BACKLOG_MAX = 5      # pass requires backlog < 5
R9_NEWEST_MAX_DAYS = 14  # pass requires days_since_last_audit < 14

# R7: a sentence is a claim if it names a tracked subject or states a price or
# rate. The lexicon is the provider inventory plus brand aliases; a claim about
# an unlisted subject is invisible to this check unless it carries a price.
R7_BRAND_ALIASES = {"z.ai"}
DATED_VARIABLES = re.compile(
    r"\b(as_of|reviewed_at|curated_at|evidence_date|generated_at|"
    r"checked_at|last_new|audited_at|first_seen_at|observed_at)\b")
ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
PRICE_OR_RATE = re.compile(r"\$\s?\d|\d\s*%|\d\s*/\s*[mMk]\b")

_VAR = "\ue000"  # sentinel wrapping Jinja expression contents before stripping


def _result(check_id: str, name: str, violations: list, **measured) -> dict:
    return {"id": check_id, "name": name, "passed": not violations,
            "violations": violations, **measured}


def r1_density(rows: list) -> dict:
    """R1: the rendered matrix must carry signal, not shape membership."""
    marks, by_column = collections.Counter(), collections.defaultdict(collections.Counter)
    for row in rows:
        for key, cell in row["matrix_cells"].items():
            marks[cell["mark"]] += 1
            by_column[key][cell["mark"]] += 1
    violations = []
    if not marks:
        return _result("R1", "information density",
                       ["no rendered cells: the matrix shows nothing"])
    unchecked = sum(marks[mark] for mark in render.NONE_MARKS)
    if unchecked >= max((n for mark, n in marks.items() if mark not in render.NONE_MARKS), default=0):
        violations.append(
            f"modal cell state is unchecked {sorted(render.NONE_MARKS)} "
            f"({unchecked}/{sum(marks.values())} cells)")
    if len(rows) >= 2:
        for key, counts in sorted(by_column.items()):
            if len(counts) == 1:
                violations.append(
                    f"column {key!r} is constant ({next(iter(counts))} in all {len(rows)} rows)")
    return _result("R1", "information density", violations,
                   cell_states=dict(marks.most_common()), columns=len(by_column))


def r2_reconstructability(rows: list) -> dict:
    """R2: every layer a verdict depends on must be on the page for that row."""
    scores, violations = [], []
    for row in rows:
        shape = row["attestation_type"]
        if shape in SHAPE_SENTINELS:
            continue
        required = REQUIRED_LAYERS_BY_SHAPE.get(shape)
        if required is None:
            continue  # R4 reports the unknown shape; there is no bar to render yet
        rendered = {check["key"] for check in row["checks"]} | set(row["matrix_cells"])
        missing = sorted(required - rendered)
        if missing:
            violations.append(f"{row['route_id']}: required layers not rendered: {', '.join(missing)}")
            scores.append(0)
        else:
            scores.append(1)
    if not scores:
        violations.append("no row carries a characterized shape, so no verdict is reconstructable")
    return _result("R2", "verdict reconstructability", violations,
                   minimum=min(scores) if scores else None, scored_rows=len(scores))


def _computed_signal(rows: list) -> dict:
    signal = {}
    for provider in sorted({row["provider"] for row in rows}):
        outcomes = {row["outcome"] for row in rows if row["provider"] == provider}
        if "verified" in outcomes:
            signal[provider] = "positive"
        elif outcomes <= {"rejected", "unavailable"}:
            signal[provider] = "negative"
        else:
            signal[provider] = "neutral"
    return signal


def _editorial_signal(routes: dict, assessments: dict) -> dict:
    """Provider -> {'positive'|'negative': [assessment cells]} from rendered routes."""
    signal: dict = {}
    route_provider = {route["id"]: route["provider"]
                      for route in routes["routes"]}
    for definition in assessments["routes"]:
        provider = route_provider[definition["id"]]
        for cell in definition.get("axes", {}).values():
            if cell.get("state") in ("established", "gap"):
                kind = "positive" if cell["state"] == "established" else "negative"
                signal.setdefault(provider, {}).setdefault(kind, []).append(cell)
    return signal


def r3_coherence(rows: list, routes: dict, assessments: dict) -> dict:
    """R3: computed status and editorial verdict must not rank oppositely unexplained."""
    computed = _computed_signal(rows)
    editorial = _editorial_signal(routes, assessments)
    violations = []
    for provider, cells in sorted(editorial.items()):
        signal = computed.get(provider)
        if signal is None or signal == "neutral":
            continue
        opposite = "negative" if signal == "positive" else "positive"
        for cell in cells.get(opposite, []):
            if not cell.get("issue_urls"):
                violations.append(
                    f"{provider}: computed status is {signal} but editorial state "
                    f"{cell.get('state')!r} ({cell.get('label')!r}) carries no linked explanation")
    return _result("R3", "same-page coherence", violations,
                   computed=computed, editorial={p: sorted(k for k in c) for p, c in editorial.items()})


def r4_cause_separation(rows: list) -> dict:
    """R4: transport causes must not render as rejection; shapes must have semantics."""
    violations = []
    for row in rows:
        error = str(row.get("error") or "")
        if TRANSPORT.search(error):
            rejected_cells = [check["key"] for check in row["checks"] if check["mark"] == REJECT_MARK]
            rejected_cells += [key for key, cell in row["matrix_cells"].items()
                               if cell["mark"] == REJECT_MARK]
            if row["outcome"] == "rejected" or rejected_cells:
                violations.append(
                    f"{row['route_id']}: transport cause {error.splitlines()[0][:60]!r} rendered "
                    f"in the failure encoding (outcome={row['outcome']}, rejected cells={sorted(set(rejected_cells))})")
    unknown_shapes = sorted({row["attestation_type"] for row in rows
                             if row["attestation_type"] not in SHAPE_SENTINELS
                             and row["attestation_type"] not in REQUIRED_LAYERS_BY_SHAPE})
    for shape in unknown_shapes:
        violations.append(f"attestation_type {shape!r} has no REQUIRED_LAYERS_BY_SHAPE entry")
    return _result("R4", "cause separation", violations,
                   transport_in_failure_encoding=sum("transport cause" in v for v in violations),
                   unknown_shapes=unknown_shapes)


def r6_subject_separation(rows: list) -> dict:
    """R6: auditor-state cells (review pending) must not sit in provider columns."""
    violations = []
    for row in rows:
        pending = [key for key, cell in row["matrix_cells"].items()
                   if cell["mark"] == REVIEW_PENDING_MARK]
        pending += [check["key"] for check in row["checks"]
                    if check["mark"] == REVIEW_PENDING_MARK]
        if pending:
            violations.append(f"{row['route_id']}: auditor-state cells in provider columns: {sorted(set(pending))}")
    return _result("R6", "subject separation", violations)


def _template_sentences(text: str) -> list:
    """Static prose sentences with Jinja expressions kept as sentinels."""
    text = re.sub(r"<(script|style)\b.*?</\1>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.S)
    text = re.sub(r"\{\{(.+?)\}\}", lambda m: f" {_VAR}{m.group(1)}{_VAR} ", text)
    text = re.sub(r"\{%-?.*?-?%\}", " ", text)
    text = re.sub(r"</(li|p|h[1-6]|td|th|summary|figcaption)>|<br\b[^>]*>", ". ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.replace(_VAR, "|")
    for sentence in re.split(r"(?<=[.!?;:])\s+", text):
        yield sentence.strip()


def _is_dated(sentence: str) -> bool:
    return bool(ISO_DATE.search(sentence) or DATED_VARIABLES.search(sentence))


def _claim_subject(sentence: str, subjects: re.Pattern) -> str | None:
    match = subjects.search(sentence)
    return match.group(0).lower() if match else (
        "price/rate" if PRICE_OR_RATE.search(sentence) else None)


def r7_prose_dating(templates: dict) -> dict:
    """R7: hand-written template claims must carry an as-of date.

    A claim is a sentence naming a tracked subject (provider inventory stems
    plus configured brand aliases) or stating a price or rate. A date is an
    ISO literal or a Jinja reference to dated data.
    """
    subjects = re.compile(
        "|".join(sorted((re.escape(s) for s in templates["subjects"]), key=len, reverse=True)),
        re.I) if templates["subjects"] else None
    violations = []
    checked = 0
    for name, text in sorted(templates["files"].items()):
        for sentence in _template_sentences(text):
            if len(sentence.split()) < 3:
                continue
            subject = _claim_subject(sentence, subjects) if subjects else None
            if subject:
                checked += 1
                if not _is_dated(sentence):
                    violations.append(f"{name}: undated claim ({subject}): {sentence[:120]}")
    return _result("R7", "prose-data drift", violations, claims=checked)


def r9_audit_liveness(audit_debt: dict) -> dict:
    """R9: the audit ledger must be alive: backlog < 5, newest record < 14 days."""
    violations = []
    backlog = audit_debt.get("backlog")
    days = audit_debt.get("days_since_last_audit")
    if backlog is None or backlog >= R9_BACKLOG_MAX:
        violations.append(f"audit backlog {backlog} is not < {R9_BACKLOG_MAX}")
    if days is None:
        violations.append("no audit ledger record exists, so ledger age is unmeasurable")
    elif days >= R9_NEWEST_MAX_DAYS:
        violations.append(f"newest ledger record is {days} days old, not < {R9_NEWEST_MAX_DAYS}")
    return _result("R9", "audit liveness", violations,
                   backlog=backlog, days_since_last_audit=days,
                   last_audit=audit_debt.get("last_audit"))


def run(snapshot: dict | None = None, repo_root: Path | None = None) -> dict:
    """Run the implemented rubric checks. Fails closed: a check with nothing to
    grade is a violation, never a silent pass."""
    root = repo_root or REPO_ROOT
    snapshot = snapshot if snapshot is not None else json.loads((root / "data/latest.json").read_text())
    rows = render._rows(snapshot)
    routes = json.loads((root / "data/routes.json").read_text())
    assessments = json.loads((root / "data/assessments/routes.json").read_text())
    quality = compute_quality(latest=snapshot)
    provider_stems = {p.stem for p in (root / "providers").glob("*.md")} - {"_template"}
    templates = {
        "subjects": provider_stems | R7_BRAND_ALIASES,
        "files": {p.name: p.read_text() for p in sorted((root / "site/templates").glob("*.j2"))},
    }
    checks = [
        r1_density(rows),
        r2_reconstructability(rows),
        r3_coherence(rows, routes, assessments),
        r4_cause_separation(rows),
        r6_subject_separation(rows),
        r7_prose_dating(templates),
        r9_audit_liveness(quality["audit_debt"]),
    ]
    return {"checks": checks, "passed": all(check["passed"] for check in checks)}


def main() -> int:
    report = run()
    for check in report["checks"]:
        status = "pass" if check["passed"] else "FAIL"
        line = f"{check['id']} {check['name']:<26} {status}"
        print(line)
        for violation in check["violations"]:
            print(f"    - {violation}")
    if not report["passed"]:
        print("\nsite-quality rubric failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
