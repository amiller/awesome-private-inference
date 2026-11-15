"""Site-quality rubric checks: each fires on tampered input and passes a clean case.

Real retained evidence (data/latest.json, data/assessments/routes.json,
site/templates/, data/audits/) is graded by the pinned current-state test; every
check additionally gets a synthetic negative control that mutates exactly one
dimension, proving the check cannot silently pass.
"""
from __future__ import annotations

import collections
from dataclasses import fields

import pytest

from probes import rubric
from probes.render import MATRIX_KEYS, _rows
from verifiers.common import REQUIRED_LAYERS_BY_SHAPE, ScoreCard

ALL_FIELDS = [f.name for f in fields(ScoreCard)]
TDX_GPU_KEYS = set(MATRIX_KEYS) | REQUIRED_LAYERS_BY_SHAPE["tdx+gpu"]


def scorecard(**overrides) -> dict:
    card = {name: None for name in ALL_FIELDS}
    card.update(overrides)
    return card


def chutes_card(**overrides) -> dict:
    """Every chutes-tee required layer decided, so no cell needs a LAYER_GAPS entry."""
    return scorecard(**{"tdx_verified": True, "nonce_bound": True, "report_data_binds_key": True,
                        "serving_code_attested": False, **overrides})


def row(provider="near-ai", model="m1", shape="tdx+gpu", outcome="verified",
        error=None, card=None, **extra):
    return {"provider": provider, "model": model, "attestation_type": shape,
            "outcome": outcome, "outcome_reason": "synthetic", "error": error,
            "scorecard": scorecard() if card is None else card,
            "details": {}, "verified_at": "2026-11-05T00:00:00Z", **extra}


def snapshot(*rows):
    attestations = collections.defaultdict(list)
    for item in rows:
        attestations[item["provider"]].append(item)
    return {"generated_at": "2026-11-05T00:00:00Z", "attestations": dict(attestations), "pricing": {}}


def rendered(*rows):
    return _rows(snapshot(*rows))


# --- R1 information density ---

def test_r1_passes_when_signal_dominates():
    rows = rendered(
        row(model="a", card=scorecard(**{k: True for k in TDX_GPU_KEYS})),
        row(model="b", card=scorecard(**{k: False for k in TDX_GPU_KEYS})),
    )
    result = rubric.r1_density(rows)
    assert result["passed"], result


def test_r1_fires_when_not_checked_is_modal():
    rows = rendered(row(model="a"), row(model="b"), row(model="c"))
    result = rubric.r1_density(rows)
    assert not result["passed"]
    assert any("modal cell state" in v for v in result["violations"])


def test_r1_counts_every_none_mark_as_unchecked():
    rows = rendered(*(row(provider="chutes", model=m, shape="chutes-tee", card=chutes_card()) for m in "abc"))
    result = rubric.r1_density(rows)
    assert result["cell_states"]["n/a"] > result["cell_states"]["✓"]
    assert any("modal cell state" in v for v in result["violations"])


def test_r1_fires_on_constant_column():
    rows = rendered(
        row(model="a", card=scorecard(**{k: True for k in TDX_GPU_KEYS})),
        row(model="b", card=scorecard(**{k: True for k in TDX_GPU_KEYS})),
    )
    result = rubric.r1_density(rows)
    assert not result["passed"]
    assert {v.split("'")[1] for v in result["violations"] if "constant" in v} == set(MATRIX_KEYS)


def test_r1_fires_on_empty_matrix():
    assert not rubric.r1_density([])["passed"]


# --- R2 verdict reconstructability ---

def test_r2_passes_when_every_required_layer_rendered():
    card = scorecard(nonce_bound=True, tdx_verified=True, report_data_binds_key=True,
                     serving_code_attested=True)
    result = rubric.r2_reconstructability(rendered(row(shape="chutes-tee", card=card)))
    assert result["passed"] and result["minimum"] == 1.0, result


def test_r2_fires_when_a_required_layer_is_not_rendered():
    card = scorecard(nonce_bound=True, tdx_verified=True, report_data_binds_key=True)
    del card["serving_code_attested"]
    result = rubric.r2_reconstructability(rendered(row(shape="chutes-tee", card=card)))
    assert not result["passed"]
    assert "serving_code_attested" in result["violations"][0]
    assert result["minimum"] == 0


def test_r2_fires_when_no_row_is_characterized():
    result = rubric.r2_reconstructability(rendered(row(shape="")))
    assert not result["passed"]


# --- R3 same-page coherence ---

def routes_and_assessment(state, issue_urls=None):
    routes = {"routes": [{"id": "p-route", "provider": "p", "observation_aliases": ["p/*"]}]}
    cell = {"state": state, "label": "synthetic", "reason": "test",
            "evidence": "e", "missing": "m", "limitation": "ours",
            "issue_urls": issue_urls or []}
    assessments = {"routes": [{"id": "p-route", "axes": {"hardware": cell}}]}
    return routes, assessments


def test_r3_computed_positive_vs_editorial_gap_fires_without_linked_explanation():
    routes, assessments = routes_and_assessment("gap")
    rows = rendered(row(provider="p", outcome="verified"))
    result = rubric.r3_coherence(rows, routes, assessments)
    assert not result["passed"]
    assert "no linked explanation" in result["violations"][0]


def test_r3_linking_an_issue_suppresses_the_violation():
    routes, assessments = routes_and_assessment("gap", ["https://github.com/o/r/issues/1"])
    rows = rendered(row(provider="p", outcome="verified"))
    assert rubric.r3_coherence(rows, routes, assessments)["passed"]


def test_r3_computed_negative_vs_editorial_established_fires():
    routes, assessments = routes_and_assessment("established")
    rows = rendered(row(provider="p", outcome="rejected"), row(provider="p", model="m2", outcome="unavailable"))
    result = rubric.r3_coherence(rows, routes, assessments)
    assert not result["passed"]
    assert "computed status is negative" in result["violations"][0]


def test_r3_assessment_without_a_route_raises():
    routes, assessments = routes_and_assessment("gap")
    assessments["routes"][0]["id"] = "unlisted"
    with pytest.raises(KeyError):
        rubric.r3_coherence(rendered(row(provider="p")), routes, assessments)


def test_r3_neutral_computed_status_never_contradicts():
    routes, assessments = routes_and_assessment("gap")
    rows = rendered(row(provider="p", outcome="not_checked"))
    assert rubric.r3_coherence(rows, routes, assessments)["passed"]


# --- R4 cause separation ---

def test_r4_transport_cause_outside_failure_encoding_passes():
    rows = rendered(row(outcome="unavailable", error="RuntimeError: HTTP 404 on /e2e/instances"))
    assert rubric.r4_cause_separation(rows)["passed"]


def test_r4_transport_cause_rendered_as_rejected_outcome_fires():
    rows = rendered(row(outcome="rejected", error="RuntimeError: HTTP 404 on /e2e/instances"))
    result = rubric.r4_cause_separation(rows)
    assert not result["passed"]
    assert "transport cause" in result["violations"][0]


def test_r4_transport_cause_with_rejected_cell_fires():
    rows = rendered(row(shape="chutes-tee", outcome="unavailable", error="HTTP 503 Service Unavailable",
                        card=chutes_card(nonce_bound=False)))
    result = rubric.r4_cause_separation(rows)
    assert not result["passed"]
    assert "nonce_bound" in result["violations"][0]


def test_r4_unknown_shape_fires_and_sentinels_do_not():
    unknown = rendered(row(provider="x", shape="redpill"))
    result = rubric.r4_cause_separation(unknown)
    assert not result["passed"]
    assert any("REQUIRED_LAYERS_BY_SHAPE" in v for v in result["violations"])
    sentinel = rendered(row(provider="x", shape="error"), row(provider="x", model="m2", shape="skipped"),
                        row(provider="x", model="m3", shape="missing"),
                        row(provider="x", model="m4", shape="retired", row_status="retired",
                            retirement_evidence={"retired_at": "2026-11-15T00:00:00Z", "summary": "gone"}))
    assert all("REQUIRED_LAYERS_BY_SHAPE" not in v
               for v in rubric.r4_cause_separation(sentinel)["violations"])


# --- R6 subject separation ---

def test_r6_passes_without_auditor_state_cells():
    assert rubric.r6_subject_separation(rendered(row(shape="chutes-tee", card=chutes_card(backend_attested=True))))["passed"]


def test_r6_fires_on_review_pending_cell_in_provider_column():
    rows = rendered(row(card=scorecard(backend_attested="audit_pending")))
    result = rubric.r6_subject_separation(rows)
    assert not result["passed"]
    assert "backend_attested" in result["violations"][0]


# --- R7 prose-data drift ---

def templates(text):
    return {"subjects": {"maple", "venice", "z.ai"}, "files": {"page.html.j2": text}}


def test_r7_dated_claims_pass():
    text = "<p>Maple publishes PCR0 measurements (as of 2026-10-01).</p>"
    assert rubric.r7_prose_dating(templates(text))["passed"]


def test_r7_dated_variable_counts_as_a_date():
    text = "<p>Venice rates come from {{ pricing.as_of }} data.</p>"
    assert rubric.r7_prose_dating(templates(text))["passed"]


def test_r7_undated_provider_claim_fires():
    text = "<p>Maple publishes PCR0 measurements for its Nitro enclave.</p>"
    result = rubric.r7_prose_dating(templates(text))
    assert not result["passed"]
    assert "undated claim (maple)" in result["violations"][0]


def test_r7_undated_price_claim_fires_without_any_subject_lexicon_hit():
    text = "<p>The pro plan is $30/mo today.</p>"
    result = rubric.r7_prose_dating(templates(text))
    assert not result["passed"]
    assert "price/rate" in result["violations"][0]


def test_r7_navigation_fragments_are_not_claims():
    text = "<nav><a>Chutes</a> <a>Venice</a></nav><script>const x='venice $5';</script>"
    assert rubric.r7_prose_dating(templates(text))["passed"]


# --- R9 audit liveness ---

def test_r9_passes_inside_thresholds():
    assert rubric.r9_audit_liveness({"backlog": 4, "days_since_last_audit": 13,
                                     "last_audit": "2026-10-23"})["passed"]


def test_r9_fires_at_and_above_backlog_threshold():
    assert not rubric.r9_audit_liveness({"backlog": 5, "days_since_last_audit": 1})["passed"]
    assert not rubric.r9_audit_liveness({"backlog": 93, "days_since_last_audit": 1})["passed"]


def test_r9_fires_at_and_above_age_threshold():
    assert not rubric.r9_audit_liveness({"backlog": 0, "days_since_last_audit": 14})["passed"]


def test_r9_fires_when_no_ledger_record_exists():
    result = rubric.r9_audit_liveness({"backlog": 0, "days_since_last_audit": None, "last_audit": None})
    assert not result["passed"]
    assert any("unmeasurable" in v for v in result["violations"])
