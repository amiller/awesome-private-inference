"""Versioned, provider-independent vocabulary for captured observations."""

SCHEMA_VERSION = "0.2"
OBSERVATION_VERSION = "1"
OUTCOMES = frozenset({
    "verified", "rejected", "not_checked", "unsupported", "unavailable",
    "stale", "not_applicable",
})
REASONS = frozenset({
    "adapter_accepted", "adapter_rejected", "missing_credentials", "transport_error",
    "http_error", "model_not_found", "evidence_missing", "missing_response",
    "probe_exception", "legacy_adapter_result", "legacy_missing", "not_in_catalog",
    "pending", "unspecified", "adapter_claim", "adapter_not_evaluated", "retired",
    "verification_incomplete",
})


def classify_report(report: dict, *, legacy: bool = False) -> tuple[str, str]:
    """Classify the adapter result without upgrading an old `valid` flag into proof."""
    if legacy:
        return ("verified" if report.get("valid") else "rejected", "legacy_adapter_result")
    declared = (report.get("details") or {}).get("verification_status")
    if declared in OUTCOMES:
        return declared, "verification_incomplete" if declared in ("not_checked", "unsupported") else "unspecified"
    kind = report.get("attestation_type")
    error = str(report.get("error") or "")
    low = error.lower()
    if kind == "skipped" or "not set" in low:
        return "not_checked", "missing_credentials"
    if "model" in low and ("not found" in low or "invalid model" in low):
        return "unavailable", "model_not_found"
    if "no tee attestation" in low or "no attestation" in low:
        return "unavailable", "evidence_missing"
    if error:
        if kind == "error" and not ("http" in low or "timeout" in low):
            return "unavailable", "probe_exception"
        if "http" in low and not any(x in low for x in ("502", "503", "504", "429")):
            return "unavailable", "http_error"
        return "unavailable", "transport_error"
    if report.get("valid") is True:
        return "verified", "adapter_accepted"
    if report.get("valid") is False:
        return "rejected", "adapter_rejected"
    return "not_checked", "unspecified"


def normalize_checks(scorecard: dict | None) -> dict[str, dict[str, str]]:
    """Keep adapter cell claims typed; non-booleans cannot become booleans."""
    checks = {}
    for name, value in (scorecard or {}).items():
        if value is True:
            outcome, reason = "verified", "adapter_claim"
        elif value is False:
            outcome, reason = "rejected", "adapter_claim"
        elif value is None or value == "audit_pending":
            outcome, reason = "not_checked", "adapter_not_evaluated"
        else:
            outcome, reason = "unsupported", "unspecified"
        checks[name] = {"outcome": outcome, "reason": reason}
    return checks
