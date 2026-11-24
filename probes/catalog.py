"""Curated model list per provider — intentionally small, high-signal.

Probes hit each entry on every run. Adding a model means adding a row to the
matrix; keep to representatives of each attestation shape.
"""

MODELS: dict[str, list[str]] = {
    # One attested workload, three hostnames. They differ only in whether the
    # measured tee_only_domains forces attested serving, which is the point.
    "aci-gateway": [
        "tee.redpill.ai",
        "inference.phala.com",
        "api.redpill.ai",
    ],
    # 2026-11-15: both previous rows retired (see RETIRED). These are the two
    # models teep verified end to end on neardirect/nearcloud that day.
    "near-ai": [
        "z-ai/glm-5.3-flash",
        "Qwen/Qwen3.8-27B",
        # 2026-11-24: the DeepSeek machines gpu02/gpu04 serve only this lane.
        "deepseek-ai/DeepSeek-V4.1-Flash-1017",
    ],
    # Refreshed 2026-08-18: Venice renamed its whole e2ee line, so the old ids
    # 404'd or returned an unusable body. Every id here answered /tee/attestation
    # with 200 on that date.
    "venice": [
        "e2ee-glm-5-1",
        "e2ee-qwen3-6-35b-a3b",
        "e2ee-gemma-4-31b",
        "e2ee-gpt-oss-120b-p",
        "e2ee-qwen3-6-35b-a3b-uncensored-p",
    ],
    # Router only since 2026-08-18. The per-model enclaves are no longer reachable
    # from outside: llama3-3-70b and gemma4-31b are NXDOMAIN, and gpt-oss-120b-0
    # accepts TCP then fails TLS ("unexpected eof"). Their hostnames used to be
    # recoverable from the router's config.yml, which now says "live config with
    # domain and settings is set in the tinfoil backend" and pins only model -> repo.
    # So we cannot rediscover them, and probing the enclaves where prompts actually
    # run is no longer something a third party can do. Tracked as a coverage loss
    # rather than papered over with rows that are red for transport reasons.
    # What replaces it: the router row now also checks that every model the router
    # serves is pinned to a confidential-* repo in the trust anchor, so a model
    # served from nothing reviewed still trips the row (verifiers/tinfoil.py).
    "tinfoil": [
        "router",
    ],
    "chutes": [
        "gemma-4-31B-TEE",
        "GLM-5.1-TEE",
        "GLM-5.2-TEE",
        "DeepSeek-V3.2-TEE",
        "Kimi-K2.6-TEE",
    ],
}

# Deliberate removals. `python -m probes.collect` records each as a visible
# retirement observation whenever the route's latest observation is not one.
RETIRED: dict[str, list[dict]] = {
    "near-ai": [
        {"model": "openai/gpt-oss-120b", "retired_at": "2026-11-15T00:00:00Z",
         "summary": "NEAR no longer serves this model: 23 captures 2026-10-13..2026-11-14 answered "
                    "HTTP 400 \"Model 'openai/gpt-oss-120b' not found\"; the other 15 were 503s and "
                    "timeouts, none an attestation"},
        {"model": "zai-org/GLM-5.1-FP8", "retired_at": "2026-11-15T00:00:00Z",
         "summary": "NEAR serves a different model under this id: all 34 attestations 2026-10-14..2026-11-14 "
                    "came from a model CVM reporting z-ai/glm-5.3-flash, which no anchor covers "
                    "(anchored: false)"},
    ],
    "chutes": [
        {"model": "Qwen3-32B-TEE", "retired_at": "2026-11-15T00:00:00Z",
         "summary": "Chutes removed the chute: all 20 captures 2026-10-26..2026-11-14 answered HTTP 404 "
                    "\"Chute not found\" for chute_id ac059e33-eb27-541c-b9a9-24b214036475"},
    ],
}
