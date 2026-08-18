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
    "near-ai": [
        "openai/gpt-oss-120b",
        "zai-org/GLM-5.1-FP8",
    ],
    "venice": [
        "e2ee-glm-5",
        "e2ee-qwen3-5-122b-a10b",
        "e2ee-uncensored-24b-p",
        "e2ee-gpt-oss-120b-p",
    ],
    "tinfoil": [
        "router",
        "gpt-oss-120b",
        "llama3-3-70b",
        "gemma4-31b",
    ],
    "chutes": [
        "Qwen3-32B-TEE",
        "gemma-4-31B-TEE",
        "GLM-5-TEE",
        "DeepSeek-V3.2-TEE",
        "Kimi-K2.6-TEE",
    ],
}
