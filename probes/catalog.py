"""Curated model list per provider — intentionally small, high-signal.

Probes hit each entry on every run. Adding a model means adding a row to the
matrix; keep to representatives of each attestation shape.
"""

MODELS: dict[str, list[str]] = {
    "near-ai": [
        "openai/gpt-oss-120b",
        "zai-org/GLM-5.1-FP8",
        "zai-org/GLM-5-FP8",
        "Qwen/Qwen3-30B-A3B-Instruct-2507",
        "deepseek-ai/DeepSeek-V3-0324",
        "meta-llama/Llama-4-Scout-17B-16E-Instruct",
    ],
    "redpill": [
        "phala/gpt-oss-20b",
        "phala/gpt-oss-120b",
        "phala/qwen-2.5-7b-instruct",
        "phala/glm-4.7",
        "phala/deepseek-v3.2",
        "phala/kimi-k2.5",
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
        "deepseek-v4-pro",
        "kimi-k2-6",
    ],
}
