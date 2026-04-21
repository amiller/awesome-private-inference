# Contributing

## Add a provider

1. Copy `providers/_template.md` → `providers/<slug>.md`. Fill in claim, endpoint, scorecard gaps.
2. Write `verifiers/<slug>.py`. It must export `verify(api_key, base_url, model, nonce) -> AttestationReport` from `verifiers.common`.
3. Register the provider in `probes/attestation.py` (`PROVIDERS` dict).
4. Add a handful of known models to `probes/catalog.py` (`MODELS` dict).
5. Open a PR. CI runs the probe with repo secrets; the resulting snapshot is committed back.

## Principles

- **Re-verify, don't trust.** Every claim a provider makes should be re-checked against a public verifier (Phala TDX, NVIDIA NRAS, etc.). If a layer isn't re-checkable, note it in the provider's scorecard.
- **Neutral tone.** No "best provider." Report what verifies, what doesn't, and link to the gap.
- **No stored secrets.** API keys live in repo secrets (for CI) or env vars (local). Never committed.
- **Small diffs.** One provider per PR; one verifier shape per PR.

## Don'ts

- Don't hide failures. A provider being offline or a model 404-ing is data.
- Don't add a provider you haven't verified manually at least once.
- Don't add heuristics ("it *probably* passes") — the re-verifier is the single source of truth.
