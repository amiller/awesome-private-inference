# awesome-private-inference

**An observatory of reference-value consistency in confidential inference.**

For each client and request path, we track what software is observed, which values the provider publishes, what the client accepts, and who can authorize a change. Devproof reviews establish what those values cover and whether operators can change the plaintext path outside that boundary.

[Dashboard](https://amiller.github.io/awesome-private-inference/) · [Route inventory](data/routes.json) · [Review workflow](docs/REVIEW-WORKFLOW.md) · [Detailed project review](research/review-2026-10-13/review.md)

[Reference history graph](https://amiller.github.io/awesome-private-inference/history.html) plots captured workload identities, published reference sets, client-policy inputs and document hashes. Select a point for full old/new values and scoped review evidence. Circle size can show set edits or captured text changes; neither is a measurement of deployed code size or security risk. The page is self-contained and works offline.

## Read the evidence by route

An ordinary gateway, an encrypted request relayed through it, and a direct model connection have different plaintext holders. A valid gateway quote does not establish that a downstream model is private. A stable base-image measurement may exclude mutable serving code. A provider-authorized update is not necessarily an independently reviewed update.

The [route inventory](data/routes.json) is the shared source for dashboard explanations: client mode, plaintext holders, reference authority, blockers and next verification step. It separates NEAR gateway/E2EE/direct paths, ACI hostnames, Tinfoil, Venice clients, Chutes modes, and candidate routes for Private Inference, Maple, Privatemode and Confidential AI. Candidate and publication-only rows are not live confidentiality verdicts.

## What runs

- **Daily observations:** immutable run and attempt records, adapter evidence, full identity values and typed outcomes. Same-day reruns preserve earlier evidence; partial-provider runs retain other routes with their old timestamps.
- **Reference publications:** bounded captures of Maple PCR histories and SDK policies, Privatemode's manifest, Confidential AI's allowlist/release metadata, and Private Inference's catalog/browser entrypoint. Mirror equality is a publication fact, not a hardware verification result.
- **Weekly discovery:** catalogs recorded separately from stable sentinel probes. Newly discovered or missing model IDs produce review work rather than silently changing the sample.
- **Continuity events:** new/revisited identities, rejected evidence, policy disagreement, missing evidence and instrument changes, with exact old/new observation references.
- **Review jobs:** immutable packets, leases, retry budgets, validated drafts, independent dispositions and explicit publication. A successful agent launch never counts as a completed audit.

## Verification scope

The adapters report individual checks, evidence and missing links. `not_checked` means the complete proof has not been established; `rejected` means a check actually failed; `unavailable` means the required evidence could not be obtained. Historical `valid` booleans remain legacy adapter results.

The October implementation repairs ACI detached quote/event bindings and NEAR cross-model anchor matching. It explicitly leaves ACI expected boot-register comparison, NEAR compose-manager/request closure, and Tinfoil AMD signature-chain verification unproven. Those adapters cannot claim complete verification on the strength of partial checks. New provider publications do not close these gaps.

[NEAR route explanation](providers/near-ai.md) · [Maple](providers/maple.md) · [Private Inference](providers/privateinference.md) · [Privatemode](providers/privatemode.md) · [Confidential AI](providers/confidential-ai.md)

## Run locally

```bash
uv sync --frozen --extra nearai --extra dev
source .venv/bin/activate
# Fetch the exact upstream verifier commit in data/instrument.json into
# _nearai-verifier, then set NEARAI_VERIFIER_PATH to its py/ directory.
python -m probes.collect
python -m probes.references
python -m probes.quality --write
python -m probes.render
python -m pytest
```

Existing environments can be reused without reinstalling. Never print API keys or include them in evidence. New observations go to `data/observations/`; reference bodies to `data/references/`; events to `data/continuity/events/` and `data/references/events/`. Raw request prompts are not collected. `data/latest.json` is a derived view; daily snapshots remain a compatibility/history format.

`python -m probes.references --catalogs` refreshes discovery. `python -m probes.collect --backfill` explicitly imports historical snapshots as legacy evidence. Queue commands and rollout checks are in [REVIEW-WORKFLOW.md](docs/REVIEW-WORKFLOW.md); private lease state stays under ignored `local-data/`.

## Contributing

Start with a client/request-path inventory and an evidence boundary, then implement reference capture or verification with meaningful negative controls. New discovery candidates do not need a completed audit; a route labeled verified does. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [implementation acceptance checklist](tasks/reference-observatory.md).

Pricing remains a secondary, separately invoked probe. The observatory does not infer deployment frequency or fleet size from daily samples, and it does not turn a zero error bucket into a provider-security confidence bound.

Code: MIT. Prose, observations and provider analysis: CC-BY 4.0.
