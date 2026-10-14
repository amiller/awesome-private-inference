# Private Inference Beat

**Compare private inference routes and explore the reference values behind them.**

For a particular client, model and request path: **who can read protected data,
what evidence limits that access, and who can change the software the client
accepts?** We retain observations, audit what they cover, and critically test the
verifiers and policies that interpret them. Each conclusion should be traceable
to dated evidence that another person or agent can check.

The useful result is a shared evidence trail for users, client developers and
auditors: conflicting reference publications, a verifier's missing binding,
changes to plaintext access, or a route whose evidence has gone stale. Review
work should resolve those questions or state the missing proof precisely.

The website has two views:

| Resource | What you can find |
| --- | --- |
| [Comparison](https://amiller.github.io/awesome-private-inference/) | What the client verifies, who can access plaintext, and who can approve software changes. Expand each provider into its request paths and follow each assessment to its evidence. |
| [Reference values](https://amiller.github.io/awesome-private-inference/history.html) | Captured measurements, image/compose digests, published reference sets and policy documents. Inspect full values, changes, dates and review evidence. |

The comparison publishes dated, preliminary assessments. [Proposed stage criteria](https://amiller.github.io/awesome-private-inference/stages.html) explain what stronger assurance would require; no stages are awarded.

The repository remains **awesome-private-inference**. Its [verifier directory](data/verifiers.json) records the implementations behind the reference process, their checks, delegated trust and missing proof. This is maintained in Git alongside the verifier routines, evidence and review records.

**Observed, provider-authorized, reviewed and accepted by a client are independent facts.** A newly observed value creates review work; it never silently expands a client allowlist. An assessment applies to a named client mode and request path, rather than a whole provider brand.

[Verifier directory data](data/verifiers.json) · [Route inventory](data/routes.json) · [Review workflow](docs/REVIEW-WORKFLOW.md) · [Shared verification contract](specifications/shared-verification.md)

Start with the [repository guide](docs/REPOSITORY-GUIDE.md) to locate authoritative
inputs, follow a claim to evidence, run independent checks and choose useful
follow-up work. [AGENTS.md](AGENTS.md) gives agents the working rules;
[CONTRIBUTING.md](CONTRIBUTING.md) describes route and verifier contributions.

The reference history page shows exact old/new values and scoped review evidence. First seen is not deployment time. Document changes do not measure deployed code size or security risk. This is an observatory backed by retained evidence, without certificate-transparency-style append-only or consistency guarantees.

Abalone and multi-provider gateways could share the verifier routines and versioned reference records while applying their own explicit acceptance policies. The [consumption contract](specifications/shared-verification.md) documents the existing adapter interfaces, machine-readable exports and an unknown-value example. These integrations are not implemented here yet.

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

Use an existing Python environment to inspect and validate the retained evidence:

```bash
python -m pytest
python -m probes.render
git diff --check
```

Rendering regenerates the website and reference export without contacting
providers. The [repository guide](docs/REPOSITORY-GUIDE.md#validation-and-observation-commands)
separates environment setup, browser checks, live collection and health checks.
Collection health measures whether the observer obtained evidence; it is not a
confidentiality verdict. Queue commands and rollout checks are in
[REVIEW-WORKFLOW.md](docs/REVIEW-WORKFLOW.md); private lease state stays under
ignored `local-data/`. Never include API keys or private prompts in evidence.

## Contributing

Start with a client/request-path inventory and an evidence boundary, then implement reference capture or verification with meaningful negative controls. New discovery candidates do not need a completed audit; a route labeled verified does. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [implementation acceptance checklist](tasks/reference-observatory.md).

Pricing remains a secondary, separately invoked probe. The observatory does not infer deployment frequency or fleet size from daily samples, and it does not turn a zero error bucket into a provider-security confidence bound.

Code: MIT. Prose, observations and provider analysis: CC-BY 4.0.
