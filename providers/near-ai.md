# NEAR AI routes and reference policies

Scope reviewed 2026-10-14. NEAR has several request paths with different confidentiality boundaries. This page describes the paths and the registry's current checks; it does not give the provider a single privacy stage.

| Client path | Plaintext holders | References and required binding | Registry status |
| --- | --- | --- | --- |
| Gateway without application E2EE | Client, gateway TLS terminator, selected backend and inference code | Gateway image/config/TLS key, routing policy, backend workload/key | Partial attestation observations; actual request route is not proven |
| Gateway with verified application E2EE | Client and model environment for protected fields; gateway still sees unencrypted metadata/fields | Requested-model policy, workload/OS/config, fresh quote, model encryption key, selected route, response-key binding | Separate client protocol; registry does not perform the complete encrypted request |
| Direct model endpoint | Client and selected endpoint/model environment, conditional on channel proof | Direct endpoint key/session, expected workload, model mapping and freshness | Experimental upstream path; not covered by a gateway quote |

In the E2EE path the gateway may remain in the network route while being excluded from decryption of protected prompt fields. Tool-related fields require attention to the actual client encryption configuration. The [current E2EE documentation](https://docs.near.ai/cloud/guides/e2ee-chat-completions) specifies key selection and route pinning; [direct completions](https://docs.near.ai/cloud/experimental/direct-completions) have separate limitations.

## Prompt and reply guarantees differ

[Open issue 1061](https://github.com/nearai/cloud-api/issues/1061) describes an intermediary replacing the unauthenticated response-key header and receiving the model's reply. The registry has not reproduced this attack live. Until a fixed protocol and deployment are verified, do not describe an E2EE gateway as irrelevant to reply confidentiality. A later receipt check cannot undo disclosure.

## What this instrument checks

The daily adapter verifies available TDX/GPU and key/nonce evidence, recomputes available compose commitments, compares each requested model against its own anchor entry and records authorization queries against a numbered Base block with hash. Full digest matching is required for approval-ledger matches. It does not union reference hashes across unrelated models.

These checks do not complete the compose-manager action, measured model identity and encrypted request chain. Otherwise passing responses are therefore `not_checked` at the complete-proof level, with individual check outcomes preserved. A failed authenticated binding is a rejection. An RPC or attestation transport failure is an evidence availability problem, not a privacy verdict.

The older `near_ai_lightclient.py` is an incomplete prototype. It now reports its missing proof links and refuses an end-to-end success. It must not be used as evidence that a prompt was sent only to approved code.

## Reference changes to monitor

Track gateway image/config separately from model workload/OS/inner-compose references. Record requested model, app identity, policy revision, exact observed hash, on-chain query block and client-accepted set. A chain-authorized hash absent from a client's pinned policy is a disagreement to explain, not permission to silently refresh the client.

A model rename or absent attestation should create catalog/coverage review work. It must not erase the old observation or be called a cryptographic failure. The stable daily sample and broader discovery catalog have different purposes.

## Completion gate

For each supported client mode: pin its source/release, capture fresh evidence, authenticate every detached field through the quote/event/compose chain, establish the requested model and accepted workload, and bind the real request and reply keys. Negative controls must reject changed model/compose/key, stale evidence and route fallback before sensitive data leaves the intended boundary. Record field coverage, tool behavior and streaming semantics separately.

Historical findings and earlier assumptions remain in git history and the [October review](../research/review-2026-10-13/review.md). The current route inventory at [data/routes.json](../data/routes.json) drives the dashboard's path explanations.
