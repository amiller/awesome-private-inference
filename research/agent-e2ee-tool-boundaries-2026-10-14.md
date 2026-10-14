# Agent E2EE tool boundaries

Source review on 2026-10-14. Tracking: [research #23](https://github.com/amiller/awesome-private-inference/issues/23), [Abalone #73](https://github.com/amiller/abalone/issues/73).

Encrypted inference requires an authenticated enclave key and approved code. An agent additionally needs confidentiality of every sensitive protocol field, authenticity of executable responses, and a policy for data intentionally disclosed by tools. These properties need separate evidence.

## Field and execution matrix

| Path | Sensitive fields | Execution and disclosure | Evidence limit |
| --- | --- | --- | --- |
| NEAR inference-proxy efd600a4; verifier example 94554726 | Ordinary tool fields opt in; built-in encrypted search forces expanded response encryption | Search loop runs in CVM; configured search destination receives query | Pinned source; no deployment binding or fleet-wide qualification |
| Abalone current encrypted-text integration | Definitions, requests and results carried inside encrypted message text; native definitions stripped, native history refused | Tools execute locally under selected host/sandbox profile | Inspected hosted main 7c1d9fa; coupon route rejects native responses, ordinary decoder needs explicit review |
| Older hermes-tee-providers transport inspected locally | Encrypts message content; sibling tool schemas and call arguments remain untouched | Depends on callers and provider route | Source-level gap; active deployment/reachability not established |

NEAR source: [encrypted_agent_loop_verifier.py at 94554726](https://github.com/nearai/nearai-cloud-verifier/blob/94554726fd548676842b7ea603a8173a60c31341/py/encrypted_agent_loop_verifier.py), [field encryption at efd600a4](https://github.com/nearai/inference-proxy/blob/efd600a46c4327c8d8d038ab8b01c25a0e74b5bd/src/encryption.rs), and [chat dispatch at that revision](https://github.com/nearai/inference-proxy/blob/efd600a46c4327c8d8d038ab8b01c25a0e74b5bd/src/routes/chat.rs). Its key-fetch function reads a key from an attestation report without itself verifying the quote. A successful decrypting demo alone therefore does not establish verified key binding, approved enclave code or response authenticity. Field encryption also leaves protocol metadata visible.

Abalone source: [near-provider](https://github.com/amiller/abalone/blob/7c1d9fa/agents/pi/near-provider.ts), [encrypted-text tools](https://github.com/amiller/abalone/blob/7c1d9fa/lib/intools.mjs), [coupon adapter](https://github.com/amiller/abalone/blob/7c1d9fa/lib/coupon-near.mjs). Its custom parser has a separately tracked reliability problem in [#56](https://github.com/amiller/abalone/issues/56). Existing mitigation must remain until native encrypted tools are qualified.

## Source qualification and client follow-up

The expanded-field switch is independent from encryption version 2 and is available
with ECDSA. Extended request decryption is permissive: plaintext tool names/descriptions
and parameter objects can pass through. A successful server response with the header
therefore does not prove that the client encrypted every sensitive field before sending.
Deprecated top-level functions definitions are not traversed by the inspected tools
transformer. Treat the field list as bounded coverage, not arbitrary-JSON confidentiality.

The built-in web search dispatcher forces expanded response encryption whenever E2EE
is active; ordinary tool calls still opt in. The search URL is configuration, so this
source review does not bind the deployed destination or establish its TLS/egress policy.

A [DevProof supplement in PR #5](https://github.com/amiller/devproof-audits-guide/pull/5)
records the pinned-source findings without revising the historical inference verdict.
[Abalone PR #74](https://github.com/amiller/abalone/pull/74) proposes shared request/reply
guards, including legacy function fields and alternate SSE spacing, while preserving
its encrypted-text tools. [Hermes issue #2](https://github.com/amiller/hermes-tee-providers/issues/2)
and [PR #3](https://github.com/amiller/hermes-tee-providers/pull/3) track a text-only,
fail-closed guard for the feature-branch plugin. These are proposed code changes,
not deployed mitigations. No active Hermes installation was found in the locations checked.

## Why content-only encryption fails for agents

An encrypted confidential prompt can produce an unencrypted structured search query or command that reproduces its secrets. A gateway terminating ordinary HTTPS can read those fields even when it cannot decrypt message content. This is a confidentiality gap at the protocol boundary, not necessarily a failure of enclave hardware or the encryption primitive.

Even complete field encryption does not conceal tool inputs from their ultimate recipient. Sending a search query to Brave discloses that query to Brave. Running a local filesystem tool instead places its plaintext on the trusted client. Attestation of inference does not establish either tool-egress policy or local host security.

## Audit and qualification work

The historical NEAR DevProof inference/private-chat reports did not explicitly assess this tool-field gap; the proposed supplement above adds it. [Confer's report](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/confer/DEVPROOF-REPORT.md) discusses observable tool-mediated exfiltration. Add an explicit protocol coverage section rather than inferring agent privacy from the existing inference verdict.

1. Capture upstream source revisions, field coverage and model/version capability; separate documented behavior from observed deployments.
2. Use synthetic wire canaries for definitions, history, streamed arguments, reasoning and results; require refusal of plaintext/malformed fields and unsupported fallback.
3. Verify the key before encrypting and establish response authenticity before tool execution. Encryption-to-client alone is not proof of sender identity.
4. Trace older Hermes callers to determine reachability and add fail-closed guards or full field coverage before native tools are admitted.
5. Qualify consecutive native-tool rounds only with an explicit live model/version and spend budget. Keep source, synthetic and live evidence distinct.

No live requests, real transcripts or provider changes were made for this source review. The registry's existing inference score is not changed by this note.
