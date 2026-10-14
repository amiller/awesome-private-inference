# Agent E2EE tool boundaries

Source review on 2026-10-14. Tracking: [research #23](https://github.com/amiller/awesome-private-inference/issues/23), [Abalone #73](https://github.com/amiller/abalone/issues/73).

Encrypted inference requires an authenticated enclave key and approved code. An agent additionally needs confidentiality of every sensitive protocol field, authenticity of executable responses, and a policy for data intentionally disclosed by tools. These properties need separate evidence.

## Field and execution matrix

| Path | Sensitive fields | Execution and disclosure | Evidence limit |
| --- | --- | --- | --- |
| NEAR published v2 agent-loop example with X-Encrypt-All-Fields:true | Documents encrypted content, reasoning, tool names/arguments, definitions and search-result output | Search loop runs in CVM; query sent directly to Brave over TLS | Source example; no fresh live test or fleet-wide qualification |
| Abalone current encrypted-text integration | Definitions, requests and results carried inside encrypted message text; native definitions stripped, native history refused | Tools execute locally under selected host/sandbox profile | Inspected hosted main 7c1d9fa; coupon route rejects native responses, ordinary decoder needs explicit review |
| Older hermes-tee-providers transport inspected locally | Encrypts message content; sibling tool schemas and call arguments remain untouched | Depends on callers and provider route | Source-level gap; active deployment/reachability not established |

NEAR source: [encrypted_agent_loop_verifier.py](https://github.com/nearai/nearai-cloud-verifier/blob/main/py/encrypted_agent_loop_verifier.py). Its key-fetch function reads a key from an attestation report without itself verifying the quote. A successful decrypting demo alone therefore does not establish verified key binding, approved enclave code or response authenticity. Field encryption also leaves protocol metadata visible.

Abalone source: [near-provider](https://github.com/amiller/abalone/blob/7c1d9fa/agents/pi/near-provider.ts), [encrypted-text tools](https://github.com/amiller/abalone/blob/7c1d9fa/lib/intools.mjs), [coupon adapter](https://github.com/amiller/abalone/blob/7c1d9fa/lib/coupon-near.mjs). Its custom parser has a separately tracked reliability problem in [#56](https://github.com/amiller/abalone/issues/56). Existing mitigation must remain until native encrypted tools are qualified.

## Why content-only encryption fails for agents

An encrypted confidential prompt can produce an unencrypted structured search query or command that reproduces its secrets. A gateway terminating ordinary HTTPS can read those fields even when it cannot decrypt message content. This is a confidentiality gap at the protocol boundary, not necessarily a failure of enclave hardware or the encryption primitive.

Even complete field encryption does not conceal tool inputs from their ultimate recipient. Sending a search query to Brave discloses that query to Brave. Running a local filesystem tool instead places its plaintext on the trusted client. Attestation of inference does not establish either tool-egress policy or local host security.

## Audit and qualification work

The locally inspected NEAR DevProof inference/private-chat reports do not explicitly assess this tool-field gap. [Confer's report](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/confer/DEVPROOF-REPORT.md) discusses observable tool-mediated exfiltration. Add an explicit protocol coverage section rather than inferring agent privacy from the existing inference verdict.

1. Capture upstream source revisions, field coverage and model/version capability; separate documented behavior from observed deployments.
2. Use synthetic wire canaries for definitions, history, streamed arguments, reasoning and results; require refusal of plaintext/malformed fields and unsupported fallback.
3. Verify the key before encrypting and establish response authenticity before tool execution. Encryption-to-client alone is not proof of sender identity.
4. Trace older Hermes callers to determine reachability and add fail-closed guards or full field coverage before native tools are admitted.
5. Qualify consecutive native-tool rounds only with an explicit live model/version and spend budget. Keep source, synthetic and live evidence distinct.

No live requests, real transcripts or provider changes were made for this source review. The registry's existing inference score is not changed by this note.
