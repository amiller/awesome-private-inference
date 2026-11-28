# E2EE formats: NEAR AI, Phala and Venice

How the field-level encryption formats used by NEAR AI, Phala's gateway and Venice
relate, and when each began binding the reply key. Checked 2026-11-27.

Common ancestor: NEAR's Python vllm-proxy field-level E2EE, headers `X-Signing-Algo`,
`X-Client-Pub-Key`, `X-Model-Pub-Key`, ECIES on secp256k1 (or ed25519/NaCl). The reply key
is a plain header in every member of this family until NEAR v3 / Phala v2.1.

| Date | Party | Event | Reply key bound? | Source |
|---|---|---|---|---|
| 2025-01-09 | NEAR + Phala | nearai/private-ml-sdk created; NEAR's 2025-01-19 post: "built by Phala Network in collaboration with NEAR AI" (Phala forks the repo 2025-02-14). Built jointly; no source found for joint funding | n/a | GitHub repo metadata; near.ai/blog/building-next-gen-near-ai-infrastructure-with-tees |
| 2025-12-23 | NEAR | Python vllm-proxy: "end-to-end encryption for chat completions" (the v1 family), resolving private-ml-sdk#41 (opened 2025-12-11); "The caller needs to specify custom HTTP headers: `X-Signing-Algo` and `X-Client-Pub-Key`." No blog post announced it | no | nearai/vllm-proxy #7, 61d04ec |
| 2026-03-05 | NEAR | Rust inference-proxy reimplements it; 2026-03-06 "Fix encryption compatibility with Python vllm-proxy" | no | nearai/inference-proxy b795e25, b07d8cf |
| 2026-03-11 | Venice | TEE/E2EE guide added; same scheme with headers renamed `X-Venice-TEE-*`, signing algo "Always `ecdsa`" | no | veniceai/api-docs b7b1e26 |
| 2026-03-12 | NEAR | v2: XChaCha20-Poly1305 (`x-encryption-version`) | no | inference-proxy 421e506 |
| 2026-04-13 | NEAR | `X-Encrypt-All-Fields`, with lenient decryption | no | inference-proxy c6ed8f0 |
| 2026-05-19 | Phala | private-ai-gateway first public commit already carries both the `X-Signing-Algo` "pre-ACI legacy" path and an `X-E2EE-Version` v2 | no (v2 binds model, field, nonce, timestamp) | private-ai-gateway e9e335d3 |
| 2026-07-08 | Phala | removes a "legacy pipe-AAD mode (LegacyV2)" variant | — | private-ai-gateway #79 |
| 2026-08-07 | Phala | #86 disables E2EE advertisement, drafts a whole-body design | — | private-ai-gateway #86 |
| 2026-08-10 | Phala | #127 restores v2 as a frozen compatibility protocol, supported through at least 2027-02-10, "while E2EE v3 is developed" | no | private-ai-gateway #127 |
| 2026-09-14 | NEAR | reply-key substitution reported | — | cloud-api #1061 |
| 2026-10-28 | NEAR | v3 binds the reply key (AAD includes it); v1/v2 still accepted | **yes** | cloud-api #1296, inference-proxy 53d5041 |
| 2026-11-25 | — | KTibow connects the legacy format to Venice | — | kendell.dev/blog/venicewrapper |
| 2026-11-26 | Venice | docs wording only; still documents legacy `ecdsa` | no | api-docs #937–939, 28d5757 |
| 2026-11-27 | Phala | v2.1 proposed: binds client key, MACs responses | **yes** (proposed) | private-ai-gateway #657 |
| 2026-11-27 | NEAR | proposal to retire v1/v2 (HTTP 400) | — | inference-proxy #394, cloud-api #1469 |

Naming collisions: NEAR "v2" (cipher change) and Phala "v2" (JCS-AAD field binding with
freshness) are unrelated protocols. Phala's "legacy" is the NEAR-v1 family. Phala's ACI/1
spec once referred to a "v3" under development (#127), distinct from NEAR's v3.
Unverified: whether Venice's server forwards NEAR v3 or Phala v2 headers.
