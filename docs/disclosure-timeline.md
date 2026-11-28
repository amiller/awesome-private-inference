# Reports, responses and incidents

Generated from [data/disclosure-timeline.json](../data/disclosure-timeline.json) by `python tools/disclosure_timeline.py`. Reports of flaws in private-inference providers and clients, the responses to them, incidents, and protocol changes. A response points at the report it answers. Dates are UTC days. No entry rates a provider; each links the primary source.

## Reports and what followed

| Reported | By | About | Report | First response |
|---|---|---|---|---|
| 2026-04-24 | Andrew Miller | Venice | [DevProof audit: agent skills teach no attestation checks; concluded the gateway path was not a re-encryption backdoor (missed the reply key)](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/venice-private-inference/DEVPROOF-REPORT.md) | 2026-09-30 Venice: [Skills synced with the live API: protocol named, headers listed, attestation fetch added](https://github.com/veniceai/skills/commit/c02361f) |
| 2026-05-06 | Andrew Miller | NEAR AI | [Silent model substitution in the model catalog](https://github.com/nearai/cloud-api/issues/573) | 2026-05-11 NEAR AI: [Maintainer reply; closed 2026-06-09](https://github.com/nearai/cloud-api/issues/573) |
| 2026-08-03 | teemoon | NEAR AI | [Published review: SGLang engines run with no API key; /configure_logging unauthenticated (CRITICAL)](https://github.com/teemoonai/audits/tree/main/images/docker.io/nearaidev/sglang) | — |
| 2026-08-10 | Andrew Miller | Venice | [Report linked in a public thread tagging @VeniceAI](https://x.com/socrates1024/status/2086936800258388123) | — |
| 2026-09-14 | hanakannzashi | NEAR AI | [E2EE: the client response key is not authenticated in the request](https://github.com/nearai/cloud-api/issues/1061) | 2026-10-22 NEAR AI: [Proposal to bind the response public key to encrypted requests](https://github.com/nearai/inference-proxy/issues/312); 2026-10-28 NEAR AI: [E2EE v3 binds the reply key; v1/v2 still accepted](https://github.com/nearai/cloud-api/pull/1296) |
| 2026-11-15 | Austin-Williams | Venice | [Signed receipt hashes match neither the request nor the response bytes (Phala route)](https://github.com/veniceai/api-docs/issues/874) | no reply |
| 2026-11-15 | Andrew Miller | NEAR AI | [compose-manager's attested log does not establish what runs](https://github.com/nearai/compose-manager/issues/85) | no reply |
| 2026-11-25 | KTibow | Venice | [Venice's server can swap the unbound reply key, read replies and inject messages (with video, 26 Nov)](https://kendell.dev/blog/venicewrapper/) | 2026-11-26 Venice: [Documentation wording only (#937, #938, #939); format unchanged](https://github.com/veniceai/api-docs/pull/939); 2026-11-27 Phala: [E2EE v2.1 proposed: binds the client key, with a migration guide for APIs in front of the gateway](https://github.com/Dstack-TEE/private-ai-gateway/pull/657); 2026-11-27 NEAR AI: [Proposal to retire E2EE v1/v2 (HTTP 400)](https://github.com/nearai/inference-proxy/pull/394); 2026-11-27 Juraj Bednar: [venice-e2ee-proxy README: the reply key is not bound to the client](https://github.com/jooray/venice-e2ee-proxy/issues/7) |
| 2026-11-25 | KTibow | Phala | [Phala is a Chutes+ wrapper: most catalog models are served by other providers](https://kendell.dev/blog/phalawrapper/) | — |

## Incidents, launches, fixes and audits

| Date | Party | Kind | Event |
|---|---|---|---|
| 2025-05-26 to 2025-06-13 | zkSecurity | audit | [dstack audit at be9d0476 (guest-agent, ra-tls, dstack-util, image recipes); KMS, gateway, VMM and dcap-qvl out of scope](https://reports.zksecurity.xyz/reports/phala-dstack/) |
| 2025-12-23 | NEAR AI | launch | [Field-level E2EE in vllm-proxy; reply key sent as a plain X-Client-Pub-Key header](https://github.com/nearai/vllm-proxy/pull/7) |
| 2026-03-11 | Venice | launch | [TEE/E2EE guide: the same scheme with X-Venice-TEE-* headers, signing algo always ecdsa](https://github.com/veniceai/api-docs/commit/b7b1e26) |
| 2026-08-06 | Juraj Bednar | audit | [Automated (Qwen) audit of venice-e2ee-proxy and the Venice/Phala stack; found nothing breaking E2EE confidentiality](https://github.com/jooray/venice-e2ee-proxy/blob/main/docs/SECURITY-AUDIT.md) |
| 2026-10-08 to 2026-10-12 | Phala | incident | [dstack guest-agent /logs passed unvalidated container names to Docker; env vars of some apps read. Fixed in dstack v0.6.1/v0.5.12 on 10-13; post-mortem 10-19](https://phala.com/posts/2026-10-post-mortem-dstack-guest-agent-vulnerability) |
| 2026-10-21 to 2026-11-01 | Phala | incident | [DeepSeek V4 Flash 0731 machine (OpenRouter route) compromised; development OS image, attestation not checked by the gateway](https://phala.com/posts/phala-november-detailed-incident-report) |
| 2026-11-05 | Phala | incident | [Legacy KMS root key handed to an attacker-controlled replica; rotation does not revoke the copy](https://phala.com/posts/phala-november-detailed-incident-report) |
| 2026-11-06 | Phala | fix | [AI gateway moves to a new app on the on-chain KMS, not announced in advance](https://github.com/Dstack-TEE/private-ai-gateway/releases/tag/gateway-prod-2026-11-05) |
| 2026-11-06 to 2026-11-08 | NEAR AI | incident | [Unauthenticated SGLang /update_weights_from_tensor reached through the proxy's OHTTP SSRF; report 11-09](https://near.ai/blog/security-incident-report-sglang-vulnerability) |
| 2026-11-08 | NEAR AI | fix | [Proxy restricts OHTTP inner requests to inference routes](https://github.com/nearai/inference-proxy/commit/7924418) |
| 2026-11-09 | NEAR AI | fix | [Engine image v13: admin auth and credential redaction (names the attack chain)](https://github.com/nearai/cvm-compose-files/commit/ab7eeee) |
| 2026-11-10 | Phala | response | [Preliminary incident report; detailed report 11-23](https://phala.com/posts/phala-november-preliminary-incident-report) |
| 2026-11-26 | David Gobaud | audit | [AI-agent audits of Venice, Phala, NEAR AI and others, scored against Tinfoil](https://gist.github.com/dgobaud/ecfbff2a9a14d4ad43062845bc0beee7) |
