# Audits and reviews of private-inference software

Public security reviews of the software behind private-inference routes, with the
version and scope each covered and what later happened inside that scope. An entry
records the review; it does not grade it. Compiled 2026-11-27; additions welcome.

## Firm audits

| Auditor | Date | Scope | Later inside that scope | Link |
|---|---|---|---|---|
| zkSecurity, for Phala | 2025-05-26 to 06-13 | dstack `be9d0476` (about v0.5.1): ra-tls/ra-rpc, guest-agent, dstack-util, OS image recipes. KMS, dstack-gateway, VMM and dcap-qvl out of scope; KMS and dcap-qvl recommended for follow-up | Finding #08 covered host-side container log exposure. The guest-agent `/logs/<container>` flaw exploited in October 2026 (affected v0.3.1–v0.6.0) is in the audited component and is not in the report. No errata published | [report](https://reports.zksecurity.xyz/reports/phala-dstack/) |
| Bluethroat Labs | reported 2026-01-06 | dcap-qvl: missing QE Identity verification, CVE-2026-22696 (critical, fixed in 0.3.9); "Finding 1 of 6" of a dstack ecosystem assessment | The other five findings are unpublished | [write-up](https://bluethroatlabs.com/reveries/cve-2026-22696-fetching-collateral-is-not-enough), [advisory](https://github.com/Phala-Network/dcap-qvl/security/advisories/GHSA-796p-j2gh-9m2q) |
| Google Project Zero / Cloud Security | 2023-04 | Intel TDX 1.0 | — | [report](https://projectzero.google/2023/04/technical-report-into-intel-tdx.html) |
| Google Cloud Security with Intel | 2025 | Intel TDX Module 1.5 | — | [report](https://services.google.com/fh/files/misc/intel_tdx_1.5-full_report.pdf) |
| Google Project Zero / Cloud Security | 2022-05 | AMD SEV-SNP on EPYC Milan | — | [report](https://projectzero.google/2022/05/release-of-technical-report-into-amd.html) |
| NCC Group | 2023 | AWS Nitro System API security claims | — | [report](https://www.nccgroup.com/research/public-report-aws-nitro-system-api-security-claims/) |
| Trail of Bits | 2025-08 | Meta WhatsApp Private Processing (SEV-SNP + NVIDIA CC); none of the providers below | — | [report](https://github.com/trailofbits/publications/blob/master/reviews/2025-08-meta-whatsapp-privateprocessing-securityreview.pdf) |

No public firm audit was found for NEAR AI's cloud-api or inference-proxy, Phala's
private-ai-gateway, Venice's API, Tinfoil, Chutes, Maple/OpenSecret, Edgeless
Privatemode, confidential.ai, the NVIDIA confidential-computing stack, SGLang or vLLM.

## Provider disclosures

| Source | Date | What | Link |
|---|---|---|---|
| dstack public security reports | 2026-03 onward | tracked reports on KMS, gateway and guest-agent (issues #549–#568, #605–#619) | [docs/security/public-security-reports.md](https://github.com/Dstack-TEE/dstack) |
| Phala | 2026-10-19 | guest-agent post-mortem | [post](https://phala.com/posts/2026-10-post-mortem-dstack-guest-agent-vulnerability) |
| NEAR AI | 2026-11-09 | SGLang incident report | [post](https://near.ai/blog/security-incident-report-sglang-vulnerability) |
| Phala | 2026-11-23 | detailed incident report (supersedes 11-10) | [post](https://phala.com/posts/phala-november-detailed-incident-report) |

Compliance attestations are not code reviews: Phala SOC 2 Type I
([report](https://phala.com/phala_soc2_type1_report.pdf)), Tinfoil SOC 2 and HIPAA
seals ([site](https://www.tinfoil.sh)). Maple's [proof page](https://maple.ai/proof)
answers the audit question "Not yet".

## Volunteer, vendor and independent reviews

| Reviewer | Kind | Date | Scope | Later | Link |
|---|---|---|---|---|---|
| teemoon | client-app vendor, per-image reviews | 2026-07 onward | NEAR images by digest (vllm-proxy-rs, sglang, vllm, compose-manager); question: where can plaintext go | Recorded the unauthenticated engine routes and the missing proxy path allowlist before the SGLang incident; missed the deserialization route and the OHTTP request forgery, and says so on its incident page | [repo](https://github.com/teemoonai/audits), [incident page](https://github.com/teemoonai/audits/blob/main/incidents/2026-11-06-nearai-sglang.md) |
| Andrew Miller, DevProof case studies | volunteer | 2026-04 onward | Venice, Tinfoil, Phala verifier, NEAR AI, Chutes, RedPill, Darkbloom | Venice report (2026-04-24) found the agent skills taught no attestation checks (fixed 2026-09-30) and concluded the E2EE path was not a re-encryption backdoor, which KTibow's finding overturned | [devproof-audits-guide](https://github.com/amiller/devproof-audits-guide) |
| Juraj Bednar | self-published, automated (Qwen) | 2026-08-06 | venice-e2ee-proxy, venice-e2ee, Venice/Phala stack | Found nothing breaking E2EE confidentiality; corrected 2026-11-27 for the unbound reply key | [audit](https://github.com/jooray/venice-e2ee-proxy/blob/main/docs/SECURITY-AUDIT.md), [correction](https://github.com/jooray/venice-e2ee-proxy/issues/7) |
| teep | verifier maintainers' gap analysis | ongoing | per-provider attestation gaps | Recorded that E2EE v2 responses can be forged by a relay; described the content as confidential against it | [attestation_gaps](https://github.com/13rac1/teep/tree/main/docs/attestation_gaps) |
| KTibow | independent researcher; discloses an OpenRouter grant | 2026-09 onward | provider routing ("wrapper" posts: CrofAI, Venice, Phala, GMI Cloud, Ark) and Venice's E2EE | Phala proposed E2EE v2.1 and NEAR proposed retiring v1/v2 within two days of the Venice post | [blog](https://kendell.dev/), [E2EE write-up](https://kendell.dev/_astro/_e2ee-interception.3SX09GMt.md) |
| David Gobaud | AI-agent audits | 2026-11-26 | Venice, Phala, NEAR AI, Maple, Orbio, TrustedRouter, Dot, Phala PR #657; scored against Tinfoil | Evidence links point at local files; method disputed by Phala's co-founder | [gists](https://gist.github.com/dgobaud) |
| This repository | observatory reviews | 2026-08 onward | dated version ledgers and route assessments | — | [data/audits](../data/audits), [data/audit-synthesis.json](../data/audit-synthesis.json) |
