# Audit refresh roadmap — 2026-11-15

Base: `origin/main` @6f440f3 (the live dashboard). The laptop checkout is at 7a14405, ~370 commits behind, with uncommitted verifier edits; nothing here touches it. teep refs are 13rac1/teep @6548996. The previous gap map is `notes/our-gaps-and-teep-parity-2026-11-05.md`.

## 1. The Session column

The rubric question (`data/assessments/routes.json`, rendered at `assessments.html#rubric-session`) is "Are prompt recipient, reply key and freshness bound to the actual client exchange?"

Plainly: before your prompt leaves your machine, did you check that the key you are encrypting it to belongs to the attested enclave, that the reply comes back under a key the enclave controls (not one a relay swapped in), and that the attestation you checked is fresh for this request rather than replayed? A receipt you get after the prompt is already sent does not count.

Why it was hard to explain:
- It bundles four checks: channel binding (TLS key), recipient key, reply key, freshness (nonce/replay). A route can pass two and fail two, and the cell shows one word.
- Its 19 cells carry eight labels: "Our session test to do", "Our backend test to do", "Our session proof to do", "Reply key substitutable", "Proxy sees prompts", "No client attestation", and so on.
- 14 of the 19 cells are `limitation: evidence`, i.e. "we haven't run a test yet", not a statement about the provider. Only five are findings (NEAR E2EE reply-key substitution via cloud-api#1061, Private Inference ×3, Privatemode proxyless).
- "Session" means two other things in the same repo: ACI/1 "attested sessions" (`verifiers/aci.py`, `data/routes.json` "session evidence digest") and HTTP sessions in `probes/references.py`. teep's new `aci_session_verified` factor uses the ACI/1 sense.

Options (decision for you, no edit made):
- **Rename** to "Prompt encryption" or "Encrypted to the enclave", keep one cell.
- **Split** into "Recipient key" and "Reply key + freshness". The NEAR E2EE finding and the teep Phala receipt work both land on the second half, so the split would show real differences instead of "partial".

## 2. Why the page reads as a to-do list

Of ~190 cells on the live page, ~150 say "Our … to do"/"Our … missing" (`limitation: ours` or `evidence`). About 20 are findings about a provider. All 19 route assessments are dated 2026-10-14. Since then teep has merged 143 commits, and the page's own reference-history banner flags 5 changed ACI reference surfaces. So the gaps are mostly ours, and the provider findings are a month old.

The passes below are ordered so the earliest ones flip the most "ours" cells for the least new judgment.

## 3. Passes

### Pass 0 — Review and merge the Nov 5 GLM lanes (verifier work, `ours`)
Nine branches are still on zed in `/data/amiller/api-lanes/<lane>` (branch `glm/<lane>-20261105`, base ec09e8f), none reviewed. Diff sizes vs base: aci 830, chutes 7.2k, dstack 1.9k, gcpfw 14.8k, ledger 330, misc 4.2k, rubric 810, tinfoil 1.5k, venice 3.7k lines. Each finished in 0.1–0.3h of work, so read the verification code against the issue criteria, not just the tests. Merge order and checklist: `tasks/glm-issue-sweep-2026-11-05.md`.

| Lane | Issues | Cells it would move |
|---|---|---|
| tinfoil | #26, #18 | tinfoil-router Hardware ("Our AMD check missing") |
| chutes | #28, #7, #18, #19 boxes 1–2 | chutes-tee Hardware ("Our GPU/RTMR checks missing") |
| aci | #27, #18 | 3 ACI routes Hardware ("Our boot check missing") |
| dstack | #18 NEAR, teep parity | NEAR/Venice Hardware: TCB policy, debug bit, MRTD/RTMR0–2, event log |
| venice | teep parity | Venice ACI/1 format, NRAS signature + nonce |
| misc | — | stale catalog rows (NEAR gpt-oss-120b, GLM-5.1-FP8, Chutes Qwen3-32B); N/A vs not-checked render |
| ledger, rubric, gcpfw | #5, #3, #9, #33 | no route cells; registry hygiene and the firmware observatory |

Check before merging: teep changed what counts as a pass for NVIDIA evidence (815bdc0: `nvidia_signature` no longer passes EAT evidence whose signatures weren't verified; 647978b `nvidia_claims` fails on unverified evidence). Hold our chutes/venice NRAS code to the same bar.

### Pass 1 — Session retained tests, following teep (`evidence` → finding or pass)
teep now does per-request work that a daily probe can reproduce as a dated test. One test per route, retained with the capture:

| Route | Test | teep source |
|---|---|---|
| aci-gateway-phala (and the RedPill ACI routes) | E2EE v2 request; fetch the receipt; check ed25519 over JCS under the keyset, `body_hash` = sha256 of bytes received, request hash, model/endpoint match, `upstream.verified` names a pinned session | 7f44520, 3402d7b, `aci_receipt_verified` / `aci_session_verified` |
| aci (all) | keyset `not_after` present and in the future; record whether the keyset is REPORTDATA-bound (Phala canonical) or self-asserted (Venice, NanoGPT compatibility route) | b4d94f8, aci_gateway.md residual 7 |
| near-ai-direct | encrypted `/v1/completions` returns encrypted `choices[].text`; note `stop`/`user` are plaintext | eec3081, 74834db |
| near-ai-gateway-e2ee | re-test reply-key substitution (cloud-api#1061) against the current deployment; the gateway refuses encrypted completions | — |
| chutes-tee | full prompt+reply round trip; record that freshness rests on REPORTDATA = SHA256(nonce‖e2e_pubkey), since the evidence echoes no nonce | 6967376 |
| tinfoil-router | EHBP round trip; record that only the router is attested | — |
| all E2EE routes | a non-200 2xx and an endpoint outside E2EE coverage must not deliver plaintext | 3ceef76, 938bd26 |

Needs: provider API keys for Phala/RedPill (blocker on #30) and a decision on whether to run teep itself (see §4). Break #30 into one issue per route as each test lands; it currently backs ~60 cells.

### Pass 2 — Re-review against teep's new findings (dated provider findings)
Each item is a candidate cell change. Confirm against our own capture before writing it into `routes.json`.

| Finding (teep) | Our route / axis |
|---|---|
| A Phala Cloud stream reaches the client before its receipt exists; on a cut stream the receipt 404'd ~25 s and its `body_hash` matched no prefix received (aci_gateway.md residual 12, d7cbe07) | aci-gateway-phala / Session |
| E2EE v2 responses are confidential but not authenticated against a relay; only the receipt authenticates (residual 10) | aci routes / Session |
| Venice ACI/1 responses carry `gpu_evidence_omitted`, no NVIDIA payload, since 2026-11-12 (residual 11) | venice-phala / Hardware |
| The inference host behind the ACI gateway is unattested to the client (residual 1) | aci routes / Downstream |
| Gateway redeploys change measurements; KMS root and app id are trust-on-first-use (residuals 2, 4; a09043a) | aci routes / Updates |
| NEAR cloud serves one model from several instances sharing one signing key; the gateway picks (c1f253a) | near-ai-gateway-* / Downstream |
| NEAR attested model name differs from requested (glm-5.3-flash vs -long) (4ecddb6) | near-ai-* / Downstream |
| NEAR DeepSeek-V4.1 composes pin a manifest digest Rekor doesn't index; GLM pins the index and passes (near_image_provenance.md) | near-ai-* / Code |
| NEAR completions: every field but `prompt` is plaintext (74834db) | near-ai-direct / Session |
| Tinfoil enclave hosts didn't answer direct attestation; teep disabled `tinfoil_v3_direct` (e732070) | tinfoil (direct path) / scope note |

### Pass 3 — Downstream (21 "Our worker test to do")
The largest single label. Two automatable pieces: NEAR cloud instance enumeration (count, distinct `instance_id`, all signing keys equal, each id bound to an RTMR3 event, per teep c1f253a/da6cbcf), and for ACI, which backend served the request (only the receipt's `upstream.verified` names it). The rest are routes with no adapter (§4).

### Pass 4 — Operator access (17 "Our access review to do")
These need a structured source review, not a probe. teep's `docs/audit_prompts/{direct,gateway}_inference/` is a reusable shape: a fail-closed preamble, numbered stage files (routing, fetch, transport, TDX quote, measurements, event log, TLS binding, CVM image, policy/caching, NVIDIA, proof of cloud), four agents by file group, and every check classified as enforced fail-closed / computed but non-blocking / skipped. Adapt the stages to our six axes and run once per provider. teep's gap-doc template (`docs/attestation_gaps/TEMPLATE.md`: Problem, Impact, Background, Analysis, Remediation, Status) fits our provider findings.

### Pass 5 — Updates and allowlists
Our reference-history baselines and teep's measurement allowlists track the same values. teep lags NEAR's OS measurements (your teep #233) and the gateway MRTD 7fe60787… (96cc741). Publish our observed values in a form teep can pull, and record when each was first seen versus traced to a release. Also from teep: a provider can downgrade a dstack model to ACI/1 to get the weaker check list (residual 3); our Updates cell for Venice should say whether we pin format per model.

### Standing — keep teep parity current
The beat digest already reads teep daily (`watch/beat/2026-11-*.md`). Add one step: when a digest reports a teep factor or gap-doc change, append a row to the parity table and open or update the matching issue. The Nov 5 table is stale on: ACI/1 (Venice "✗ no ACI/1" is now handled by teep for Venice, Phala Cloud, NanoGPT), NVIDIA signature semantics, and per-instance NEAR cloud checks.

## 4. Decisions for you

1. **Session column**: rename or split (§1).
2. **Routes with no adapter**: Maple ×2, Privatemode ×3, Private Inference ×3, Confidential AI produce most of the all-"unknown" rows. Build adapters, or collapse them to one "not assessed" cell each so the page stops reading as a to-do list.
3. **Coverage teep has and we don't**: NanoGPT (ACI/1 and relayed Chutes evidence), Phala Cloud direct ACI/1 at `tee.redpill.ai`, neardirect. Add them as routes?
4. **Run teep as an instrument**: retained teep captures could serve as Session evidence for Pass 1. It is a Go build; where should it run (zed?).
5. **Pass 0 first?** It is review work on code that already exists, and it flips the most "ours" cells.
