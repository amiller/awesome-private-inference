# Private inference reference value consistency review

Prepared for Andrew on 2026-10-13 America/Detroit. Research continued into 2026-10-14 UTC.

**Recommendation: make this a public observatory of the reference values that confidential inference clients accept, the workloads actually observed, and the evidence connecting the two.** Use devproof audits to establish what each value covers and who can change it. Use Sol for bounded reviews of new identities, policies and request paths. The primary product should be an understandable, reproducible history of changes and unresolved inconsistencies.

The project has valuable accumulated evidence and several substantive investigations. Its weakness is the absence of a common unit of analysis. Provider, model, gateway, client, release, measured workload and audit finding are repeatedly treated as interchangeable. More sweeps and more general audit prompts will reproduce this confusion unless the data model changes first.

This review covers current upstream commit [`cbf555f661e81c838ba8daa3f7bb131691d5dbae`](https://github.com/amiller/awesome-private-inference/tree/cbf555f661e81c838ba8daa3f7bb131691d5dbae), the local implementation and research notes, current primary web sources, and three Sol research assignments. The local worktree was dirty and substantially behind upstream; its existing edits were preserved. Main findings below refer to upstream unless explicitly labeled otherwise.

Supporting material:

- [Private Inference preliminary audit](privateinference.md)
- [Maple preliminary audit](maple.md)
- [Provider landscape and scoped Privatemode and Confidential AI audits](landscape.md)
- [Captured upstream metrics and observation summary](baseline.json)
- [Offline ACI binding counterexample](check_aci_binding.py) and [result](aci-binding-result.json)
- [Upstream test result](upstream-tests.txt)

## The question the project should answer

For a particular client, model and request path: **what software and policy can receive the user's plaintext, which reference values authorize it, how have those values changed, and does the evidence observed today satisfy the policy the user intended?**

Change frequency is one useful result, but it needs four related dimensions:

| Dimension | Question | Example |
| --- | --- | --- |
| Continuity | What changed over time? | A new compose digest, newly accepted PCR, removed release, or retired model |
| Agreement | Do independent views agree? | Maple's SDK roots, canonical history and compatibility mirror |
| Binding and coverage | What does the value actually identify? | Chutes MRTD can identify a base image without covering the serving application |
| Authority | Who may admit or retire values, and how does the client learn that? | Provider-signed update, client-pinned manifest, on-chain allowlist, or automatic adoption of latest |

A quiet digest can coexist with changeable unmeasured code. A frequently changing digest can represent well-reviewed, reproducible maintenance. An on-chain authorization can be a malicious or mistaken update by an authorized key. The observatory should expose these distinctions without awarding points for immobility.

The central comparison has three sets: **published by the provider**, **accepted by a particular client policy**, and **observed in a particular request path**. Record all three with time and provenance. They need not be equal: a rollout can legitimately serve two releases, a strict client can intentionally accept a subset, and a retired release may remain in old clients. Explain each difference against a declared rollout and retirement policy.

Devproof remains essential. Its narrow job is to determine whether a reference value constrains the people who operate the service. It establishes the boundary for subsequent monitoring. General vulnerability hunting, model quality experiments, and pricing comparisons should have separate work queues and should not determine this observatory's headline.

## What works and should be retained

The repository already has provider adapters, daily collection, historical snapshots, a static renderer, audit ledgers, required-check declarations, and a watcher capable of launching review work. Recent changes correctly replaced the obsolete RedPill endpoint with hostname-specific ACI rows and replaced NEAR's stale historical authorization sweep with live checks of served compose hashes. The latest Chutes page records a manually found unpublished measurement and differences between streaming and non-streaming behavior. These are useful foundations.

The August [critical review](../critical-review-2026-08-10.md) and [observation-log proposal](../observation-log.md) already identify much of the desired direction. Some of that work shipped: the dashboard has quality information and a trajectory table, and audit debt now spans three providers. The remaining problem is not that nobody articulated the direction; the implementation and editorial rules still allow stronger claims than the evidence supports.

The scope should preserve historical failures when integrations retire. Upstream already does this for legacy RedPill. Keep that principle when splitting providers into routes or retiring obsolete model names.

## Current evidence and its limits

The checked-in October 13 snapshot was generated at 19:51:26 UTC. GitHub's corresponding [probe run succeeded](https://github.com/amiller/awesome-private-inference/actions/runs/38458139841). This does not establish that the independent zed watcher completed its audit work; its process state and logs were not inspected.

| Baseline from current upstream | Value | Interpretation |
| --- | --- | --- |
| Stored daily snapshot dates | 171 across 176 calendar dates | Missing April 28 and October 8–11; a missing file does not by itself identify the cause |
| Historical rows | 3,406 | Provider/model observations, not independent experimental trials |
| Rows classified as pass | 2,359 | Adapter-specific validity; not a common confidentiality guarantee |
| Transport-classified rows | 818 | Includes broad regex classes such as HTTP 4xx, which can actually mean a retired model or missing permission |
| Invalid rows with no error | 229 | Includes genuine failed checks and historical appraisal-service ambiguity |
| Explicit verification-failure bucket | 0 | Does not imply zero cryptographic or policy failures |
| Current rows | 17 over five adapter IDs | Includes three ACI hostnames sharing a workload; not 17 independent systems |
| Current classifications | 2 verified, 9 partial, 2 invalid, 4 unreachable | Labels come from the current checks and inherit their limitations |
| Ledger coverage | 7 of 88 observed identities | 81 unmatched identities: NEAR 25, Tinfoil 56, Chutes 0 |
| Latest ledger review date | September 2 | 41 days before the October 13 snapshot |

These are the generated report's numbers, preserved in [baseline.json](baseline.json). The 88 identities are heterogeneous: gateway image digests, Tinfoil bundle digests, and Chutes MRTDs. They are not 88 equally important audits. Tinfoil's historical model releases are also compared against a router-only ledger. Prioritize active, plaintext-relevant identities before spending time clearing historical counts.

Today's NEAR `openai/gpt-oss-120b` row gets HTTP 400 for an invalid model name. Two Venice entries have no attestation at the selected endpoint. The other NEAR row has a chain-authorized model compose that is absent from the current Hermes anchor comparison. These are three different events: catalog drift, evidence unavailability, and reference-policy divergence. They deserve distinct explanations and workflows.

## Why daily sweeps miss important information

**The catalog is a manually maintained sample.** `probes/catalog.py` contains two NEAR models, six Chutes models, five Venice models, one Tinfoil router and three ACI hostnames. It does not discover new routes or systematically track removed models. Upstream's October 12 Chutes investigation reports fourteen confidential-compute models and an unpublished-MRTD instance; the daily adapter still samples a narrower set. Keep the stable sentinel sample for time series, but add an independently versioned discovery inventory and a rotating sample of the rest.

**Collection preserves one filename per day rather than one observation per attempt.** `probes/collect.py` writes `YYYY-MM-DD.json` and replaces `latest.json`. A same-day rerun can replace earlier evidence; a `--providers near-ai` investigation can make the latest file look like a one-provider registry. Git may retain committed older versions, but the collectors and analytical readers do not make this an append-only event stream. Assign a run ID and observation ID, persist attempts immutably, and derive the latest complete view.

**The watcher treats scheduling as completion.** It acknowledges after `paseo run --detach` succeeds. It does not require a valid draft, evidence, completed tests or an analyst disposition. A crashed or stalled worker can consume an alert permanently. Acknowledgment also recomputes current values instead of acknowledging exactly the dispatched event batch. New observations arriving meanwhile can be acknowledged without being in that job's input.

**Important changes have no generic detector.** `diffalert.py` knows NEAR gateway digests, Tinfoil digests and unaudited Chutes MRTDs. ACI compose, keyset and source changes have no equivalent identity-change event. If their booleans stay the same, the sweep can miss them. There is also no systematic monitor of SDK policy changes, accepted-reference removals, browser bundle changes, security advisories, issue resolutions, or upstream route changes.

**Unknown and absent states are not represented reliably.** A missing model or evidence entry can disappear without an explicit retirement event. NEAR anchor drift is a set across observed models: a hash disappearing due to collection failure can be described as no longer served unanchored. Several identity checks occur only while `valid` is true, which can hide the changed inputs that caused rejection. Preserve rejected observations separately from trusted facts, and represent missing, error, retired and recovered states explicitly.

**Freshness is too coarse.** A fresh `latest.json` does not imply fresh evidence for every component. A provider can have a fresh HTTP failure while its last authenticated quote is weeks old. Track last attempt, last successful capture, last cryptographic verification, last policy review, and last completed triage independently. An external heartbeat should detect failures in the watcher itself.

**The review instruction can understate security changes.** The current Tinfoil playbook calls build/dependency-only changes mundane. Dependencies, Dockerfiles, build workflows and base images can all alter a plaintext-reading process or its trust roots. Classify by impact on the trust boundary and uncertainty, not filename alone. The watcher also requires `./run-audit.sh`, which is absent from the reviewed repository; a host-local script may exist, but the declared workflow is not reproducible from this checkout.

Source: [collector](https://github.com/amiller/awesome-private-inference/blob/cbf555f661e81c838ba8daa3f7bb131691d5dbae/probes/collect.py), [catalog](https://github.com/amiller/awesome-private-inference/blob/cbf555f661e81c838ba8daa3f7bb131691d5dbae/probes/catalog.py), [detector](https://github.com/amiller/awesome-private-inference/blob/cbf555f661e81c838ba8daa3f7bb131691d5dbae/probes/diffalert.py), [watcher](https://github.com/amiller/awesome-private-inference/blob/cbf555f661e81c838ba8daa3f7bb131691d5dbae/watch/devproof-watch.sh).

## Verifier and methodology issues that precede expansion

### ACI checks detached fields without establishing all quote bindings

The ACI adapter calculates a statement from the fresh nonce and served keyset, then compares its hash with `attestation.report_data`. It separately appraises the quote, but never compares the statement with the authenticated quote body's report data. The [offline counterexample](aci-binding-result.json) supplies a quote appraisal body with different report data and still obtains `valid=true`, `nonce_bound=true`, and `report_data_binds_key=true`. This establishes a registry acceptance defect under mocked appraisal, not a live provider compromise.

A related source-level issue affects the compose chain: RTMR3 replay uses event `digest` values, while compose matching separately uses `event_payload`. The adapter does not recompute the event digest from the payload under the event format. Preserving the digest sequence while changing the detached payload can therefore sever the intended relationship. `vm_config.os_image_hash` likewise needs an authenticated connection to the quote before an archive lookup proves which OS ran. Review these links together, then add negative tests that alter each side independently.

The same adapter names the presence of session evidence digests `backend_attested`, without actually verifying those session bundles, and treats a nonempty model catalog as `catalog_serves`. Rename these to the facts tested. This project's two currently fully verified rows are ACI hostnames, so correcting these checks is a launch prerequisite for a stronger observatory claim. [ACI source](https://github.com/amiller/awesome-private-inference/blob/cbf555f661e81c838ba8daa3f7bb131691d5dbae/verifiers/aci.py).

### NEAR reference membership is weaker than the prose suggests

The daily adapter unions compose hashes across every model in the Hermes anchor. Membership means that some model's anchor includes the hash; it does not establish that the requested model accepts that hash. Preserve `(model, app, component, hash, policy revision)` relationships. Live `eth_call` checks use `latest` without recording the block, so later replay cannot reconstruct the exact authorization state. Capture chain ID, contract, implementation where relevant, block number/hash and the policy query result.

The separate lightclient is not a complete client proving an encrypted request. It selects the first model report, compares detached compose-manager `report_data` with detached `actions_hash`, and does not itself recompute the action hash or verify a compose-manager quote authenticating that value. Its on-chain check also consumes `info.app_id` and `info.compose_hash` without establishing their quote binding in that function. It sends no encrypted completion. The claimed closure needs verification at each link, then a request test; a command printing “verified end-to-end” cannot stand in for that.

These are implementation findings, not a claim that every upstream NEAR SDK has the same defects. [Daily adapter](https://github.com/amiller/awesome-private-inference/blob/cbf555f661e81c838ba8daa3f7bb131691d5dbae/verifiers/near_ai.py), [lightclient](https://github.com/amiller/awesome-private-inference/blob/cbf555f661e81c838ba8daa3f7bb131691d5dbae/verifiers/near_ai_lightclient.py).

### Tinfoil source provenance is not hardware verification or an independent rebuild

The Tinfoil adapter explicitly leaves AMD VCEK-chain verification and an HPKE request outside its scope. It parses report fields and compares measurement/provenance statements, yet sets `code_measurement_reproducible=true`. Distinguish: attestation signature verified, release provenance verified, measurement agrees with release, build independently reproduced, and encryption/session binding tested. One field should not imply all five.

Direct model probing was removed after endpoints stopped being reachable. A router catalog-to-repository check is useful but cannot substitute for observing the worker serving the request. Expose that coverage loss. Avoid making per-request nonce support universally necessary where authenticated session freshness can provide an appropriate alternative; declare a freshness requirement and the protocol-specific evidence that satisfies it. [Tinfoil adapter](https://github.com/amiller/awesome-private-inference/blob/cbf555f661e81c838ba8daa3f7bb131691d5dbae/verifiers/tinfoil.py).

### The statistical interpretation needs tightening

The earlier research and trajectory code identify a first-observed value as a real deployment. That is too strong: it can be an existing fleet member first sampled today. A revisit can be load balancing, rollback, recovery or an observation artifact. A control-plane document can also revert, so zero revisits are not guaranteed by its being a document.

Report first and last observation windows and the observation process. Use “newly observed identity” until deployment evidence supports a stronger label. Avoid a corrected deployment-rate point estimate without explicit sampling/process assumptions and sensitivity analysis. Single daily samples do not identify fleet size or true rollout cadence.

The dashboard's rule-of-three confidence statement is particularly inappropriate here: observations share components, are correlated over time, and the zero bucket excludes invalid responses with missing reasons. Detector sensitivity is also uncalibrated. Use a labeled replay/mutation suite to measure detector performance; do not turn an error-string bucket into a provider security failure rate.

Finally, a provider's on-chain authorization is a policy authority, not automatically an independent reviewer. The observation-log proposal's “authorized means informational” rule would miss malicious authorized updates. And a signed hash chain only exposes rewriting to observers holding prior checkpoints; independent witnesses are required to expose split views. [Quality computation](https://github.com/amiller/awesome-private-inference/blob/cbf555f661e81c838ba8daa3f7bb131691d5dbae/probes/quality.py), [dashboard template](https://github.com/amiller/awesome-private-inference/blob/cbf555f661e81c838ba8daa3f7bb131691d5dbae/site/templates/index.html.j2).

## How to explain NEAR without mixing paths

Use a route card for each combination of client mode and protocol. Transport routing and confidentiality are distinct: application encryption can pass through a gateway while removing that gateway from the prompt decryption boundary.

| Path | Data flow | Main reference values | What the reader must understand |
| --- | --- | --- | --- |
| Gateway without application E2EE | Client → gateway TLS termination → selected inference backend | Gateway image/config, TLS binding, route policy, backend identity and key | Gateway is a plaintext holder; its verification and routing behavior matter |
| Gateway with verified application E2EE | Client encrypts selected fields → gateway relays ciphertext → model environment decrypts | Client acceptance policy, model mapping, workload/OS/config identity, key binding, encryption protocol | Gateway can remain a routing and availability dependency while being excluded from decryption of protected fields |
| Direct model endpoint | Client → selected model endpoint | Endpoint/session key, model identity, workload policy and freshness | Bypassing gateway routing does not automatically prove the direct channel; NEAR currently labels direct verification experimental |

The [current E2EE guide](https://docs.near.ai/cloud/guides/e2ee-chat-completions) describes verifying model candidates, selecting the attested key, pinning that key for routing and preventing aliasing. It also distinguishes default encrypted fields from additional tool-related fields. Thus a route card must state exactly which fields are protected. The [direct-endpoint documentation](https://docs.near.ai/cloud/experimental/direct-completions) needs its own support and limitation status.

There is also a current caveat the registry should surface: open [NEAR issue 1061](https://github.com/nearai/cloud-api/issues/1061), filed September 14, describes a relay substituting the response public-key header so that replies become readable to that relay. Private Inference documents the same limitation. This review did not reproduce it live. It means the proposed explanation must distinguish prompt confidentiality from reply confidentiality; it cannot say that the gateway is categorically irrelevant under E2EE. A signature checked after disclosure cannot undo that disclosure.

Every route card should start with the same five sentences: the selected client and endpoint; who receives plaintext; what the client checks before sending; who can change accepted software; and what today's evidence establishes. Follow with a small path diagram and exact evidence links. Move PR chronology into the history section. Keep availability, request integrity, prompt confidentiality, reply confidentiality and reference-policy agreement as separate results.

## Expansion priorities and what the Sol reviews established

The discovery pass found substantial missing coverage, but it does not establish a market denominator or justify “we cover X percent.” Count brands, independent stacks, protocol families and verified routes separately. Maple contributes valuable client/update-policy coverage even when its inference backends overlap existing providers.

| System | Evidence from this pass | Next bounded audit and completion condition |
| --- | --- | --- |
| Private Inference | Deployed browser code checks self-consistency without approved compose/OS baselines; private tier uses NEAR. Standard/ZDR paths have different plaintext holders. Public discovery worked; attestation required a key. | Audit only private beta first. Capture credentialed quote and exact browser build, test model and reference-policy mismatch rejection, demonstrate request/reply key binding. Standard/ZDR remain separate routes. |
| Maple | Current PCR0 agrees across source reference files, SDK roots and history; canonical and compatibility files match at one observation. Signatures cover PCR0 text, not a complete release/retirement statement. Tinfoil and Continuum/PrivateMode are distinct upstream paths. | Capture Nitro/session evidence for shipped clients, establish source-to-EIF provenance remotely, audit both upstream paths and history rollback behavior. Record mirror agreement independently from live deployment agreement. |
| Privatemode | Public manifest was retrieved; eight policies, SNP and TDX entries. Documentation distinguishes automatically refreshed manifests, explicitly pinned manifests and proxyless access. | Compare pinned and auto-update modes. Verify Coordinator, secret service and worker admission/key distribution. Require a changed manifest to produce the intended rejection or explicit update event. |
| Confidential AI | Public allowlist and nonce-echoing attestation response were retrieved; cryptographic proofs were not validated. Published threat model describes operator/control-plane access concerns. | Match signed release and live evidence; verify the actual TLS session and worker route. Resolve or explicitly retain operator-access exclusions before a devproof verdict. |
| Confer | Public design and image source provide a consumer-client/transparency comparison. | Review release-log inclusion/consistency, client update acceptance and request-key binding. Separate consumer service cohort. |
| Apple PCC | Useful public release-transparency comparison with a device-specific verification path. | Comparative reference-policy study first; live device testing separately. Do not count it as a general API endpoint. |

Secret AI and Nillion are further discovery priorities; Google Private AI Compute is another consumer comparison. OpenGradient's gateway and OpenPCC belong in component/framework cohorts until a concrete operated route is selected. The [landscape](landscape.md) provides primary links and scope for each. The four preliminary audits establish research directions, not new fully verified providers.

Existing systems also need explicit work packages:

| Current integration | Review workflow | Completion condition |
| --- | --- | --- |
| NEAR | Refresh catalog; separate gateway, gateway E2EE and direct modes; preserve per-model policy mappings; verify all detached-to-quote links; test response-key protection and encrypted tool fields | One current route packet per supported mode, with exact client revision and explicit prompt/reply guarantees; no cross-model anchor substitution accepted |
| Tinfoil | Verify report signatures; split release provenance from reproducibility; identify router and downstream worker evidence; monitor accepted repository/release policies | Router observations never imply worker coverage; every claimed hardware or channel check has positive and negative controls; missing worker evidence remains visible |
| Chutes | Enumerate confidential models and all discoverable instances; retain instance IDs and full relevant measurements; compare provider golden values with reviewed values; separate streaming and non-streaming E2EE | The already documented unpublished-MRTD case and missing-evidence models are caught by replay; stable base-image values never imply measured serving code |
| ACI and RedPill/Phala | Repair quote/key/compose/OS links; separate host enforcement from upstream evidence availability; review receipts and the selected request route | Altering any detached binding field rejects; a TEE gateway with a nonconfidential upstream is shown accurately; shared-workload changes fan out to each hostname |
| Venice | Rediscover current model IDs; distinguish official clients from third-party verifying proxies; trace upstream plaintext holders and their reference policies | Client verification and downstream confidentiality have separate results; a proxy pass cannot override an unresolved plaintext-hop gap |

These are readiness gates, not promises that every provider currently exposes enough evidence to meet them. A well-supported `unverifiable at this boundary` result is a useful outcome.

## Proposed data model

Keep the current adapters behind a normalization layer. Add these objects before broad dashboard work:

| Object | Required contents |
| --- | --- |
| Route | Provider, client/version/mode, endpoint, protocol, model mapping, plaintext holders, trust graph, fallback behavior, active interval |
| Component | Stable ID, role, operator, measured boundary and exclusions; reusable across reseller routes |
| Reference policy | Full digest/measurement, component and model scope, publisher, signature/trust root, source/build mapping, client acceptance rule, issue/expiry/retirement data |
| Observation | Unique ID, UTC capture time, observer/vantage, run ID, route and instance where available, raw evidence digest/location, verifier version, reference-policy revision, typed outcomes |
| Change event | Exact old/new observation or policy IDs, change kind, affected routes, first/last-seen interval, uncertainty and priority |
| Review | Event ID, source diff/build evidence, finding scope, disposition, reviewer identities, pending checks, expiry/revalidation triggers |

Use full digest equality in new approval records. Existing ledger prefix matches should be migrated with evidence; an eight-character prefix is not an adequate long-term authorization key. Treat old snapshot fields as historical adapter results rather than retroactively upgrading them to complete observations.

Outcomes should distinguish `verified`, `rejected`, `not_checked`, `unsupported`, `unavailable`, `stale`, and `not_applicable`, each with a reason and evidence. Store review status separately: `unreviewed`, `draft`, `accepted`, `rejected`, `superseded`. No string such as `audit_pending` should live inside a nominal boolean.

Suggested continuity measures are newly observed identities per 30 observed component-days, mixed-version windows, unapproved-observation counts, authorization-to-first-observation lag, first-observation-to-reviewed-decision lag, obsolete-client acceptance windows, and disagreements between vantage points. Report numerator, denominator, coverage window and censoring. A changed session key is not automatically a software update; classify certificate/key rotation separately.

## Workflow for provider discovery and onboarding

Run a weekly discovery pass over provider catalogs, official documentation, SDK releases, attestation standards implementations and existing provider relationships. Keep a dated candidate inventory with inclusion/exclusion reasons and next review date. Discovery should not require a completed audit; active scored coverage should.

For each selected system, first produce the route inventory and plaintext graph. Next locate reference publications and client acceptance code. Capture small public artifacts, pin source commits, and distinguish documentation claims from inspected implementation. Then verify a fresh live bundle and the exact session or encryption key used for a harmless request. Independently inspect mutable inputs, release authority and rollback behavior. Finally run negative controls and create a baseline review packet.

**Success gate:** every tracked route has an owner, scope and sampling plan. Every route labeled verified additionally has a reproducible capture procedure, reference-policy source, measured exclusions, and successful plus rejected-control transcripts. Rejected controls may use offline evidence mutation, clearly distinguished from deployed-client tests. A blocked credential or absent public proof is a published coverage status, not a reason to invent a verdict. Expensive image/EIF reproduction runs on zed or another suitable remote builder; preserve hashes, build logs and results, then remove installed/build copies.

Use Private Inference and Maple to design reseller/client-policy records. Use Privatemode and Confidential AI to add independent architectural coverage. Review shared Tinfoil and NEAR components once and propagate changes to dependent routes, while separately checking each wrapper's client behavior and fallback rules.

## Workflow for observation and change detection

Separate three cadences. Daily: capture representative production routes and policy publications. Weekly: refresh the full discovered model/route inventory and rotate through unobserved candidates. On a release, policy change or security notice: schedule a targeted capture and review. Each has its own completion record.

Persist each attempt before appraisal. Keep raw attestations, signatures, policy bytes and their hashes with bounded retention/storage rules; exclude credentials and sensitive prompt content. Pin the verifier dependency revision and policy revision so replay is possible. Upstream CI currently clones the verifier's moving default branch and installs dependencies with broad bounds; that can change the instrument between observations. Record or lock those inputs and explicitly classify instrument changes.

Compare observed identities against previous observations, provider references and client policies. Emit typed events for first-seen, known revisit, unauthorized value, revoked value still served, policy expansion/contraction, model mapping change, missing evidence, field/protocol change, key rotation, divergent simultaneous views and lost coverage. Do not classify a release publication as a deployed release without evidence connecting it to the running workload.

Retry transient failures under a bounded policy, retaining each attempt. Use a second vantage to investigate disagreements; two successful probes still do not prove global uniformity. Expose the period of uncertainty. An independent heartbeat watches collection and queue completion, with an alert after the declared freshness deadline.

## Workflow for Sol review jobs

The orchestrator should construct an immutable job packet: one event, exact old/new evidence and policies, baseline review, source/artifact mapping, affected paths, concrete questions, allowed tools, cost/time bounds and required output schema. “Audit provider X” is too unconstrained for recurring work.

Use a durable state machine: `detected → queued → running → draft_ready → reviewed → published`, with `retryable_failure`, `blocked` and `superseded` alternatives. Deduplicate by event ID; lease running jobs; retry expired leases; retain errors. A launch acknowledgment is only a queue receipt. Completion requires the stored output to pass validation. Publishing requires an explicit reviewed disposition, independent of agent prose.

For a new system, assign Sol to trace the request and reference-value chain. For an update, assign Sol only the bounded delta and require a source-to-live-artifact mapping. A second reviewer challenges the strongest claim and the unmeasured inputs. The root reviewer reconciles disagreement and signs the disposition. Agreement between two agents is not a cryptographic proof; tests and evidence remain necessary.

Require this output: affected route/component; old/new full identities; change classification; evidence links; plaintext-boundary impact; acceptance-policy impact; checks performed; uncertainties; recommended disposition; and concrete next action. Missing mapping is `needs evidence`, not mundane. Agents draft approval records but do not expand accepted values themselves.

Priority order should be: evidence/key-binding failure or new plaintext holder; accepted-policy expansion/revocation mismatch; active unreviewed build; coverage loss; ordinary key rotation; historical unused build. Shared-component changes fan out to all routes. This avoids repeatedly reviewing one gateway once for each model while a new independent system remains unexamined.

## Workflow for clear explanations and publishing

The front page should lead with: changes needing attention, current observation coverage, and recent reference-policy history. A reader should be able to select a route and see its plaintext graph, current observed/accepted values, last relevant change and unresolved gap. Keep detailed hardware fields underneath that explanation.

Generate the README summary, provider summaries and dashboard from common reviewed records. A claim must carry an evidence date, scope, review status and explicit conditions. New evidence affecting a claim makes it stale or superseded until reviewed. Keep historical claims visible in history rather than silently rewriting them.

Replace provider-wide Stage labels at the entry point with route-specific statements. A verifying Venice proxy cannot establish the confidentiality of an unmeasured downstream plaintext hop; label the client behavior separately. A Tinfoil audit of an older deployment cannot automatically cover every current backend. Stage terminology can remain in a secondary devproof appendix with its complete criteria and exact scope.

Before publishing, use a short comprehension review: can a reader identify who sees plaintext, what is pinned, who can update it, what changed and what remains unverified? Test NEAR gateway/E2EE/direct, Maple's two upstreams and a plain gateway route. If readers cannot distinguish these, the explanation is unfinished regardless of how many cryptographic fields it shows.

## Proposed success goals

These are acceptance targets for the next iteration, not measurements already achieved.

| Area | First acceptance target | Ongoing measure |
| --- | --- | --- |
| Verifier honesty | Fix or downgrade every identified unsupported pass; negative controls for quote/key, event/compose and policy bindings | Zero seeded binding violations reported verified |
| Reference consistency | Every active route declares observed, published and client-accepted values or explicit unknowns | Full-digest agreement/mismatch counts by component and policy |
| Capture reliability | Unique records survive two same-day runs and a partial-provider rerun | At least 95% of scheduled attempts recorded over 30 days; missed attempts remain visible |
| Freshness | Last authenticated observation and last attempt visible separately for every active route | Stale active-route evidence alerted within 26 hours under a daily schedule |
| Change detection | Every seeded identity, policy, model-map, evidence-loss and retirement event produces the correct typed record | Detection latency and missed-event rate on replay plus monitored production |
| Queue reliability | Kill a worker after launch; job retries without losing or duplicating its event | Every event has a durable state and owner; no silent disappearance |
| Review throughput | All active unexplained identities receive triage before clearing historical debt | At least 90% triaged within two working days; high-severity cases get a same-working-day owner |
| Coverage expansion | Four preliminary packets become explicit candidate/blocked/verified route records; target live cryptographic verification of two additional independent stacks subject to access, reporting rebuild and request proof separately | Separate counts of brands, stacks, routes, policy publications and live verified routes |
| Explanation quality | Four of five unfamiliar technical readers answer the five route questions correctly within two minutes | Recheck after material route or presentation changes |
| Agent usefulness | Blind replay of at least 20 historical/seeded cases with known answers and withheld later evidence | Critical-miss rate, abstention accuracy, reviewer corrections, time/cost per accepted packet versus deterministic baseline |

Avoid rewarding total alerts or total audits. Better outcomes are fewer unexplained active changes, shorter evidence gaps, reliable rejection of seeded inconsistencies, and less reviewer time to understand a real change. Set longer-term SLOs after measuring workload rather than promising full audit completion within an arbitrary deadline.

## Implementation sequence

**First slice: correct the instrument and the scope.** Reconcile work on a branch based on current upstream while preserving local edits. Fix ACI bindings, narrow misleading field names and lightclient wording, add targeted negative controls, and separate invalid from unreachable. Document NEAR's three paths and the response-key issue. Done when none of the known unsupported checks can produce an unexplained pass and route summaries match tested scope.

**Second slice: durable observation and review.** Add unique observation IDs, typed outcomes, component/policy records and a queue whose completion requires a validated review artifact. Backfill existing snapshots as legacy evidence. Add independent heartbeat and missing-model/evidence events. Done when partial runs cannot erase coverage, worker failure cannot consume an event, and published changes link to immutable evidence.

**Third slice: onboard the four research targets.** Start with reference-publication monitoring for Maple and Privatemode, since it is accessible immediately. Obtain the required access and perform scoped request tests for Private Inference; verify Confidential AI's public proofs before drawing deployment conclusions. Run heavy reproduction remotely. Each target exits with a verified route packet or a precise blocked/unknown status and named missing evidence.

**Fourth slice: publish and evaluate.** Build the timeline and route cards from the new objects, challenge them with unfamiliar readers, and backtest Sol jobs against deterministic alerts and archived cases. Retire misleading headline statistics. Defer broad pricing work, fleet-size estimators, public submission infrastructure and automatic approval until these fundamentals work.

The first useful release is small: an honestly scoped NEAR route comparison, an immutable observed-versus-accepted history, one external reference-publication monitor, and one review event that survives a crashed worker and reaches a reviewed public explanation. That tests the project's central promise before scaling it.

## Validation performed for this review

The existing local suite passed 34 tests. The reviewed upstream revision passed 41 tests using the existing venv in a temporary source copy; that copy was removed afterward. The separate offline ACI counterexample demonstrated acceptance with mismatched quote report data. The passing suite therefore does not establish verifier soundness.

Sol produced source/publication reviews for Private Inference and Maple and scoped evidence reviews for Privatemode and Confidential AI. No paid inference, credentials, live attack, heavy build, dependency installation, external message, deployment or approval-ledger promotion was performed. Provider-specific limitations and source links are recorded in the supporting reports. Production code and existing user edits remain unchanged.
