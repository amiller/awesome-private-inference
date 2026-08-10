# Critical review: what this registry actually measures

Date: 2026-08-10. Data: 111 daily snapshots, 2026-04-21 → 2026-08-10, 2,358 provider-model-days.
All numbers below are computed from `data/snapshots/*.json` on `origin/main`, not from the README.

## Summary

> **Correction, same day.** This review said Venice's bar was uneven but still treated its
> full row as a scoring quirk. It is worse than that: the two layers Venice's bar excluded
> — `prod_os_image` and `serving_code_attested` — are exactly where Venice's prompt-path
> exposure lives, per an independent audit that does not cite this registry. Corrected in
> `verifiers/common.py` on 2026-08-10; Venice now reads 6/9 and the board has zero fully
> verified targets. See `providers/venice.md` and issue #11.


The instrument works. The verdict layer on top of it has never fired, and the website shows
the wrong thing. The unique asset — a 111-day version timeline — is not published anywhere.

The recommendation is to stop framing this as an audit and reframe it as an observatory:
the object of study is *how fast the trusted computing base of a production confidential-inference
service changes*, and what that does to any client that pins it.

## 1. The headline signal has never fired

Across 111 days and 2,358 observations:

| outcome | count | share |
|---|---|---|
| pass | 1,656 | 70.2% |
| transport / liveness failure (502, 503, DNS, TLS, 404) | 572 | 24.3% |
| invalid with no error recorded | 130 | 5.5% |
| **verification failure** | **0** | **0%** |

Not one red cell in the registry's history was caused by a cryptographic check rejecting a
provider. Every one was network weather from a GitHub Actions runner, or an unexplained
invalid with no error string.

So the dashboard's largest numbers — `redpill 0/6`, `tinfoil 1/4` — measure provider uptime
as seen from one vantage point on one afternoon. A reader has no way to tell that apart from
"this provider failed a security check," which is what the page's framing implies.

RedPill has been 0/6 on 502s since 2026-06-30. Six weeks of solid red that says nothing about
RedPill's privacy properties.

## 2. `valid` and `stage1_ready` are different, and the page leads with the wrong one

Chutes shows **4/5 valid** — one of the largest green numbers on the page. But `chutes-tee`'s
required-layer set in `verifiers/common.py:65` includes `serving_code_attested`, which the
verifier returns `False` for by construction. Chutes can never reach Stage 1 under this repo's
own definition. It is also the provider where live cross-user prompt exfiltration was
demonstrated (2026-06-16/17).

The summary card is structurally incapable of reflecting the registry's own most serious
finding. `valid` means "we got a well-formed attestation back and parsed it," which is close
to a liveness check.

## 3. The provider rated best renders as an empty row

`REQUIRED_LAYERS_BY_SHAPE["tinfoil-sev-snp-v2"]` is exactly five layers:

    code_measurement_reproducible, tls_pubkey_pinned, hpke_pubkey_attested,
    client_nonce_supported, runtime_config_fully_attested

None of the five is in `SCORECARD_LABELS` (`probes/render.py:24`). Every one of the nine
visible columns for a Tinfoil row is a grey "architecturally N/A" dash, and the `Surface ✅`
verdict is computed entirely from fields that appear nowhere on the page.

Six of the fifteen scorecard fields are collected and never rendered. This is the single
largest cause of "inscrutable": for the provider the README calls Stage 1, the table is blank.

## 4. The prose is hardcoded and has drifted from the data next to it

The "Known limitations" list is literal HTML in `site/templates/index.html.j2:150`. It still
asserts that RedPill switching to the prod OS image "hasn't been done" — while the
`prod_os_image` column exists specifically to track that, and the README records it resolved
2026-06-18. The page contradicts its own column, and will keep doing so until someone
hand-edits the template.

The Stage-1 verdict table at the top is likewise hand-written HTML: undated, no provenance,
no re-check, no link to the observation it came from.

## 5. There is no quality control on the auditor

Nothing in the system measures the registry's own coverage, freshness, or correctness.

Worse: over 111 days there were 24 scorecard cell flips on valid rows, and **20 of the 24 are
`backend_attested` on NEAR** — a tri-state whose amber state means *the analyst pair hasn't
reviewed this image yet*. The remaining four are `gpu_attested` flapping on RedPill, almost
certainly transient NRAS failures.

The only column that meaningfully moves is one measuring our own review backlog, and the page
does not say so.

## 6. Minor tells

- The page says "eight capability layers." The code renders nine. The schema has fifteen.
- "Stage 0 / Stage 1" is load-bearing on every surface and is defined in a different repo.
- 111 snapshots of time series exist; the site renders exactly one day.

---

# The trajectory data — the part that is actually unique

Computed by separating **novel** transitions (a version string never observed before → a real
deploy) from **revisits** (a return to a previously-seen value → fleet sampling or rollback).

| target | obs | days | distinct | novel | revisit | days/deploy |
|---|---|---|---|---|---|---|
| tinfoil/router | 106 | 106 | 29 | 28 | 0 | **3.8** |
| near-ai/openai/gpt-oss-120b | 83 | 85 | 19 | 18 | 0 | **4.7** |
| near-ai/zai-org/GLM-5.1-FP8 | 83 | 83 | 18 | 17 | 0 | **4.9** |
| near-ai/Qwen3-30B (retired) | 32 | 31 | 10 | 9 | 0 | 3.4 |
| tinfoil/gemma4-31b | 87 | 87 | 7 | 6 | 0 | 14.5 |
| tinfoil/llama3-3-70b | 93 | 93 | 3 | 2 | 0 | 46.5 |
| tinfoil/gpt-oss-120b | 82 | 82 | 2 | 1 | 0 | 82.0 |
| chutes/Qwen3-32B-TEE | 53 | 53 | 2 | 1 | **19** | 53.0 |
| chutes/gemma-4-31B-TEE | 53 | 53 | 2 | 1 | **16** | 53.0 |
| chutes/Kimi-K2.6-TEE | 53 | 53 | 2 | 1 | 4 | 53.0 |
| redpill/phala/* | 33 | 40 | 1 | 0 | 0 | never |
| venice/* | 109 | — | — | — | — | no version identity |

Version field used per provider: near-ai `cloud_api_image_digest`; tinfoil `digest`;
chutes `mrtd`; redpill `os_image`; venice — none exists.

### Four findings

**Confidential-inference TCBs move fast.** NEAR ships a new cloud-api image every ~4.7 days
observed, ~4.2 after correcting for deploys that begin and end between two probes
(`lambda = -ln(1 - T/(n-1))/delta`). Tinfoil's router: 3.8 observed, 3.3 corrected.
Any client that pins a measurement is stale inside a week. This
directly contradicts the assumption every deployed client verifier rests on — hermes' anchor
PR, bitrouter's `AciDcapVerifierPolicy` env allowlist, Phala's flat lists all assume pins are
approximately static.

**There is a two-tier pattern.** The router/gateway churns (3.8 days); the per-model enclaves
where prompts are actually decrypted are near-static (Tinfoil gpt-oss-120b: one change in 82
days). The fast-moving component is the one with the most operator-reachable surface. That is
a real architectural result and it falls straight out of the data.

**Naive churn counting is wrong by 20×.** Chutes' Qwen3-32B appears to change 20 times. It has
exactly two MRTDs in its entire history, and 19 of the 20 transitions are returns to a
previously-seen value. That is a load balancer being sampled once a day, not a deploy timeline.
Any "commit frequency" metric that does not separate novel from revisit reports the most static
fleet in the registry as the most volatile.

Pooling the five Chutes models sharpens it: one deploy with a ~7-day ramp (2026-06-25 → 07-02),
then a persistent minority of old-image instances still appearing five weeks later (Qwen3-32B
29%, gemma-4 21%). Not a permanent 50/50 split, not A/B routing, and not a completed rollout.

**Correction — revisits only mean fleet sampling for Chutes.** For near-ai the version is
regexed out of the *gateway's* `app_compose`, and for tinfoil it is read from GitHub
`releases/latest`. Both are single control-plane documents, so those series cannot show fleet
structure and their zero-revisit sequences are guaranteed by construction rather than observed.
Fleet size is not identifiable from once-daily single-sample probing on any row; it needs
instance labels (Chutes already returns a full instance census that the verifier discards;
Tinfoil's per-connection TLS SPKI is an attested instance label). Recorded in
`probes/quality.py:VERSION_IDENTITY`; issues #8 and #9.

**Coverage is uneven, and this is the honest answer to "how well do we track the others?"**

| provider | trackable? | why |
|---|---|---|
| near-ai | yes | `cloud_api_image_digest` is a stable content hash and a meaningful audit unit |
| tinfoil | yes, incidentally | sigstore `digest` is a content hash; we never designed for it |
| chutes | partial | one `mrtd`, no instance id, so fleet and deploys are inseparable |
| redpill | no | `os_image` is a mutable tag; it never changes by design |
| venice | no | exposes no version identity at all |

So the intuition is right: NEAR is tracked well, Tinfoil accidentally well, and the rest
poorly or not at all. The fix is not more probing — it is making "what names the code version
here" an explicit, declared property per provider instead of an accident of five different
verifier files.

---

# Is this a good research topic?

Yes, but not as an audit.

The audit framing is what breaks it. Every output has to be a verdict; verdicts need judgment;
judgment does not automate; and the automation ends up producing 111 days of nothing. The
0-verification-failures result is a null result for an audit and the *entire point* for a
measurement study: **deployed TEE inference does not fail its own attestation checks. It fails
everything around them, and it rewrites itself every four days.**

### The question

*How does the trusted computing base of a production confidential-inference service change
over time, and what does that imply for any client that must pin it?*

### Why it holds up

- **Empirically load-bearing, and nobody has the data.** The deployed client verifiers all pin.
  The measurement says the pins rotate weekly. That falsifies a working assumption.
- **Clean unit of measure with a real methodological contribution.** Novel-vs-revisit
  transitions, plus the fleet-sampling confound: you cannot infer a deploy timeline from
  single-sample polling of a load-balanced fleet. That is a generalizable result about
  measuring any attested fleet from outside.
- **A legible analogue already written down.** `research/observation-log.md` frames this as
  Certificate Transparency for enclave measurements — TOFU-and-complain, cross-check against
  an independent authority, contribute observations back. That doc is the strongest thing in
  the repo and it is the one thing nobody sees.
- **The agent loop is a second contribution if scoped narrowly.** Not "an agent audits." An
  agent that turns a *detected* transition into a *triaged* one: classify the drift, draft the
  delta review. Backtestable against 111 days of ground truth already on disk.

### Risks

- n = 5 providers, 21 targets. Small. 111 days is a workshop paper; 12 months is a paper.
- If the fleet-sampling confound is not handled, the headline numbers are simply wrong.
- Two of five providers currently have no measurable version identity, which caps coverage
  until the probe changes.

---

# Rebuild from first principles

The core inversion: **stop publishing verdicts, start publishing a timeline.** The daily
snapshot is the wrong primitive. The observation and the transition are the right ones.

### Four layers

1. **Observation** — an immutable signed record of one probe of one target at one instant,
   including the observing vantage and the *instance* identity. Never overwritten.
   Mostly exists as `data/snapshots/`. Missing: instance identity, without which fleet
   sampling cannot be separated from deploys.

2. **Identity** — per provider, a declared answer to "what string names the code version, and
   is it a content hash or a mutable tag?"
   `{field, kind: content-hash | mutable-tag | absent, is_audit_unit: bool}`.
   This is the abstraction the repo is missing; it is currently implicit across five verifier
   files. Venice's answer is `absent` — the page should say so instead of rendering a green row.

3. **Transition** — derived, never probed. Novel vs revisit; anchored vs unanchored against the
   on-chain authority already swept by `probes/onchain_sweep.py`. This becomes the primary
   published artifact, replacing the matrix as the front page. It is the continuity log already
   designed in `research/observation-log.md`.

4. **Triage** — the agent layer. Input: one transition. Output: a class and a draft review.
   Evaluated by backtest, not by vibes.

### Three presentation rules

- **Split the three axes currently collapsed into one ✅:** *reachable* (did we get a response),
  *verifies* (did the check pass), *sufficient* (does the shape expose enough for the check to
  mean anything). Today all three render as the same green or red, which is the whole problem.
- **Nothing hardcoded in a template.** Every claim carries an as-of date and the observation id
  it derives from, or it does not go on the page.
- **Publish the auditor's own metrics.** Coverage, freshness, and the count of findings the
  system has ever produced. If that number is zero, print zero. That is the quality control
  the system currently has none of.

### What to keep

The probe layer, the CI, and `REQUIRED_LAYERS_BY_SHAPE`. The per-shape required-layer model is
the best idea in the codebase: it encodes "what should this provider be able to prove, given
what it claims," and treats a missing check as a failure rather than an N/A. That epistemics is
right and should survive the rebuild intact.

---

# Framing note for handoff

This is a measurement instrument, not a security audit. That distinction matters for how the
work reads and for who can pick it up cold.

**Vocabulary to drop:** verdict, Stage 0 / Stage 1, backdoor, attack, exfiltration-as-headline.
"Stage 0/1" in particular is load-bearing on every surface and defined only in
`devproof-audits-guide`, a different repo — anyone reading this one cold cannot resolve it.

**Vocabulary to use:** observation, version transition, deploy cadence, coverage, anchored,
vantage, confound.

**The three genuinely hard parts, worth handing off:**

1. **The fleet-sampling estimator.** Given single-sample daily polling of a load-balanced fleet
   of unknown size, recover the true deploy timeline and estimate fleet size. Chutes is the
   worked example: 2 distinct MRTDs, 20 observed transitions, 1 real deploy.
2. **The identity abstraction.** One declarative schema for "what names the code version" that
   covers five heterogeneous attestation shapes — dstack compose hash, sigstore digest, SEV
   measurement, raw MRTD, and absent.
3. **The triage-agent backtest harness.** 111 days of transitions with known outcomes; measure
   whether an agent's classification beats the trivial baseline.

**The mechanical parts, not worth handing off:** probes, verifiers, CI, rendering.
