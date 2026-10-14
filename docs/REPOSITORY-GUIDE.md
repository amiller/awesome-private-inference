# Repository guide

Private Inference Beat connects three kinds of work: observing what providers
publish and serve, auditing what those observations actually constrain, and
critically testing the verifiers and policies used to interpret them. Its public
outputs are a route comparison and a reference values explorer. The verifier
directory and reusable routines support that work in Git.

The question is: **for this client, model and request path, who can read protected
data, what evidence limits that access, and who can change the software the client
accepts?** A useful result lets another person or agent check the answer, notice
when its dependencies change, and identify the next unresolved proof obligation.

This is a maintained orientation guide. Operational queue commands belong in
[REVIEW-WORKFLOW.md](REVIEW-WORKFLOW.md); the export and downstream-policy contract
belongs in [shared-verification.md](../specifications/shared-verification.md).
Update those documents with the code they describe. Keep dated investigations in
`research/`; they are historical evidence, not silently renewed conclusions.

## Keep the questions separate

| Question | Evidence needed | What it does not establish |
| --- | --- | --- |
| What did we observe? | Timestamped response/capture, full identity, route/component context and instrument revision | That the response or detached field is authentic |
| What did we verify? | Named cryptographic checks, trust roots, freshness and key/measurement bindings, with replay evidence | That every plaintext holder or client obligation is covered |
| What did we analyze? | Dated source review or experiment, exact versions, reasoning and counterexamples | A new live observation or permission to accept new software |
| Who authorized this value? | Identified authority and policy revision; signed statement or block-specific query where relevant | Independent review or acceptance by every client |
| What will this client accept? | The actual versioned client policy and enforcement path, including rejection controls | That an accepted workload is currently serving this request |
| Is the server or observer working? | Endpoint result, last attempt/capture, collection age and watcher heartbeat | Confidentiality, correct model binding or completed review |

An HTTP failure is not automatically a privacy finding. A responding endpoint is
not automatically verified. A fresh aggregate JSON file may contain old route
observations. Quote authentication, source provenance, independent build
reproduction and a protected request/reply exchange are separate obligations.

The comparison's **Collection** column reports returned adapter evidence and its
age, not successful inference completions or continuous provider uptime.
`probes.health` checks retained capture freshness and, when supplied, the watcher
heartbeat; it does not make a live server-availability measurement. The optional
pricing probe can exercise chat calls, but is not a comprehensive uptime monitor.
A green freshness check can coexist with unresolved reviews and incomplete proofs.

## Where to look and what to edit

| Source or output | Role and maintenance rule |
| --- | --- |
| `data/routes.json` | Maintained client/request-path inventory: plaintext holders, reference authority, dependencies and blockers. Use its route IDs in claims. |
| `data/candidates.json` | Maintained discovery candidates, inclusion reasons and unresolved onboarding work. Inclusion is not verification. |
| `data/verifiers.json`, `verifiers/` | Curated implementation/scope directory and executable adapters. Check the actual code, external appraisal and unchecked links before relying on a label. |
| `data/instrument.json`, `uv.lock`, `probes/instrument.py` | Dependency pin and recorded instrument provenance. An instrument change can change results without a provider change. |
| `probes/catalog.py`, `probes/attestation.py` | Sentinel selection and adapter dispatch. Catalog discovery does not automatically change the monitored sample. |
| `data/observations/{runs,attempts,records}/`, `data/snapshots/` | Retained attempts and reports, including rejected, incomplete and legacy observations. Preserve their original scope and time. |
| `data/references/observations/` and its `raw/` directory | Dated publication captures and retained bytes. Recheck recorded hashes when tracing a claim. Publication is not runtime attestation. |
| `data/continuity/events/`, `data/references/events/` | Persisted change events derived from retained evidence; inputs to review work. An event is not an approval. |
| `data/reviews/decisions/`, `data/audits/` | Published review dispositions and historical scoped audit ledgers. Preserve review scope/date; neither grants a client policy update. Some adapters use audit matches as individual check inputs. |
| `data/assessments/routes.json`, `providers/*.md` | Maintained, dated interpretation of route evidence and its gaps. New claims require supporting evidence, not only a wording change. |
| `data/latest.json`, `data/references/latest.json`, `data/quality.json` | Derived current indexes and summaries. Follow their references to original evidence; do not treat regeneration time as renewed verification. |
| `probes/observations.py`, `continuity.py`, `references.py`, `reference_history.py`, `assessments.py` | Observation, event, history and assessment transformations. Test context preservation and missing/failed evidence behavior when changing them. |
| `site/templates/`, `probes/render.py` | Website source. Comparison and Reference values are the two primary views. Supporting assessments, methodology and stage criteria explain them. |
| `docs/*.html`, `docs/reference-values.json`, `docs/evidence/` | Generated publication outputs. Regenerate them; do not edit them as source evidence. `docs/*.md` are maintained documentation. |
| `research/`, `tasks/` | Dated investigations, retained validation and work records. A completed task list is not proof of current operations. |
| `local-data/` | Ignored local working evidence and private queue state. Preserve useful sanitized results, never publish leases or credentials. |

## Trace and independently challenge one claim

1. **Choose the exact route and claim.** Start with a comparison cell and its
   linked assessment, or an explorer event and its evidence. Record client/mode,
   requested model, component and protected fields. Distinguish prompt from reply
   confidentiality and ordinary API use from an optional encrypted path.
2. **Recover the evidence and its time.** Follow the assessment's pinned sources
   or the event's old/new observation references. Inspect the retained bytes,
   full values, capture outcome and instrument revision. Record missing evidence.
3. **Identify the boundary.** Trace what the measurement covers, what remains
   mutable, who holds plaintext, and who can change the client policy. A gateway
   quote does not prove the selected worker; a base image may exclude serving code.
4. **Challenge the strongest link.** Replay the relevant verification with retained
   evidence where supported. Independently alter a claimed nonce, key, payload,
   model, reference or policy binding. Document exactly what rejects and what is
   merely parsed or compared. A mocked counterexample demonstrates the tested
   acceptance defect, not a live provider compromise.
5. **Publish a bounded conclusion.** Name the performed checks, strongest supported
   claim, unresolved obligations and next action. Use the review workflow for a
   queued event; update an assessment only when its scoped evidence warrants it.
   Preserve the previous history. Never translate a reviewed change into automatic
   acceptance or a stage award.

For example, a new Chutes MRTD is an observed base-image identity. Checking its
quote binding and provider golden-set membership does not establish which
unmeasured serving code handled a prompt. The review should identify that missing
link and its effect on the route, even when the measured value itself is familiar.

### Trace a retained Maple publication

From the repository root, this example locates an actual retained capture,
checks its recorded byte digest and finds the corresponding explorer event.
It needs only Python's standard library and the generated reference export:

```bash
python - <<'PY'
import hashlib
import json
from pathlib import Path

archive = Path("data/references/observations")
capture = archive / "publications-20261014T012427578778Z-9757b38a5d973c69.json"
record = next(item for item in json.loads(capture.read_text())["observations"]
              if item["source_id"] == "maple-canonical-pcrProd.json")
raw = archive / record["raw_path"]
assert hashlib.sha256(raw.read_bytes()).hexdigest() == record["sha256"]
export = json.loads(Path("docs/reference-values.json").read_text())
events = [event for event in export["events"] if event["evidence"] == raw.as_posix()]
assert events, "No explorer event links this retained publication"
print(json.dumps({"capture": str(capture), "raw": str(raw),
                  "observed_at": record["observed_at"], "source": record["url"],
                  "verification": record["verification"],
                  "events": [{"id": e["id"], "scope": e["scope"],
                              "new": e["new"]} for e in events]}, indent=2))
PY
```

This establishes that the retained bytes match the capture record and that the
explorer exposes them with a declared scope. It does **not** authenticate the
publisher, prove a live Nitro measurement, or show that a shipped client enforces
these PCRs. Continue with [Maple's route analysis](../providers/maple.md), its
dated sources and the relevant client-policy implementation before making any
of those claims.

To check the change detector's handling of rejected values and missing evidence,
run `python -m pytest tests/test_continuity.py`. Its labeled cases in
`tests/replay_cases.py` are synthetic negative controls for detector behavior;
they neither evaluate an agent's audit quality nor establish provider behavior.

## Validation and observation commands

Run from the repository root with an existing Python 3.11+ environment activated.
For offline review of retained evidence:

```bash
python -m pytest
python -m probes.render
git diff --check
git diff --stat
```

`render` writes generated files but makes no live provider probes. Inspect the
diff and confirm that another render produces identical outputs. Tests establish
the behavior covered by their fixtures; they do not renew a provider assessment.
Use focused tests during implementation and the full suite before a completed PR.

For website changes, reuse existing Playwright and `/usr/bin/chromium`:

```bash
python tools/check_comparison_browser.py
python tools/check_history_browser.py
python tools/check_beat_browser.py
```

These scripts write screenshots/results under ignored `local-data/`. Inspect
desktop and mobile views as well as assertions. The standalone explorer embeds
its data and works offline; comparison styling currently uses the Tailwind CDN.
Do not install a second browser or a Node build to run these checks.

If an environment must be provisioned, `uv sync --frozen --extra dev` follows CI.
Live NEAR collection additionally needs `--extra nearai` and an upstream verifier
checkout at `data/instrument.json`'s exact revision, exposed through
`NEARAI_VERIFIER_PATH`. Reuse existing environments/checkouts where possible.

The observation sequence starts with **live collection** (`collect` and
`references`, with network and evidence-writing effects), then derives quality
and publication outputs offline (`quality --write` and `render`):

```bash
python -m probes.collect
python -m probes.references
python -m probes.quality --write
python -m probes.render
```

Use `python -m probes.references --catalogs` for catalog discovery.
`python -m probes.collect --providers chutes` limits collection to that provider;
other retained routes keep their old timestamps. `--pricing` is separate and
can spend money. `--backfill` imports historical snapshots as legacy observations;
it is an evidence-writing operation, not a new verification.

For operational status, inspect the stored evidence with:

```bash
python -m probes.health
python -m probes.review_queue status
```

To include the local watcher heartbeat, use
`python -m probes.health --queue-status local-data/review-queue/status.json`.
Health failures can reveal old captures, missing evidence or an expired heartbeat.
The GitHub freshness workflow cannot prove that a separate zed watcher is alive.
The detailed [review workflow](REVIEW-WORKFLOW.md) documents dispatch, leases,
independent review and sanitized publication; its `--dry` worker command still
ingests queue work, so it is not a purely read-only check.

## Sustained priorities and completion criteria

Prioritize broken bindings and new plaintext access, unexpected acceptance-policy
changes, unexplained active identities, then lost coverage and historical gaps.
For each task, record the route/component, exact evidence, owner or blocker, next
action and what result would close it. Do not substitute more provider names,
more samples or a quieter dashboard for resolving a proof obligation.

Maintain these feedback loops:

- **Observations:** preserve attempts and rejected evidence; expose stale or
  missing captures and distinguish newly observed identities from deployments.
- **Verifier criticism:** retain replayable failures and negative controls;
  recheck claims when dependencies, adapters or trust policies change.
- **Scoped audits:** trace source to measured software and actual protected
  exchanges; retain unknowns when builds, credentials or bindings are missing.
- **Review operations:** measure completed dispositions and age of unresolved
  work, not worker launches. Keep an independent heartbeat for the observer.
- **Reader usefulness:** a reader should follow a comparison claim or timeline
  point to evidence and reproduce its limits without reconstructing chat history.

Current implementation gaps and dated rollout evidence are linked from
[the implementation record](../tasks/reference-observatory.md). Revalidate them
before treating them as present status. A successful PR states what changed,
what was independently checked, and which obligations remain open. Git history
and stored hashes support inspection but do not implement a witnessed transparency
log. Shared exports do not integrate Abalone or authorize its clients.
