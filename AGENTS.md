# Work on Private Inference Beat

Read [README.md](README.md) for the project question and
[docs/REPOSITORY-GUIDE.md](docs/REPOSITORY-GUIDE.md) for authoritative inputs,
evidence tracing, validation and priorities. Use
[docs/REVIEW-WORKFLOW.md](docs/REVIEW-WORKFLOW.md) for observation review jobs.
Historical research and completed task checklists describe their own revisions;
they do not override current code or constitute current deployment evidence.

## What a useful change establishes

For a named client, mode, model and request path, explain what can receive
plaintext, what evidence constrains it, which authority changes accepted software,
and what remains unknown. Preserve a reader's ability to check that conclusion.
Observation, cryptographic appraisal, analysis, provider authorization, client
acceptance and service liveness are distinct facts. Never promote one into another.

- Keep full identities and component/model/policy context. An unchanged hash does
  not prove unchanged unmeasured code; a newly observed hash is not a deployment.
- Link claims to dated evidence and exact source/instrument revisions. State what
  was actually tested. Source inspection, a simulated counterexample and a live
  request prove different things.
- Preserve failed/rejected observations and history. New observations and agent
  reviews must not silently expand accepted values or award security stages.
- Review the verifier as critically as the provider. Test a claimed binding by
  altering each relevant input independently; a passed adapter flag is insufficient.
- Separate source inputs from generated outputs. Edit `site/templates/` and
  regenerate with `python -m probes.render`; do not hand-edit generated HTML or
  `docs/reference-values.json`. The Markdown guides under `docs/` are maintained
  source, not generated files.
- The website's two primary views are Comparison and Reference values. The
  verifier directory belongs in Git. Stage criteria and methodology support the
  views; no stages are currently awarded.

## Working method

For changes to project goals, public claims, explanatory prose or visual design,
involve Astra in framing and final review. Give implementation agents bounded
tasks with concrete success conditions and exact evidence to inspect. Keep final
editorial judgment tied to the evidence, including when an honest unknown is the
correct result.

Inspect `git status` and the current branch before editing; preserve unrelated
work. Reuse an existing Python environment. Begin with offline validation; live
collection is a separate action with network, credential and evidence-writing
effects. A task's existing authorization governs whether to run it. Do not buy
access, change trust roots or weaken checks to make a blocked task pass.

For a change to a verifier, preserve a reproducible case and meaningful negative
controls. For UI changes, exercise the existing browser checks and inspect desktop
and mobile screenshots. Report checks actually run, remaining proof gaps and
whether live evidence was collected. Do not present tests as deployment health.

Never commit credentials, private prompts, authorization headers or review-queue
lease tokens. Queue state stays under ignored `local-data/`; publish only sanitized
evidence and reviewed dispositions through the documented workflow.

## Disk hygiene on this laptop

The laptop disk is small and has filled up repeatedly. Every npm install costs
about 1G and every cargo target/ several G.

- Remove a worktree with `git worktree remove` once its branch merges. Move any
  local-data/ evidence it holds into the owning project's
  local-data/retired-worktrees/<name>/ first.
- Once a test install, release rehearsal or cloned upstream source has produced
  its evidence, delete its node_modules/, target/, dist/ and build/ output. Keep
  logs and results, not installed copies. Keep at most one live install per
  rehearsal.
- No heavy builds here: Rust toolchains, full node builds like zebrad, or
  downloads over about 500MB. Run them on zed, or ask first.
