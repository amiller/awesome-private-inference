# Plan: daily per-machine archive of NEAR AI Cloud model machines

Drafted 2026-11-24 from origin/main `1876d43`.

**Decisions (Andrew, 2026-11-24):** one full raw entry per machine per day (~70 MB/yr) is fine; keep using `NEAR_API_KEY`; NEAR's own machines first — recording Chutes/Tinfoil-routed models as "not a NEAR machine" is wanted but deferred (follow-up note); the Logbook moves into the observatory site; the duplicate `cc796618` listing is handled by the agreement rule, not raised with NEAR.

## 0. Findings that shape the plan

1. `data/near-deployments-seen.json` never updates: `near_ai.verify()` writes it, but `probe-daily.yml`'s commit step doesn't `git add` it, so `deployments_aged` can never become true for a new deployment.
2. The GLM lane fails because the gateway lists instance `cc796618` twice (different quotes, same compose hash, TLS fingerprint and 60-action log) since about 11-20. `near_ai.verify` and teep both require distinct instance ids.
3. The model list is `probes/catalog.py` `MODELS["near-ai"]`; NEAR routes in `data/routes.json` are wildcards.
4. Keyless `GET https://cloud-api.near.ai/v1/model/list` returned 65 models on 11-22, 16 with `metadata.attestationSupported: true`; 12 of those are `ownedBy: "nearai"` and run on compose-manager CVMs. DeepSeek-v3.2 and Kimi route to Chutes; `z-ai/glm-5.3` routes to Tinfoil (503).
5. `_public_attestation_fields` drops `info.vm_config`, `device_id`, `app_cert`, `key_provider_info`, `mr_aggregated`, `compose_manager_attestation.{vm_config, event_log, nonce_source}` and `ohttp_*`. A model entry is ~190 KB (GPU payload ~98 KB); gzip is ~5×.
6. Since 11-14 the Qwen and GLM evidence already captured compose-manager logs for gpu13 `a8a25faa`, gpu23 `cc796618`, gpu03 `19aea169`. DeepSeek machines gpu02 `fccd496a` and gpu04 `7bb9af0a` exist only in souk captures (11-22, and a manual capture on 11-24 in `souk/local-data/near-captures-2026-11-24/`: gpu04 88 actions, gpu02 37).
7. Machine labels come from `INSTANCE_LABEL=gpuNN` in the measured `app_compose`. Key by `instance_id`; the label is an attribute.
8. Direct `-iN` hostnames don't name machines (DeepSeek `i0`–`i5` alternate between two instances). Direct discovery: `GET https://completions.near.ai/endpoints`, `GET /backends/count?domain=…`, `https://<label>-i<N>.completions.near.ai/v1/attestation/report`.
9. The NEAR Machine Logbook (`souk/notes/near-machines/`) is built by `souk/local-data/near-compose-manager-2026-11-22/research/machine-eval-scripts/`; input enters via `load.py:machine_actions()` with hard-coded tables and dedupes on a 7-field tuple that omits `tag` and `file_sha256`.
10. Failures are masked today: `probes/attestation.py:_one` turns exceptions into rows, `probes/collect.py` always returns 0, job timeout 20 min (#18 records 4 cancellations).

## 1. Collection

- Once per run: `GET /v1/model/list`, stored raw. Select `attestationSupported && ownedBy == "nearai"` (12 today). Exclusions are an explicit list with reasons.
- Per model: `GET /v1/attestation/report?model=…&nonce=<fresh 32 bytes>&signing_algo=ecdsa&include_tls_fingerprint=true`. One nonce per request, recorded. A compose-manager log counts as fresh only if `report_data == sha256(canonical actions) || our nonce` (`near_deployments.appraise` already checks).
- Direct, until 2026-12-06: enumerate endpoints and backend counts, fetch each `-iN` report with its own nonce, record the presented leaf cert and compare to `tls_cert_fingerprint`. Only Direct gives the cert→instance binding, fleet totals and `all_attestations`. Remove the stage in an explicit commit on 12-06; until then a Direct failure fails the run.
- GLM fix in `verifiers/near_ai.py`: appraise every entry; group by `instance_id`; accept duplicates only if MRTD, RTMR0–3, compose hash, signing key/address, TLS fingerprint and `actions_hash` agree, else reject "instance <id> listed with conflicting identities". Record `instance_entries`. Never drop a duplicate silently.
- Split `near_ai.verify` into `fetch_report` (raises on non-200) and `appraise_report`. The collector archives raw first, then appraises; a policy rejection is an appraisal outcome, not a collection failure.
- Widen `_public_attestation_fields` to keep the fields in §0.5 (also helps #35/#36).
- Add `deepseek-ai/DeepSeek-V4.1-Flash-1017` to `catalog.MODELS["near-ai"]`.

## 2. Per-machine record

Key: full `instance_id`. Records are per (machine, model) entry.

- `data/near-machines/<instance_id>/captures/<run_id>.json`: identity (instance id, label, app_id, compose hash, `app_compose_sha256`, os image, `vm_config`, `device_id`, MRTD/RTMR0–3/MRCONFIGID, debug, boot registers, optional PCK leaf hash); one entry per model (source gateway/direct, nonce, quote, TCB status and advisories, signing key/address, TLS fingerprint, OHTTP key config, GPU verdict, appraisal booleans, compose-manager `{actions_hash, recomputed_ok, report_data_binds_nonce, same_cvm_as_model, tcb, nonce_source, ordered action digests, quote}`, raw ref).
- Raw: one full raw entry per machine per run plus the gateway attestation; other entries keep quotes but drop `nvidia_payload` (Q1).
- `data/near-machines/<instance_id>/actions.jsonl`, append-only: `{sha256 over the whole canonical action, action, first_seen_at, first_capture, bound}`. An archived action from the last 6 days missing from today's bound log becomes an `actions_missing_within_retention` finding.

## 3. Storage

- Raw and blobs in the existing content-addressed store `data/observations/evidence/sha256/`, via `observations.digest` / `_write_new`.
- Run records `data/near-machines/runs/<run_id>.json` with per-model `ok | fetch_failed | appraisal_error` and `status`.
- Derived (regenerated): `data/near-machines/index.json`, `<instance_id>/timeline.json`, `changes/<run_id>.json`.
- Size: ~1 MB JSON/day (~70 MB/year packed) as written; ~180 MB/year if every entry keeps full raw. Repo is fine at this volume; revisit past ~20 machines. Run only on `schedule` and `workflow_dispatch`.

## 4. Where it runs, failure reporting

- New job `near-machines` in `.github/workflows/probe-daily.yml`: `needs: probe`, `if: !cancelled() && event != push`, 30-minute timeout, same setup as the probe job.
- `python -m probes.near_machines` writes everything captured and a run record, exits 1 if any fetch failed. Commit with `if: always()` (stage `data/near-machines/`, `data/observations/evidence/`, and Q2). No retries, no substituted data.
- `probes/health.py`: `stale_near_machine_collection` (>26 h) and `near_machine_collection_failed`.

## 5. Derived views

- `timeline.json`: first/last seen; changes to compose, app_compose, os image, MRTD/RTMR0–2, TCB, signing address per model, TLS fingerprint, OHTTP key, GPU verdict, models served, entry counts, running deployments; deploy actions by reported (host-supplied) timestamp.
- Logbook: replace `load.py:machine_actions()` with a reader over `actions.jsonl` and `index.json`.
- `changes/<run_id>.json` feeds `watch/beat-digest.sh`; add one sentence to `watch/beat-digest.md` source 1 (machine changes with old/new values; a failed collection is a coverage gap).

## 6. Tests (each prevents a named failure)

1. Duplicate instance entries (GLM lane unavailable since ~11-20): replay `2ca9798d…`; conflicting duplicate rejects. Replaces `test_duplicate_instance_rejects`.
2. Pruning loss: long log then pruned log keeps every action; actions differing only in `file_sha256` stay distinct.
3. Masked failure (#18's `|| true`): one model 503 → run `failed`, nonzero exit, other captures written.
4. Replayed log: unbound `report_data` stored with `bound: false`, not counted as authenticated.

## 7. Steps

Urgent: gpu02/gpu04 logs prune after 7 days; the 11-24 manual capture covers them until the archive runs.

1. `verifiers/near_ai.py`: split, duplicate rule, widen fields; tests 1 and 4.
2. `probes/catalog.py`: DeepSeek lane.
3. `probes/near_machines.py` (~200 lines); tests 2 and 3.
4. Direct stage, dated removal 12-06.
5. Workflow job; commit `near-deployments-seen.json` (Q2).
6. `probes/health.py` findings.
7. Backfill (`--backfill <paths>`): the 15 repo evidence files, then souk captures tagged `source: backfill:<path>@sha256`; logs without a retained quote marked unauthenticated; dates without `vm_config` listed for #36.
8. Beat-digest feed; repoint the Logbook.

Fit with issues: #35 keeps the RTMR0 derivation; #36 gets model-CVM boot-register history from day 1; #18 gets NEAR model TCB history; #29 gets per-machine key/TLS/OHTTP history.

## 8. Open questions for Andrew

1. Raw retention: one full raw per machine per day (~70 MB/yr) or every entry with GPU payload (~180 MB/yr)?
2. Should CI commit `near-deployments-seen.json` (widens what the age gate accepts after 24 h), or derive `first_seen` from `actions.jsonl`?
3. Keep `NEAR_API_KEY` or go keyless (works today)?
4. Scope: only `ownedBy == nearai`? Record Chutes/Tinfoil-routed models as "not a NEAR machine" or leave out?
5. Backfill souk's corpus including logs without a quote, or only quote-bearing captures?
6. Logbook home: souk reading the archive, or a `docs/` page in the observatory?
7. Ask NEAR why `cc796618` is listed twice for GLM?

## 9. Implementation notes (2026-11-24, branch `near-machines`)

- Q2 is still open: the `near-machines` job does not stage `data/near-deployments-seen.json`, and `near_ai.appraise_report` no longer writes it (only `verify` records deployments, as before).
- Follow-up (wanted, deferred): record the Chutes/Tinfoil-routed attested models (`deepseek/deepseek-v3.2`, `moonshotai/kimi-*`, `z-ai/glm-5.3`) as "not a NEAR machine". Run records already list them under `not_nearai` with their `ownedBy`.
- Raw retention: a repeat entry of a machine already archived in full this run drops `nvidia_payload` and the bulky `info`; a repeat compose-manager log (same `actions_hash`) keeps only its quote, `report_data`, nonce and hash. Captures reference the raw document instead of copying quotes. Measured on 11-24: 1.7 MB/day gateway raw (0.4 MB gzipped), 2.4 MB/day while Direct runs.
- Direct entries and backfilled captures get the offline checks only (quote registers, `actions_hash` recomputation, `report_data` binding, same CVM); only live gateway reports go through `appraise_report`. A log counts as `bound` only against a nonce we chose; the 11-22 `fresh/` and `neardirect/` captures carry only an echoed nonce and are archived `bound: false`.
- `actions_missing_within_retention` uses the action's own (host-supplied) timestamp for the 6-day window.
