# GLM lane `ledger` — report for 2026-11-05 run

Issues: #5 (implemented), #3 (verified, proposed closing comment below),
#2 (README bullet, separate commit). Spec: `docs/tasks/glm-ledger-20261105.md`.

## Milestone 1 — issue #5: full-length ledger keys, exact match only

Commit `9948318`. Files changed:

- `verifiers/common.py` — `load_audit_ledger(path, key_field, key_length=64)`:
  a key must be exactly `key_length` lowercase hex chars after lowering, else
  `ValueError`. `audit_match(value, audit_set)`: exact case-insensitive
  membership; prefixes never match.
- `verifiers/near_ai.py` — `_cloud_api_audit_set()` unchanged call (default 64);
  the `full_audit_key`/`audit_key` dual path collapsed: a match is now by
  construction a full-digest match, so `audit_match_scope` is `full_digest` or
  `none` (`legacy_prefix_hint` is unreachable and removed).
  `gateway_reference_audited` still requires self-consistency + chain
  authorization + full-digest ledger membership.
- `verifiers/chutes.py` — `load_audit_ledger(_TEE_AUDITS, "mrtd", key_length=96)`
  (MRTD is `body[136:184]`, 48 bytes).
- `verifiers/tinfoil.py` — `_digest_audited` uses `audit_match` on a loader that
  already rejects truncated keys; the old `{entry for entry in audit_set if
  len(entry) == 64}` filter was redundant with the new invariant and removed.
- `probes/quality.py` — `AUDIT_LEDGERS` values now carry the key length
  (near-ai 64, tinfoil 64, chutes 96).
- `data/audits/near-ai_cloud-api.json` — row `22763fe4` (8 hex, the only
  truncated key in any ledger; chutes keys are 96 hex, tinfoil 64 hex) moved to
  a new `legacy_audits` section with `legacy_audits_note`, retained verbatim for
  history. The loader reads only `audits`, so the row can no longer authorize
  anything. Backfill was impossible: `grep 22763fe4 data/snapshots data/observations`
  returns no match (verified this session; the row's own notes say the full
  digest was never captured).
- Tests: `tests/test_common.py` flipped from asserting prefix matching to
  asserting rejection (see controls); `tests/test_tinfoil.py::test_prefix_only_
  legacy_ledger_does_not_authorize_digest` renamed to `..._is_rejected` and now
  asserts `ValueError` — assertion changed because reject-at-load *is* the #5
  behaviour change (previously the adapter silently filtered prefix entries);
  `tests/test_chutes_evidence.py` mock lambda now accepts the `key_length` kwarg.

### Success criteria vs tests (all in `tests/test_common.py` unless noted)

| Criterion | Proof |
|---|---|
| `audit_match` exact equality only | `test_audit_match_exact_and_case` |
| Loader rejects truncated/non-hex keys | `test_load_audit_ledger_rejects_short_or_nonhex_key` (includes `22763fe4`, 63-hex, 65-hex, non-hex) |
| Per-ledger lengths (64/64/96) | `test_load_audit_ledger_enforces_declared_key_length`; `test_repo_ledgers_hold_only_full_length_keys` |
| `22763fe4` retired, unmatched, history kept | `test_repo_ledgers_hold_only_full_length_keys` asserts it is absent from ids/meta and that `22763fe4 + 56 hex` does not match the shipped ledger |
| All ledgers checked for truncation | same test loads all three real ledgers; `data/audits/` contains no other ledgers |

### Negative controls and results

- `22763fe4` (8 hex) — previously *accepted* by the old `>= 8` rule — now
  `ValueError`. Passes; would fail on the old code.
- 63-hex / 65-hex / non-hex keys → `ValueError`. Pass.
- 64-hex key under `key_length=96` → `ValueError`; real chutes ledger (96-hex
  keys) loads. Pass.
- Tamper: one hex char of a real near-ai ledger digest mutated → no match. Pass.
- Prefix forgery: `22763fe4` + 28 bytes vs the shipped ledger → no match (the
  legacy section is not loaded). Pass. Under the old code this exact case
  matched — that was the vulnerability.
- `audit_match(full + "aa")` and `audit_match(full[:-1])` → `None`; the old
  startswith code returned a match for the first. Pass.
- Behaviour cross-check: `python -m probes.quality` reports identical audit
  debt (7/100 reviewed, backlog 93, last audit 2026-09-02) before/after — no
  observed digest relied on the retired prefix, so the fix changed no published
  number. (Recomputed from `data/snapshots/` + ledger this session: near-ai
  33 observed / 4 reviewed.)

### Honest validation status

All controls run against retained real evidence (`data/audits/*.json`,
`data/snapshots/`); no mocks except the pre-existing chutes transport/ledger
monkeypatch. No live provider request was made or needed. The near-ai vendor
verifier (`_nearai-verifier`) is not installed here, so `verify()` itself was
not exercised live; the audit-gating logic it shares is covered by the unit
tests above.

## Milestone 2 — issue #2: README "Known limitations"

Commit `60c941a`. Adds a "Known limitations" section after "Verification scope"
with one bullet: TEE.fail (IEEE S&P '26, read from https://tee.fail/ on
2026-11-05) extracted keys from Intel TDX / AMD SEV-SNP via a cheap DDR5
memory-bus interposer — including attestation keys from fully patched hosts in
trusted status, which also unlocks Nvidia GPU CC — so this registry's
attestation verification assumes the hardware root of trust is sound.

## Issue #3 — verification result (no code changed)

Everything below was read on this branch at commit `9948318^..60c941a`.

### Proposed closing comment

> **Resolution: fixed on current main by 79fff1b (2026-10-13, "Reframe private
> inference monitoring around reference consistency"). The ack-on-spawn rule is
> gone.** Point-by-point:
>
> 1. **"`watch/devproof-watch.sh` runs `diffalert --ack` immediately after the
>    `paseo run` command returns"** — no longer true. The script contains no
>    diffalert invocation at all; `watch/devproof-watch.sh:3` states "Legacy
>    diffalert acknowledgments are intentionally not consumed or updated."
>    `probes/diffalert.py:29` still exposes an `--ack` flag but nothing on main
>    calls it.
> 2. **"Acks on spawn, not completion"** — replaced by an explicit lease model.
>    `probes/review_queue.py:1` "Launch is a lease, never an acknowledgment";
>    `claim()` (`:108-126`) stamps `lease_until`/`lease_token`, expires stale
>    leases to `retryable_failure` (`:114-116`), and only a *validated* draft
>    (`submit()`, `:149-167`), a *distinct* reviewer (`review()`, `:188-193`)
>    and `publish()` (`:195-205`) can close a job. `probes/review_worker.py:1-4`
>    ("neither dispatch nor a prose 'done' closes a job") and the packet prompt
>    (`:40` "Do not amend the event packet or treat launch as completion")
>    enforce the same rule on the agent side; a dispatcher crash or lease expiry
>    is recorded as a retryable failure (`review_worker.py:77-86`), never an ack.
>    This is stronger than the rule proposed in this issue — nothing ever
>    auto-acks; the `method`/`prev_digest`/`verifier_surface_changed` gating
>    idea is tracked separately as #4 and is out of scope here.
> 3. **"Ledger last appended 2026-06-18 (53 days)"** — superseded. Two rows were
>    appended 2026-09-02 (promoted from agent drafts,
>    `data/audits/near-ai_cloud-api.json` rows 3-4). The current gap
>    (2026-09-02 → 2026-11-05) is real but is now *measured in public* as audit
>    debt by `probes/quality.py` (`data/quality.json`:
>    `by_provider.near-ai.backlog = 29`, `days_since_last_audit`), not hidden
>    behind an ack.
> 4. **"`data/audits/drafts/` has never existed"** — was true of the old design
>    (the pre-October playbook referenced it; see commits 9ddc856/41a2803), and
>    the directory still does not exist, but current main no longer references
>    `data/audits/drafts` anywhere. Drafts are now validated queue artifacts
>    under ignored `local-data/review-queue/` (`review_worker.py:68-70` writes
>    `<event>-<attempt>.json` packets; drafts are submitted via
>    `probes.review_queue submit`), documented in `docs/REVIEW-WORKFLOW.md:20-43`.
> 5. **"19 distinct digests observed; 2 covered; backlog 17"** — numbers have
>    moved and are tracked, not frozen: recomputed today from
>    `data/snapshots/` + the ledger: **33 observed / 4 reviewed / backlog 29**
>    (matches `data/quality.json`). Review throughput remains the open work, but
>    it is visible backlog, not an ack-rule failure.
> 6. **"Spawn failing since 2026-07-02 (`paseo: command not found`)"** — fixed
>    in c921392 (2026-08-10, "watch: fix PATH so the paseo spawn works again");
>    today `watch/devproof-watch.sh:5` exports the node PATH and `:26` fails
>    fast (`command -v paseo`) before doing anything, so a missing binary is a
>    loud failure, not a silent one.
> 7. **"The watcher has no watcher"** — addressed for collection and the review
>    queue: `.github/workflows/observation-health.yml` runs `python -m
>    probes.health` every 6h independently of the probe workflow, and
>    `probes/health.py` exits 1 (CI failure → notification) on
>    `stale_collection` (>26h, `:29-30`), `stale_route` (`:35-36`),
>    `stale_review_heartbeat` (>4h, `:39-40`), `expired_review_lease`
>    (`:42-45`), `reference_capture_unhealthy` (`:50-53`) and
>    `reference_mirror_mismatch` (`:54-56`). One gap honestly remains, already
>    documented in `docs/REVIEW-WORKFLOW.md:55-59`: the GitHub workflow does not
>    pass `--queue-status` (queue state lives in ignored `local-data/` on zed),
>    so lease/heartbeat findings fire only when health runs zed-side with
>    `--queue-status local-data/review-queue/status.json` (the watch script
>    writes that status each run, `devproof-watch.sh:30`), and no external
>    chat/email page is sent by these scripts. That residual zed-side
>    monitoring gap is worth its own follow-up, not a reason to keep this issue
>    open.
>
> Closing this as fixed; the auto-ack policy proposal lives in #4.

I verified each file:line cited above by reading the files on this branch this
session; the historical claims (what the old script did, when PATH was fixed,
when the reframe landed) come from `git log`/`git show` of those commits, also
this session. No assertion here relies on the issue's own numbers.

## Full suite

`~/.local/bin/uv run --extra dev --extra nearai pytest -q` → **154 passed**
after both commits, clean tree.

## Blockers

None for #5, #3 (verification-only) and #2. Not attempted (out of scope):
implementing #4's auto-ack rule; #3 explicitly must not include it.
