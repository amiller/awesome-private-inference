# Audit refresh — 2026-11-15

Roadmap: `notes/roadmap-audit-refresh-2026-11-15.md` (laptop checkout). Branch `refresh/2026-11-15` off origin/main 6f440f3,
worktree `.worktrees/refresh`. No push; Andrew pushes.

Decisions (Andrew, 2026-11-15): split Session into Recipient key / Reply key + freshness; collapse the 9 no-adapter
routes to one "not assessed" cell; run teep on zed (keys already in zed `~/.config/private-inference.env`); local branches only.

## Phase A (parallel)
- [x] A1 Pass 0: review the 9 GLM lanes (`refs/remotes/lanes/*`) against their issues: tinfoil, chutes+venice, aci+dstack, misc+ledger+rubric+gcpfw
- [x] A2 Rubric: split Session, collapse no-adapter routes (branch `refresh/rubric`)
- [x] A3 teep on zed: build @6548996, capture `teep verify` per provider, retain reports + raw

## Phase B
- [x] Merge lanes in order ledger → misc → chutes → tinfoil → aci → dstack → venice → gcpfw → rubric, with review fixes; full pytest after each
- [x] Merge A2

## Phase C
- [ ] Pass 1/2: retained Session tests per route from teep captures + our probes; dated cell updates in routes.json
- [x] Pass 3: NEAR cloud instance enumeration in near_ai.py
- [ ] Pass 4: operator-access review per provider (teep audit-prompt structure)
- [x] Pass 5: export observed measurements; parity table refresh
- [x] Beat digest: teep change → parity row step

## Review
- ledger merged + fixes (af14d1b); chutes merged after fix agent (signed NRAS, TCB gate, hermetic replay).
- teep captures: zed /data/amiller/teep-refresh-20261115 (run.sh, SUMMARY.md). Venice key 401s on chat (Andrew).
- Pending: tinfoil, dstack+aci, misc+rubric-CI, gcpfw fixes; venice re-base after chutes+dstack; then refresh/rubric merge.
- Open: #3 closing note to rewrite (closes ack-on-spawn only); Session split doubled finding counts for no-channel routes; old #…-session anchors break.
- 2026-11-15 all lanes merged (venice re-based); NEAR every-instance; parity table + beat step; Tinfoil note.
- Live collect on branch (pinned NEAR verifier), 3/16 valid: ACI tee.redpill.ai + inference.phala.com pass; api.redpill.ai fails attested serving;
  NEAR ×2 reject on compose anchor (hermes anchor lacks glm-5.3-flash/Qwen3.8-27B — Andrew's branch); Tinfoil rejects TCB snp 0x17<0x1d;
  Venice ACI/1 ×2 reject gateway-only, gemma 404, legacy qwen passes; Chutes ×5 reject (serving code unmeasured; gemma also gpu_count 1 vs row 8 — open: is row gpu_count per node?).
  Snapshot kept at scratchpad live-snapshot-2026-11-15.json, not committed.
