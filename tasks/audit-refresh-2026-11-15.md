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
- [ ] Merge lanes in order ledger → misc → chutes → tinfoil → aci → dstack → venice → gcpfw → rubric, with review fixes; full pytest after each
- [ ] Merge A2

## Phase C
- [ ] Pass 1/2: retained Session tests per route from teep captures + our probes; dated cell updates in routes.json
- [ ] Pass 3: NEAR cloud instance enumeration in near_ai.py
- [ ] Pass 4: operator-access review per provider (teep audit-prompt structure)
- [ ] Pass 5: export observed measurements; parity table refresh
- [ ] Beat digest: teep change → parity row step

## Review
- ledger merged + fixes (af14d1b); chutes merged after fix agent (signed NRAS, TCB gate, hermetic replay).
- teep captures: zed /data/amiller/teep-refresh-20261115 (run.sh, SUMMARY.md). Venice key 401s on chat (Andrew).
- Pending: tinfoil, dstack+aci, misc+rubric-CI, gcpfw fixes; venice re-base after chutes+dstack; then refresh/rubric merge.
- Open: #3 closing note to rewrite (closes ack-on-spawn only); Session split doubled finding counts for no-channel routes; old #…-session anchors break.
