# Reference-value ledgers + coding-agent continuity triage

Goal: (a) maintain per-provider reference values (approved version identities), and
(b) use coding agents to triage each new deploy — auto-classify mundane/continuity
updates so humans only review substantive ones. Today only near-ai has this.

## Reference-value semantics (established)
| provider | identity field | source-of-truth ("the code") | anchor |
|---|---|---|---|
| near-ai | cloud_api_image_digest | nearaidev/cloud-api commits | on-chain DstackApp compose-set + audit ledger |
| tinfoil | ATC bundle `digest` (per model) | tinfoilsh/confidential-<model> release tag | sigstore GH-OIDC (refs/tags) |
| chutes  | mrtd | chutes-api (serve path CFSV-excluded, unmeasured) | provider /servers/tee/measurements golden set |
| redpill | os_image (mutable tag) | — | weak |
| venice  | none | — | unmeasurable |

## Phase 1 — Wire near-ai verifier (immediate)
- [ ] Set NEARAI_VERIFIER_PATH -> _nearai-verifier/py, re-capture today's near-ai digest
- [ ] Make it durable (not just this shell)

## Phase 2 — Generalize ledger infra
- [ ] Extract the near-ai-only audit-ledger logic into a provider-agnostic module
- [ ] drafts/ convention usable per provider

## Phase 3 — Continuity triage on pending updates (agent-draft)
- [ ] near-ai: refresh c427… draft to today's live digest + commits through today
- [ ] tinfoil/router: baseline + draft for new digest 7299507cca23…
- [ ] Recommend promote/reject (human/analyst-pair does final ledger append)

## Phase 4 — Extend ledgers to chutes + tinfoil
- [ ] data/audits/tinfoil_<repo>.json + data/audits/chutes_tee.json baselines
- [ ] Wire into quality.py backend/serving-code cell

## Review — done 2026-09-02
- Phase 1: near_ai.py now defaults NEARAI_VERIFIER_PATH to in-repo _nearai-verifier/py
  (no env needed). near-ai re-captured; new digest 455d25f3… today.
- Phase 2: load_audit_ledger()/audit_match() lifted into common.py; near_ai delegates
  (behavior identical, verified). Tests green (34 passed).
- Phase 3: agent-draft continuity triage produced two drafts (await human promotion):
    * near-ai 455d25f3… → MUNDANE (inline PR552/558 chain intact; all touching PRs
      continuity/stricter). Flagged chain_authorized=FALSE as STALE data → refreshed
      onchain_sweep → compose 9b15afa6… now confirmed anchored (True). Resolved.
    * tinfoil router 7299…→ mapped DEFINITIVELY to v0.0.142 (digest==tinfoil.hash);
      baseline SOUND (backends re-attested w/ Measurement.Equals + repo-pin). Watch:
      manager/, config.yml pins, and the v0.15.3 sev-guest fork swap.
- Phase 4: data/audits/chutes_tee.json + tinfoil_confidential-model-router.json created;
  chutes.py sets mrtd_audited, tinfoil.py sets digest_audited (per-repo, None if no
  ledger). diffalert emits version:tinfoil/<model> (control-plane, every deploy) and
  unaudited-mrtd:chutes/<model> (only mrtd NOT in ledger — quiet on the known flip-flop).

## Pending (human/next)
- Promote drafts into ledgers after analyst signoff (drafts stay in data/audits/drafts/).
- redpill down (502) + tinfoil non-router models unreachable at refresh time.
- Codify the agent-draft triage prompt as a repeatable job wired to diffalert findings.
- Give other tinfoil model repos their own ledgers as they're audited.
