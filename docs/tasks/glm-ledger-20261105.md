# GLM lane `ledger` — 2026-11-05

Issues: #5 (audit ledger prefix matching), #3 (watcher ack-on-spawn — verification
only), plus a README "Known limitations" bullet for tee.fail (#2, separate commit).

## Issue #5 — success criteria and how each is met

1. **`verifiers/common.py:audit_match` matches by exact equality only.**
   `load_audit_ledger` gains a `key_length` parameter (default 64). `audit_match`
   returns the key only when the lowercased live value equals a ledger key.
2. **`load_audit_ledger` rejects truncated or non-hex keys with `ValueError`.**
   A key must be exactly `key_length` lowercase hex chars after lowering. Any
   other length (shorter *or* longer) or non-hex content raises.
3. **Per-ledger full lengths:** 64 hex for image digests (near-ai) and bundle
   digests (tinfoil); 96 hex for chutes MRTD (48 bytes, `chutes.py` parses
   `body[136:184]`). Chutes and tinfoil call sites pass their length; near-ai
   uses the default.
4. **`tests/test_common.py` flipped:** the test that asserted prefix matching
   (`audit_match("22763fe4aabbccddeeff") == "22763fe4"`) now asserts that such a
   ledger is rejected at load and that a value beginning with a retired legacy
   prefix does not match.
5. **Ledger row `22763fe4` moved to a clearly labelled legacy section** the
   loader never reads (`legacy_audits` in `data/audits/near-ai_cloud-api.json`),
   retained for history. Cannot be backfilled: grep of `data/snapshots/` and
   `data/observations/` for `22763fe4` returns no match (verified this session;
   the only occurrence in the repo is the ledger row itself).
6. **Every ledger under `data/audits/` checked for other truncated keys.**
   near-ai: exactly one truncated row (`22763fe4`). chutes: both keys 96 hex.
   tinfoil: single key 64 hex. No other ledgers exist (`data/audits/drafts/` does
   not exist and is not referenced on current main).
7. **All callers updated** (`verifiers/near_ai.py`, `verifiers/chutes.py`,
   `verifiers/tinfoil.py`, `probes/quality.py`) and the full suite passes.

## Negative controls (each pass must fail on tampered input)

- `22763fe4` (8 hex, previously *accepted*) → `ValueError` at load.
- 63-hex and 65-hex keys, non-hex keys → `ValueError`.
- Chutes: a 64-hex key under `key_length=96` → `ValueError`; the real chutes
  ledger loads at 96.
- Tamper: a real near-ai ledger digest with one hex character mutated →
  `audit_match` returns `None` (tested against the real ledger in
  `data/audits/`).
- Prefix forgery: a live digest equal to `22763fe4` + 28 more bytes → no match
  against the shipped ledger (legacy section not loaded).
- tinfoil: `tests/test_tinfoil.py::test_prefix_only_legacy_ledger_does_not_authorize_digest`
  changes assertion from `is False` to `pytest.raises(ValueError)` — the
  behaviour change (reject instead of silently filter) is the point of #5.
  Reason recorded here per working rules.

## Issue #3 — verification only (no implementation)

Confirm or refute each point with file:line and write the result in the report
as a proposed closing comment. The proposed `method`/`prev_digest`/
`verifier_surface_changed` auto-ack rule is **not** implemented (belongs to #4).

## Issue #2 — README "Known limitations" bullet (separate commit)

One or two factual sentences from https://tee.fail/ (read 2026-11-05) plus the
statement that attestation verification in this registry assumes the hardware
root of trust is sound.

## Blockers

None expected. Live provider verification is not needed: all controls run on
the retained ledger/snapshot evidence in the repo.
