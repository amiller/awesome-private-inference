#!/usr/bin/env bash
# Devproof watcher (zed cron, every 3h). Replaces near-watch.sh.
# Pull fresh snapshots -> sweep on-chain state -> diffalert. On new findings,
# spawn ONE detached Paseo agent with the delta + playbook; ack state only
# after the spawn succeeds so a failed spawn re-fires next run.
# Usage: devproof-watch.sh [--dry]
set -euo pipefail
# paseo needs node >= 21 (--disable-warning); /usr/bin/node on zed is v20.9.0.
# Without the nvm bin dir first, `paseo` is either missing or dies on startup —
# which silently wedged this watcher from 2026-07-02 to 2026-08-10.
export PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"
command -v paseo >/dev/null || { echo "FATAL: paseo CLI not on PATH; agent spawn impossible"; exit 127; }
cd "$(dirname "$(readlink -f "$0")")/.."
source .venv/bin/activate
STATE="$HOME/.config/devproof-watch.state.json"

# our own sweep dirties generated files under data/ every run; CI also updates them
# daily, so an unrestored copy makes every pull fail (near-watch was stuck on this
# for days). Restore whatever is actually tracked and modified rather than naming
# paths — naming one that isn't in the checkout yet would kill the script here,
# before the pull that would have introduced it.
DIRTY=$(git ls-files -m -- data/)
if [ -n "$DIRTY" ]; then git restore $DIRTY; fi
git pull --ff-only
python -m probes.onchain_sweep || echo "onchain_sweep exit $? (drift is informational; RPC errors above)"

if [ ! -f "$STATE" ]; then
  python -m probes.diffalert --state "$STATE" --ack
  echo "baseline initialized"
  exit 0
fi

set +e
FINDINGS=$(python -m probes.diffalert --state "$STATE")
RC=$?
set -e
if [ "$RC" -eq 0 ]; then echo "no new findings"; exit 0; fi
if [ "$RC" -ne 3 ]; then echo "diffalert failed rc=$RC"; echo "$FINDINGS"; exit "$RC"; fi

echo "$FINDINGS"
if [ "${1:-}" = "--dry" ]; then echo "[dry] would spawn paseo agent"; exit 0; fi

PASEO_HOST=$(cat "$HOME/.config/paseo-host")
paseo run --detach --host "$PASEO_HOST" --provider "${DEVPROOF_PROVIDER:-codex}" --mode full-access \
  --cwd "$PWD" --title "devproof watch $(date +%F)" \
  "You are the devproof audit agent for awesome-private-inference (read README.md and docs/methodology.html for context). The watcher detected these changes since last ack:

$FINDINGS

Playbook by finding type:
- [valid] up->down: re-probe the endpoint yourself (provider keys: source ~/.config/private-inference.env; run python -m probes.collect --providers <slug>). Decide: provider outage vs attestation regression. Check the raw error in data/latest.json.
- [cell] or [digest] changes on near-ai backend_attested / cloud-api image digest: continuity-audit draft. Read data/audits/near-ai_cloud-api.json for the last audited digest and its evidence format. Fetch github.com/nearai/cloud-api and review all commits since that audit for reverts or weakening of inline backend verification (PR #552/#558 baseline: dcap_qvl TDX + RTMR3 replay + GPU NRAS + strict report_data binding). Write a DRAFT ledger entry to data/audits/drafts/<digest>.json in the same schema with audited_by [\"agent-draft\"] and your evidence in notes. Do NOT append to the signed ledger itself — the analyst pair reviews drafts and promotes them.
- [version:tinfoil/<model>]: a new sigstore-tag-bound router/model release. Map the new bundle_digest to its release tag (github.com/tinfoilsh/confidential-<model>: the digest is that tag's tinfoil.hash), diff the source vs the last audited tag in data/audits/tinfoil_<repo>.json. MUNDANE = build/dep-only (Dockerfile, go.mod, config placeholder); SUBSTANTIVE = changes under manager/ (addEnclave, updateModelMeasurements), config.yml repo pins, or the shim path allowlist. Write a DRAFT to data/audits/drafts/tinfoil-<repo>-<digest12>.json as a single audit object in that ledger's schema (bundle_digest, sigstore_measurement, release_tag, audited_by [\"agent-draft\"], signoff \"agent-draft-baseline\"). Do NOT append to the ledger.
- [unaudited-mrtd:chutes/<model>]: a chutes mrtd not in data/audits/chutes_tee.json. Confirm it is in the provider golden set (/servers/tee/measurements). Remember the audit unit is WEAK: mrtd does not cover serve.py (CFSV-excluded). Write a DRAFT to data/audits/drafts/chutes-<mrtd12>.json in that ledger's schema (mrtd, first_seen/last_seen, audited_by [\"agent-draft\"], signoff \"agent-draft-baseline\"). Do NOT append to the ledger.
- [cell] changes elsewhere (prod_os_image, serving_code_attested, ...): explain what changed and whether it is a regression against the provider's page in providers/.
- [anchor-drift]: identify which near-ai CVM the new compose hash belongs to and whether the hermes anchor needs a fresh preimage.
- [stale]: find out why data stopped refreshing (GitHub Actions probe-daily runs? Base RPC?).

Always finish by running ./run-audit.sh (refreshes + publishes the dashboard) and a short brief: what changed, what you concluded, what needs the human analyst."

python -m probes.diffalert --state "$STATE" --ack
