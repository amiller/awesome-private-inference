#!/usr/bin/env bash
# Existing daily Beat job. --dry collects public evidence and writes only under dry/;
# it receives no router MCP servers or posting tools. Live publication is unchanged.
set -euo pipefail
export PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$HOME/.local/bin:$PATH"
cd "$(dirname "$(readlink -f "$0")")/.."
case "${1:-}" in
  "") MODE=live ;;
  --dry) MODE=dry ;;
  *) echo "usage: [BEAT=name] beat-digest.sh [--dry]" >&2; exit 2 ;;
esac
BEAT="${BEAT:-beat-digest}"
PROMPT="watch/$BEAT.md"
PUB=watch/beat
[ "$BEAT" = beat-digest ] || PUB="watch/$BEAT"
HISTORY="$HOME/.local/share/$BEAT"
ARCHIVE="$HISTORY"
MCP="$HOME/.config/beat-digest/mcp.json"
DATE=$(date +%F)
RUN_ID="$(date -u +%Y%m%dT%H%M%S)-$$"
if [ "$MODE" = dry ]; then
  # Isolate each dry rehearsal, including its evidence, from live history.
  ARCHIVE="$HISTORY/dry/${RUN_ID}"
fi
mkdir -p "$ARCHIVE"
git pull --ff-only -q
THREAD_ACTIVITY="$ARCHIVE/evidence/$RUN_ID-thread-activity.json"
python3 watch/thread_activity.py --output "$THREAD_ACTIVITY"
FIRMWARE="$ARCHIVE/evidence/$RUN_ID-firmware.txt"
COMMIT=("$PUB/$DATE.md" notes/teep-parity.md)
if grep -q '{{FIRMWARE}}' "$PROMPT"; then
  SNAPS="$HISTORY/gce-tcb"
  GCE_HISTORY=data/gce-tcb-endorsements.json
  if [ "$MODE" = dry ]; then
    # Dry runs diff against copies of the live snapshot and history without advancing them.
    mkdir -p "$ARCHIVE/gce-tcb" "$ARCHIVE/gce-tcb-history"
    cp "$(ls "$SNAPS"/gce-tcb-*.json | tail -1)" "$ARCHIVE/gce-tcb/"
    cp "$GCE_HISTORY" "$ARCHIVE/gce-tcb-history/"
    SNAPS="$ARCHIVE/gce-tcb"
    GCE_HISTORY="$ARCHIVE/gce-tcb-history/gce-tcb-endorsements.json"
  else
    COMMIT+=(data/gce-tcb-endorsements.json data/gce-tcb-intel-rims)
  fi
  uv run --locked python watch/firmware_endorsements.py --snapshots "$SNAPS" --history "$GCE_HISTORY" --output "$FIRMWARE"
fi
# Dry mode has no shell tool; retain bounded repository evidence before the agent.
REFERENCE_ACTIVITY="$ARCHIVE/evidence/$RUN_ID-reference-activity.txt"
python3 - "$REFERENCE_ACTIVITY" <<'PYTHON'
import datetime, json, pathlib, subprocess, sys
since = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=26)).strftime("%Y-%m-%dT%H:%M:%S")
events = [e for e in json.loads(pathlib.Path("docs/reference-values.json").read_text())["events"] if e["at"] >= since]
fields = ("at", "provider", "lane", "kind", "old", "new", "added", "removed", "scope", "code_delta", "text_delta", "evidence", "id")
stat = subprocess.run(["git", "log", "--since=26 hours ago", "--stat"], capture_output=True, text=True, check=True).stdout
with pathlib.Path(sys.argv[1]).open("w") as out:
    out.write(f"REFERENCE-VALUE EVENTS with at >= {since}Z ({len(events)}), from docs/reference-values.json:\n")
    for e in events:
        out.write(json.dumps({k: e[k] for k in fields if e.get(k) not in (None, [], "")})[:4000] + "\n")
    out.write("\nCOMMAND: git log --since=26 hours ago --stat\n" + stat[:100000])
    if len(stat) > 100000:
        out.write("\nTRUNCATED at 100000 characters.\n")
PYTHON
# X posts (tee_inference, private_inference) pushed hourly from Andrew's laptop browser collector.
X_POSTS="$ARCHIVE/evidence/$RUN_ID-x-posts.txt"
python3 - "$X_POSTS" <<'PYTHON'
import datetime, json, pathlib, sys
rows = {r["id"]: r for f in sorted((pathlib.Path.home() / ".local/share/beat-x").glob("*.json")) for r in json.loads(f.read_text())}
since = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=26)).strftime("%Y-%m-%dT%H:%M:%S")
recent = sorted((r for r in rows.values() if r["created_utc"] >= since), key=lambda r: r["created_utc"])
with pathlib.Path(sys.argv[1]).open("w") as out:
    out.write(f"X POSTS created >= {since}Z ({len(recent)}), from searches tee_inference and private_inference. "
              f"Newest post collected: {max(r['created_utc'] for r in rows.values())}. Columns: created | likes | replies | link | text\n")
    for r in recent:
        out.write(f"{r['created_utc']} | {r['score']} | {r['num_comments']} | https://x.com/i/status/{r['id']} | {r['title'][:300]}\n")
PYTHON
BASE_TOOLS="Read,Write,Glob,Grep,WebSearch,WebFetch"
TOOLS="$BASE_TOOLS"
MODE_FLAGS=()
if [ "$MODE" = dry ]; then
  # A fresh empty MCP configuration makes posting unavailable, not just forbidden.
  MODE_FLAGS=(--permission-mode dontAsk --permission-prompts none)
  MCP="$ARCHIVE/no-post-mcp.json"
  printf '{"mcpServers":{}}\n' > "$MCP"
  PUBLISH_INSTRUCTION="DRY RUN: write the digest, but skip step B entirely. Do not post, sync or send messages. No router or Bash tools are available. Use the pre-collected GitHub evidence and public WebFetch/WebSearch; label any source you cannot inspect as a dry-run coverage gap."
else
  BASE_TOOLS="$BASE_TOOLS,Bash"
  TOOLS="$TOOLS,Bash(gh:*),Bash(git log:*),Bash(git show:*),Bash(git diff:*),Bash(jq:*),Bash(ls:*),mcp__shaperotator__router_write,mcp__public__router_write_entry"
  PUBLISH_INSTRUCTION="LIVE RUN: follow the publication instructions below."
fi
# --tools restricts the base tool inventory as well as the approval allowlist;
# no generic network shell or MCP discovery tools are exposed by the dry runner.
python3 - "$DATE" "$ARCHIVE" "$HISTORY" "$MODE" "$THREAD_ACTIVITY" "$REFERENCE_ACTIVITY" "$FIRMWARE" "$X_POSTS" "$PUBLISH_INSTRUCTION" "$PROMPT" <<'PYTHON' |
import pathlib, sys
text = pathlib.Path(sys.argv[-1]).read_text()
for key, value in zip(["DATE", "ARCHIVE", "HISTORY", "MODE", "THREAD_ACTIVITY", "REFERENCE_ACTIVITY", "FIRMWARE", "X_POSTS", "PUBLISH_INSTRUCTION"], sys.argv[1:-1]):
    text = text.replace("{{" + key + "}}", value)
print(text)
PYTHON
  claude -p --model opus --mcp-config "$MCP" --strict-mcp-config \
    --tools "$BASE_TOOLS" "${MODE_FLAGS[@]}" \
    --allowedTools "$TOOLS" --add-dir "$ARCHIVE" --add-dir "$HISTORY"
test -s "$ARCHIVE/$DATE.md"
if [ "$MODE" = live ]; then
  # Public archive in this repo: the script commits only the new digest and firmware history, never the agent.
  mkdir -p "$PUB"
  cp "$ARCHIVE/$DATE.md" "$PUB/$DATE.md"
  git add "${COMMIT[@]}"
  git diff --cached --quiet || git commit -q -m "${PUB#watch/}: $DATE digest" -- "${COMMIT[@]}"
  git pull --rebase -q
  git push -q
fi
