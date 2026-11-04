# Daily Beat discussion monitoring

The existing zed cron still invokes `watch/beat-digest.sh` at 08:30 Central.
The discussion collector is a preflight in that same job, not a second schedule.

`thread-watchlist.json` lists dated discussion leads. Add a public repository,
issue/PR number and a short context note when a finding needs continuing attention.
An old merged or closed thread can still receive important replies. Context is
not a current deployment claim. Discovery also searches involvement by amiller,
13rac1 and mikeperry-tor in the named provider organizations; newly discovered
threads are candidates to inspect, not automatically news or watchlist entries.

`thread_activity.py` uses read-only GitHub GETs through the existing `gh`
authentication. It collects paginated issue comments/status events and PR reviews
and inline replies, including edits to old comments. Every run retains a new
JSON file under the archive's `evidence/`; errors and search truncation mark
coverage incomplete. The digest compares stable IDs, revisions and meaning with
the last seven live digests to suppress the overlapping 26-hour window.

Keep acknowledgment, proposal, review approval, merge, release and deployment
confirmation distinct. Attribute deployment claims to their author and scope;
do not infer runtime verification or new client policy acceptance. An unknown
commenter's participation does not establish provider affiliation. If a source
cannot be checked, report the observer coverage gap rather than a provider fault.

## Validation

```sh
python3 -m unittest discover -s watch -p test_thread_activity.py -v
bash -n watch/beat-digest.sh
bash watch/beat-digest.sh --dry
```

The dry command does make public GitHub reads and use the existing Opus model.
It writes to a unique `~/.local/share/beat-digest/dry/<run-id>/` directory, reads
last-seven history from the live archive and receives pre-collected repository
and discussion evidence. Empty strict MCP configuration, a base tool list with
no Bash, and explicit dontAsk execution remove router and shell posting tools.
The permission mode denies requests requiring approval. `--restricted` is not used:
it prevents the installed CLI from refreshing its existing OAuth credentials;
no-shell isolation is provided by the explicit base tool inventory instead. This is not a general
filesystem sandbox: read/write tools can access the allowed working directories.
Dry rehearsal never authorizes publication. The live invocation preserves the
existing router configuration and publication tools. Do not replay a live job
just to validate monitoring; it may publish a duplicate daily entry.

These scripts do not update observatory assessment data, trust roots, accepted
reference values or client policies.

## TEE Platform Beat (variant)

`BEAT=tee-beat watch/beat-digest.sh` runs the same job with `watch/tee-beat.md`.
It writes its history to `~/.local/share/tee-beat/` and its public digests to
`watch/tee-beat/`. A prompt containing `{{FIRMWARE}}` triggers
`watch/firmware_endorsements.py`, which snapshots Google's public `gce_tcb_integrity`
bucket into `~/.local/share/tee-beat/gce-tcb/` and diffs against the previous
snapshot. A dry run diffs against a copy and does not advance the live snapshot.
