# Contributing

## Add a route or reference source

1. Add a candidate with category, primary sources, inclusion reason, owner/blocker and next review date to `data/candidates.json`.
2. Add client/request-path cards to `data/routes.json`. Identify plaintext holders, shared components, published references, client acceptance policy and unmeasured inputs. A brand is not an independent inference stack.
3. Implement a bounded publication capture in `probes/references.py` or a verifier adapter in `verifiers/`. Preserve evidence needed to replay each claimed check. Never store authorization headers, private API keys or prompts.
4. Use `not_checked`, `unsupported`, `unavailable` and `rejected` accurately. A fetched manifest or nonce echo is not verified hardware evidence. Signed build provenance is not an independent rebuild.
5. Add controls that alter each security-relevant binding independently. Show that known-good evidence is handled and a missing proof cannot become a pass. Source-to-image reproduction that needs heavy builds belongs on zed.
6. Open a focused PR with exact source revisions, performed checks, unresolved boundaries and rollout evidence. An incomplete route can be included as a candidate; it cannot be labeled fully verified.

## Review a change

Follow [the review workflow](docs/REVIEW-WORKFLOW.md). Jobs refer to immutable observations and exact old/new identities. Agents produce drafts; a separate reviewer publishes a disposition. Neither step silently expands a client allowlist.

Keep historical observations and retired integrations. Distinguish policy changes, key rotation, fleet sampling and newly observed software identities. Do not infer deployment counts from a daily hash series.

Use the locked environment and pinned external verifier. Retain logs, raw public evidence and results; remove temporary installs/build outputs after rehearsals. Keep at most one live install per rehearsal.
