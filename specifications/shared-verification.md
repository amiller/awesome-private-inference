# Shared verification and reference observations · v1

Private Inference Beat has three outputs: a curated verifier directory, retained
reference-value observations, and route assessments with proposed stage criteria.
The repository remains `awesome-private-inference`.

## Outputs and regeneration

`python -m probes.render` regenerates the static site and two JSON files offline:

- `docs/verifiers.json` copies the curated `data/verifiers.json` directory.
  Each provider has route IDs, implementation locations, a directory review date,
  delegated trust, missing checks and evidence pinned to `source_revision`.
  An upstream lead can be useful without a repository adapter or live proof.
- `docs/reference-values.json` has `schema_version: 1` and
  `kind: "reference-observations"`. It projects the same evidence as Reference
  history, retaining full values, context, dated changes and scoped review records.

The public files are available beside `index.html` on GitHub Pages. They are
observation/discovery inputs, not signed acceptance manifests or stable adapter
APIs. A schema change requires a version bump and consumer review. Do not flatten
all extracted values into one allowlist.

### Reference export fields

| Field | Meaning |
| --- | --- |
| `first_observed_at`, `last_observed_at` | Extent of retained evidence, not export freshness or deployment dates. |
| `surfaces[].id` | Context key including provider, component, field and evidence family. |
| `provider`, `component`, `field`, `family`, `routes` | Identity context and inventory associations. An association is not request-path proof. |
| `latest`, `last`, `evidence`, `scope` | Last retained sample's exact extracted values, capture time, repository evidence path and verification limits. `latest` does not mean currently deployed or accepted. |
| `first`, `samples`, `sample_days`, `changes`, `events` | Sampling/history metadata; missing samples do not prove retirement or stability. |
| `provider_authorization`, `client_acceptance` | `null`: not established by this export. It does not project an on-chain query or a client-policy review into an approval. |
| `events[]` | Exact old/new sets, additions/removals, observation times, evidence and scoped review matches. `new set` means newly observed. |
| `reviews[]` | Dated historical ledger records. Their verdicts have their original scope and do not grant client acceptance or a Beat stage. |
| `evidence_base` | Repository URL prefix for evidence paths. Consumers needing reproducibility must pin a repository commit and verify retained bytes/digests. |

Values preserve the history extractor's syntax. A published JSON reference entry
can include a JSON path, while a workload measurement can be a bare hex value or
an image tag. No common hash algorithm or authentication status is implied.
`document SHA-256` hashes captured bytes; `reference entries` extracts digest-shaped
JSON entries and preserves field paths. A document digest is not a workload
measurement. Consult the underlying platform field before selecting an algorithm.

For example, NEAR gateway image identity, Chutes base-image MRTD and Tinfoil
router release digest name different things with different proof coverage. A
rejected or historical adapter report can still contain extracted fields; its
`scope` does not authenticate them. A provider with no matching surface has
**no observation**, rather than an empty approved set. All inventory providers
are listed in `inventory_providers` so consumers can represent that absence.

## Existing shared routines

`verifiers.common.AttestationReport` and `ScoreCard` carry scoped adapter results.
Most adapters expose `verify(api_key, base_url, model)`; the NEAR lightclient uses
keyword arguments and returns diagnostic details instead. Directory entries name
these differences. Adapters can perform network requests and use external
appraisal services; they are not all portable, offline cryptographic primitives.
The observation instrument's external dependency revision is pinned in
`data/instrument.json` and Python dependencies in `uv.lock`.

Keep three operations distinct:

1. Authenticate evidence: vendor chain, signature, TCB/debug policy, freshness and
   key/session bindings. A detached field or `valid` flag is insufficient.
2. Compare authenticated identities with expected values for the exact route,
   component, model and client mode.
3. Apply the client's own authenticated, versioned acceptance policy. Decide
   update, expiry, revocation and rollback behavior before releasing protected data.

`has_required_check_coverage` only reports adapter check coverage. The legacy
`is_stage1_ready` name remains as a compatibility wrapper with the same behavior;
its return value cannot award a stage.

## Abalone and multi-provider gateways

This is a consumption contract and foundation for shared routines. This PR does
not integrate Abalone, change its allowlists or ship a universal verifier SDK.
An integration should pin the directory/export schema and repository revision,
choose a reviewed adapter, and separately provision an authenticated acceptance
policy whose authority and revision are visible to the user.

A downstream decision should follow this sequence (pseudocode):

```text
record = find_observation(provider, route, component, reference_kind)
if record is absent:
    return NO_OBSERVATION

quote = authenticate_fresh_session_evidence(actual_connection)
# Also bind requested model, recipient key, reply key and every required hop.
identity = extract_authenticated_identity(quote, component, reference_kind)
policy = load_authenticated_client_policy(policy_authority, policy_revision)
if not policy.permits(route, client_mode, model, component, identity):
    return POLICY_MISMATCH_REQUIRES_REVIEW
return continue_only_if_all_other_route_obligations_pass()
```

Suppose the retained history changes from measurement A to B and the client policy
still permits A. B remains a policy mismatch even if the provider authorizes it,
an analyst reviews it, or it appears in the newest export. Only an explicit
policy update by the configured authority can authorize B. Conversely, an approved
value still needs fresh hardware/session evidence; a matching historical digest
cannot authorize sending a prompt.

## Stages and transparency limits

The [stage criteria proposal](../docs/stages.html) is draft-1. No stages are awarded
by this release. Current route assessments remain separately versioned in
`data/assessments/routes.json`, with dated source evidence and six obligations.
Future stage records must include the rubric version, endpoint/client/mode/model,
protected fields, workload/policy revisions, reviewer/date, scoped proof records,
negative controls and every unmet or unknown obligation.

Publication, provider authorization, review and client acceptance are independent
facts, not a promotion ladder. Git-retained evidence does not provide an append-only
transparency log, inclusion proofs, consistency proofs or protection against a
publisher serving different histories to different clients.
