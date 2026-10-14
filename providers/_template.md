# <Provider Name>

## Claim

*What the provider advertises, in 1–2 sentences with a source link.*

## Endpoint surface

- **Chat:** `<base_url>/chat/completions`
- **Attestation:** `<base_url>/...`
- **Models:** `<base_url>/...`
- **Auth:** Bearer token in `Authorization` header.

Example:

```bash
curl "<base_url>/attestation?model=<model>&nonce=<32-byte hex>" \
     -H "Authorization: Bearer $API_KEY"
```

## Verifiers and reference policy

- **Route IDs / client versions / modes:** link entries in `data/routes.json`.
- **Verifier implementation and pinned revision:** entry point or explicit missing verifier.
- **Checks / delegated trust / unchecked proof:** distinguish source inspection from live evidence.
- **Reference identities:** component, platform field, algorithm, full value and evidence.
- **Authority and policy:** who publishes, who authorizes, and which client/policy revision accepts it?
- **Dates:** observation time and review date separately; include update/rollback behavior.

Add a scoped entry to `data/verifiers.json`. An observed value is not an approved
value. Link retained evidence and the reference history, including missing data.

## Route assessment

Link dated, version-bound evidence for each applicable assessment obligation.
Name protected fields, plaintext holders, model and downstream boundaries.
Unknown/unmet obligations prevent promotion; automated check coverage cannot
award a stage. See the proposed [stage criteria](../docs/stages.html).

## Known gaps

- *Inner-boundary: does the gateway actually verify backend attestation?*
- *KMS / key management opacity.*
- *Routing-mutability: can an operator change `inference_url` without breaking attestation?*

Link to [devproof-audits-guide](https://github.com/amiller/devproof-audits-guide) case study if
one exists.

## Reproduce

```bash
export <PROVIDER>_API_KEY=...
python -m probes.attestation --provider <slug>
```

## History

Past scorecard snapshots: [data/snapshots](../data/snapshots).
