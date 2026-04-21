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

## Scorecard

See [live matrix](https://amiller.github.io/awesome-private-inference). Pulled from the last
snapshot — hover any cell for the re-verification detail.

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
