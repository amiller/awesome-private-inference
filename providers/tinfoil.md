# Tinfoil

## Claim

Tinfoil ([tinfoil.sh](https://tinfoil.sh)) offers a confidential-compute inference service
with its own hardware-policy + sigstore-golden-values attestation shape — different from
the Phala TDX / NRAS stack used by RedPill and Venice.

## Status in this registry

**Not yet probed.** Tinfoil models appear as catalog entries in RedPill's `/models`
but as of 2026-04-21, every attempt to call them returns **HTTP 404** on the
`/v1/attestation/report` endpoint. Without a working endpoint we have nothing to verify.

Known-catalog-unreachable:
- `qwen/qwen3-coder-480b-a35b-instruct`
- `deepseek/deepseek-r1-0528`
- `moonshotai/kimi-k2-thinking`

## Endpoint surface

Direct Tinfoil endpoints not yet integrated. Adding them is a follow-up —
[CONTRIBUTING.md](../CONTRIBUTING.md) describes the steps.

## Known gaps (pre-probe)

- **Catalog ≠ served.** Inclusion in a reseller's `/models` list does not imply a working
  attestation path. This is itself a registry signal.
- **Different attestation shape.** Even when reachable, Tinfoil's attestation uses
  sigstore golden values rather than live Phala re-verification — a different trust root
  that we would need a dedicated verifier for.

## History

Snapshots: [data/snapshots/](../data/snapshots/).
