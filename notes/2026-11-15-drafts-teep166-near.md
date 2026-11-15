# Drafts: teep #166 comment and NEAR issue — 2026-11-15

Posted 2026-11-15: teep comment https://github.com/13rac1/teep/issues/166#issuecomment-6902282309 ; NEAR issue https://github.com/nearai/compose-manager/issues/85

## Comment on 13rac1/teep#166

On the open question: compose-manager doesn't extend RTMR3 with its actions. It binds the log through a second quote. `attestation_binding` puts `sha256(canonical actions) || nonce` in that quote's report data (`nearai/compose-manager` `src/main.rs:1236-1243` at `2140f20c`). The canonical form is serde_json with keys sorted, compact; in Python, `json.dumps(actions, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. That reproduced `actions_hash` exactly on three live glm-5.3-flash instances on 2026-11-15, and the compose-manager quote matched the model quote on MRTD and RTMR0-3.

We added the check to awesome-private-inference's NEAR adapter (`verifiers/near_deployments.py`): verify the compose-manager quote, require the same registers as the model quote, recompute `actions_hash`, require `report_data = actions_hash || nonce`, replay `compose_up`/`compose_down` into the set of running files, and accept a file only if its bytes match `nearai/cvm-compose-files` at the logged commit and our archive first saw it at least 24 h earlier. Tests include a tampered list, a wrong nonce, a quote from another instance and non-matching public bytes.

Two limits a client can't close:

- dstack's GetQuote signs any caller-supplied report data (`Dstack-TEE/dstack` `guest-agent/src/rpc_service.rs:807-809`), and since 0.6.0 apps can't extend RTMR3 (`:816-819`). NEAR's `pack-small-models.yaml` gives GetQuote to the inference proxies and to `levantolabs/sage2-hopper-pod`. A deployed container could serve a quote over a different log, so the public commit history is the anchor, not the quote.
- The log leaves out env values interpolated into each file.

Running files on 2026-11-15 included deployments from personal branches and `experiments/` files, not only release tags.

## Issue for nearai/compose-manager (or nearai/cloud-api)

Title: Make the deployment log a complete, unforgeable record of what runs in a model CVM

Clients can now check compose-manager's deployment log against a quote (`attestation_binding`, `src/main.rs:1236-1243`). Four gaps keep that check from establishing what code reads prompts:

1. Env values interpolated into the compose file are not logged (`DeploymentAction` has no env, `src/main.rs:404-425`). A logged, public file can still point `WEB_CONTEXT_SEARCH_URL`, `FUSION_*` or `REPLICA_STATE_REDIS_URL` elsewhere. Please hash the env map into each action.
2. Any container with GetQuote can produce a quote over arbitrary report data, and the model compose exposes GetQuote to the inference proxies and a third-party container. Please measure each deployment into a register apps can't write, or keep GetQuote away from deployed workloads.
3. `MIN_TAG_AGE_HOURS` defaults to 0 (`CM_MIN_TAG_AGE_HOURS:-0`). A nonzero minimum gives observers time to see a tag before it serves.
4. cloud-api reads `compose_manager_attestation` only in tests. The gateway could apply the same check before routing.

Related: deployments from personal branches and `experiments/` files were running on production model CVMs on 2026-11-15 (for example tag `pranavraja99/glm53-pd-qualification`).
