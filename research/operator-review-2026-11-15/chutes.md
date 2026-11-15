# Chutes TEE: operator access review, 2026-11-15

Route `chutes-tee`: client → Chutes API (`llm.chutes.ai` or `/e2e/invoke`) → sek8s TDX instance → chute code.

Sources:
- `chutesai/chutes` `08d79872` (last commit on main 2026-05-25)
- `chutesai/chutes-api` `3b5609f4` (last commit 2026-09-03, now archived)
- `chutesai/sek8s` `3a74f239`
- teep `6548996b`
- `data/audits/chutes_tee.json`

There was no live request this pass. The NanoGPT relay findings (teep `nanogpt_chutes_evidence.md`) belong to a NanoGPT route and are left out.

## What changed since 2026-10-14

- `chutesai/chutes#75` ("Make the per-chute serving code verifiable in the attestation") is open, with 0 comments and no update since 2026-06-18 [read, 2026-11-15].
- `chutesai/sek8s` has one commit since 10-14, `3a74f239` (2026-10-15, #136). It limits evidence concurrency in `attestation-proxy`, with no measurement or admission change [read, file list].
- `chutesai/chutes` has no commits on main since 2026-05-25. Its last push was 2026-07-23. The latest PyPI release is 0.6.11rc2, from 2026-06-10 [read].
- `chutesai/chutes-api` is archived. Its last commit is 2026-09-03 and the archive date is unknown. The `chutesai` org listing sorted by push on 2026-11-15 shows no successor [read]. So the control plane that receives default-path prompts no longer has current public source. `providers/chutes.md` cites its line numbers without noting this.

## 1. The chute code that receives plaintext is unmeasured (unchanged)

**Problem.** The measured boundary decrypts the request and hands plaintext to `/app/chute.py`. The filesystem challenge excludes that file. No RTMR or `report_data` field names the chute code or the model revision.

**Impact.**
- **Who:** the chute author, or Chutes, which builds and signs tenant images in `forge`.
- **What they do:** ship a `chute.py` that logs or forwards the prompt.
- **What they get:** every prompt and reply on that chute.
- **What stops it today:** nothing a client can check. The registry showed prompt exfiltration from a `verified=True` enclave on 2026-06-16/17 (`providers/chutes.md`).

**Evidence.** `chutes/cfsv_wrapper.py:54` (`exclude_path="/app/chute.py"`) at `08d79872` [read]. teep `sek8s_integrity.md`: MRCONFIGID unused, container identity checked only by the in-guest admission controller [read].

**Remediation.** #75: measure the chute code and model revision into an RTMR or `report_data`, and publish the expected values.

## 2. The control plane chooses the encryption key and reads default-path prompts

**Problem.** E2E discovery returns the instance's stored `e2e_pubkey` with no quote. The default OpenAI path parses the body, iterates the messages, and hashes prompt prefixes for routing.

**Impact.**
- **Who:** Chutes, as operator of `api.chutes.ai` and `llm.chutes.ai`.
- **What they do:** read the request on the default path. On E2E, return a key it holds.
- **What they get:** prompt and reply plaintext.
- **What stops it today:**
  - On E2E: a client that fetches `/instances/{id}/evidence` and checks `report_data[0:32] == SHA256(nonce‖e2e_pubkey)`. No shipped Chutes client does this (`chutesai/e2ee-proxy#3`).
  - On the default path: nothing.

**Evidence.**
- `api/e2e/router.py:140-152`.
- `api/invocation/router.py:505, 606, 895, 937`, at `3b5609f4` [read].

The source is archived, so whether the deployed API still behaves this way is inferred.

**Remediation.** Return the quote with discovery, ship a verifying client, and republish the control-plane source.

## 3. Chutes publishes the reference values and releases the disk key

**Problem.** The API returns LUKS passphrases after checking the quote against a measurement ConfigMap that Chutes edits. Clients compare against `/servers/tee/measurements`, which Chutes also publishes. On 2026-10-12 instance `912aec3d` served `Qwen3-32B-TEE` with MRTD `ddc6efcd…`. That MRTD was absent from that day's publication. The ledger lists it for 2026-06-18 to 2026-09-02. The quote was not retained, so the case cannot be replayed.

**Impact.**
- **Who:** Chutes.
- **What they do:** add a row for an image of its choosing, or keep serving a withdrawn one.
- **What they get:** an instance that unseals its disk and passes a client that trusts the current publication.
- **What stops it today:** clients that keep their own history of reference values. The registry ledger holds two MRTDs.

**Evidence.**
- `api/config/__init__.py:394-412`: `/etc/config/tee_measurements.yaml`, which "Re-reads the file on every access".
- `api/server/router.py:221-245`: the `attest_luks` docstring says `verify_quote` "checks the TDX signature and all RTMR measurements".

Both are at `3b5609f4` [read docstrings; comparison body not traced]. See also `research/chutes-912aec3d-evidence-gap-2026-11-15.md` [read].

**Remediation.** Publish reference values in an append-only log tied to signed sek8s builds, and have clients pin to that log.

## Proposed operator-axis cell

**chutes-tee**
- **state:** gap (unchanged, re-dated 2026-11-15)
- **label:** Code can change unmeasured
- **reason:** The chute code that receives plaintext is excluded from measurement. The control plane chooses the E2E key, reads default-path prompts and sets the reference values.
- **evidence:**
  - `cfsv_wrapper.py:54` at `08d79872`.
  - `e2e/router.py:140-152` and `invocation/router.py:505-937` at archived `3b5609f4`.
  - #75 open, with no response since 2026-06-18.
- **missing:** measured chute code and model revision; quote-bound discovery; an append-only reference-value log; current control-plane source.
- **limitation:** reviewed_system. The control-plane part is also evidence-limited: the source is archived, last commit 2026-09-03.
