# Compact comparison and dated route assessments

The restored table exposed seven TDX-oriented fields and 17 model/endpoint rows. At a 1440px browser viewport every row was 73px high. Sixty-five of 119 cells were blank. A green adapter acceptance could coexist with a failed backend subcheck; Tinfoil's different architecture appeared entirely blank.

## Result

The homepage now has nine provider groups with 42px rows, all visible in one desktop screen. Expanding groups reveals 19 client paths. Six named assessment axes replace protocol-specific field names in the overview: hardware, session binding, code, operator access, downstream binding and updates. The original model-level table remains on Measurements, with denser rows and neutral adapter acceptance labels. It is linked from navigation and the overview.

Assessment definitions and evidence live in `data/assessments/routes.json`; the rubric is version 1 and rendered on `assessments.html`. Each route records a source revision, source paths, date and identified authoring reviewer. The reviewer is the source-review agent, not an independent audit approval. Source links are pinned to the reviewed commit. No new provider request proof, complete devproof audit or security stage is claimed.

## Semantics

- Established requires explicit scoped proof records; no current assessment is Established.
- Partial has evidence for only part of the obligation.
- Gap means a documented protection or verification omission in the assessed protocol/client, not exploitation.
- Unknown includes insufficient evidence and missing implementation in our own instrument.
- N/A needs an explicit architectural reason. Missing data is never converted to N/A.
- Varies preserves differing route states; groups never select the best route or average states.

NEAR ordinary gateway, application E2EE and direct endpoints remain distinct. The dated E2EE review records a response-key gap, while the direct route remains unknown where a gateway finding cannot establish it. Tinfoil's hardware state is Unknown because our verifier does not authenticate the AMD chain/report; the page does not label that as a provider vulnerability. TLS/key and release evidence supports narrower Partial assessments. The historical April operator-config review is not promoted to a current guarantee.

Collection status is computed separately from assessment status, deduplicating observation aliases. Missing credential/proof records with no checked fields do not count as returned evidence. Returned evidence may be rejected. Staleness is relative to the displayed snapshot, using a 48-hour threshold; the page does not claim a fresh HTTP attempt establishes a fresh successful proof.

## Reference continuity

The overview shows the latest newly observed set for the provider, with a provider-filtered link into the existing history page. Baseline-only sources and missing history are explicit. These dates are not deployment dates or route-specific proof changes.

The source assessment stores a baseline of tracked reference values. A differing latest set flags review work; missing baseline surfaces flag coverage loss. The date and source assessment remain unchanged. This is deliberately a provider-wide conservative signal, not a verified dependency graph or automatic invalidation/approval of a route. A reviewer must establish which route and assumption the changed surface affects.

## Verification

143 unit tests pass, including provider rollup behavior, unreviewed fallback, refusal to promote adapter success to an assessment, reference changes without policy mutation, collection versus rejection, required evidence for Established, route distinctions and HTML escaping of external model names. Jinja now enables autoescaping for `.j2` templates.

`tools/check_comparison_browser.py` checks nine provider rows, all 19 expandable routes, keyboard expansion, exact assessment anchors, filtered history navigation, desktop density, mobile sticky identities, no-JavaScript route visibility and internal fragments. Screenshots are visually reviewed. Existing graph browser checks remain in `tools/check_history_browser.py`.

The comparison does not infer new guarantees from legacy booleans, does not modify accepted client reference policies and does not change the production scheduler.
