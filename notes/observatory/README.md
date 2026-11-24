# Private Inference Observatory: proposal and design previews

Drafts from 2026-11-24. Each page is also published as a private claude.ai artifact; the HTML here is the source (it omits `<html>`/`<head>`, which the artifact host adds).

| File | What it is |
| --- | --- |
| `brochure/` | Brochure with charts from our data: identity barcode per component, NEAR gateway TCB timeline, NEAR machine logbook, client-by-provider verifier grid. `data.json` is extracted from `data/snapshots/`, the NEAR machine archive and `data/clients.json`. |
| `brochure-v1.html` | First, text-led brochure: goals, what runs today, what a full observatory needs. |
| `goals.html` | Proposal centred on reference values: who writes the list clients trust, why transparency policies need a monitor. |
| `lookbook.html`, `shots/` | 26 public observatories and monitors grouped by kind, with screenshots taken 2026-11-24 and the design move to borrow from each. |
| `previews/` | Candidate site views drawn from real data: OONI-style fleet grid (preferred landing view), per-provider stacked bars, Wayback-style capture calendars (secondary tab), Key-Transparency-style monitor cards. `index.html` = `index.tpl.html` with `data.json` inlined. |

Findings these pages rely on that are new in this round:
- All 62 Tinfoil router digests observed since 2026-04-26 equal the sha256 of `tinfoil-deployment.json` in a `tinfoilsh/confidential-model-router` release, first seen 0–2 days after publication; 28 of 89 releases published in that window were never captured by the daily probe.
- Most "unreachable" route-days are our stale model list (398 route-days of retired models) or models that offer no attestation (245), not provider faults; RedPill's Jun 30–Aug 17 502s are the main sustained provider error.
