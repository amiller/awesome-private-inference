import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
d = json.loads((ROOT / "data/disclosure-timeline.json").read_text())
resp = {}
for e in d["events"]:
    if "answers" in e:
        resp.setdefault(e["answers"], []).append(e)

L = ["# Reports, responses and incidents", "",
     "Generated from [data/disclosure-timeline.json](../data/disclosure-timeline.json) by `python tools/disclosure_timeline.py`. " + d["scope"], "",
     "## Reports and what followed", "",
     "| Reported | By | About | Report | First response |", "|---|---|---|---|---|"]
for e in sorted((e for e in d["events"] if e["kind"] == "report"), key=lambda e: e["date"]):
    rs = sorted(resp.get(e["id"], []), key=lambda r: r["date"])
    first = "; ".join(f"{r['date']} {r['actor']}: [{r['title']}]({r['url']})" for r in rs) or ("no reply" if e["id"] in d["open_without_reply"] else "—")
    L.append(f"| {e['date']} | {e['actor']} | {e.get('target', '')} | [{e['title']}]({e['url']}) | {first} |")
L += ["", "## Incidents, launches, fixes and audits", "", "| Date | Party | Kind | Event |", "|---|---|---|---|"]
for e in sorted((e for e in d["events"] if e["kind"] != "report" and "answers" not in e), key=lambda e: e["date"]):
    span = e["date"] + (" to " + e["end"] if "end" in e else "")
    L.append(f"| {span} | {e['actor']} | {e['kind']} | [{e['title']}]({e['url']}) |")
(ROOT / "docs/disclosure-timeline.md").write_text("\n".join(L) + "\n")
