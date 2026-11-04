"""Snapshot Google's public GCE TCB endorsement bucket and diff it against the previous snapshot."""
import argparse, json, pathlib, urllib.parse, urllib.request

BUCKET = "https://storage.googleapis.com/storage/v1/b/gce_tcb_integrity/o"


def listing():
    items, token = [], None
    while True:
        q = {"maxResults": "1000", "fields": "nextPageToken,items(name,size,generation,timeCreated,updated,md5Hash)"}
        if token:
            q["pageToken"] = token
        page = json.load(urllib.request.urlopen(BUCKET + "?" + urllib.parse.urlencode(q), timeout=60))
        items += page.get("items", [])
        token = page.get("nextPageToken")
        if not token:
            return {i["name"]: i for i in items}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--snapshots", required=True, help="directory of prior gce-tcb-*.json snapshots")
    p.add_argument("--output", required=True, help="diff report path")
    a = p.parse_args()
    snaps = pathlib.Path(a.snapshots)
    snaps.mkdir(parents=True, exist_ok=True)
    prior = sorted(snaps.glob("gce-tcb-*.json"))
    old = json.loads(prior[-1].read_text()) if prior else None
    new = listing()
    stamp = max(i["updated"] for i in new.values())
    (snaps / f"gce-tcb-{stamp[:19].replace(':', '')}.json").write_text(json.dumps(new, indent=1, sort_keys=True))
    lines = [f"GCE TCB endorsement bucket gce_tcb_integrity: {len(new)} objects, newest update {stamp}"]
    if old is None:
        lines.append(f"FIRST SNAPSHOT: no prior snapshot in {snaps}; nothing to diff.")
    else:
        lines.append(f"Compared with {prior[-1].name} ({len(old)} objects).")
        for n in sorted(set(new) - set(old)):
            lines.append(f"ADDED {new[n]['timeCreated']} {n} size={new[n]['size']}")
        for n in sorted(set(old) - set(new)):
            lines.append(f"REMOVED (was created {old[n]['timeCreated']}) {n}")
        for n in sorted(set(new) & set(old)):
            if new[n]["md5Hash"] != old[n]["md5Hash"]:
                lines.append(f"CHANGED {new[n]['updated']} {n} md5 {old[n]['md5Hash']} -> {new[n]['md5Hash']}")
    tdx = sorted((i["timeCreated"], n.split("/")[-1].split(".")[0]) for n, i in new.items() if "/tdx/" in n)
    lines.append(f"Latest TDX MRTD endorsement: {tdx[-1][0]} {tdx[-1][1]} ({len(tdx)} total)")
    pathlib.Path(a.output).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
