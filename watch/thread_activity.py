#!/usr/bin/env python3
"""Read public GitHub thread activity for the existing Beat; never posts or approves."""
import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess


def github(endpoint):
    result = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True, timeout=60)
    if result.returncode:
        # Do not retain arbitrary CLI stderr (auth or local configuration).
        raise RuntimeError(f"GitHub read failed (exit {result.returncode}): {endpoint}")
    return json.loads(result.stdout)


def pages(endpoint, fetch=github):
    rows = []
    separator = "&" if "?" in endpoint else "?"
    for page in range(1, 101):
        batch = fetch(f"{endpoint}{separator}per_page=100&page={page}")
        if not isinstance(batch, list):
            raise ValueError(f"Expected GitHub list: {endpoint}")
        rows.extend(batch)
        if len(batch) < 100:
            return rows
    raise RuntimeError(f"Pagination limit reached: {endpoint}")


def instant(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def recent_activity(rows, kind, since, until):
    events = []
    for row in rows:
        if kind == "issue_event" and row.get("event") not in {
            "closed", "reopened", "merged", "renamed", "converted_to_draft", "ready_for_review",
        }:
            continue
        timestamp = row.get("updated_at") or row.get("submitted_at") or row.get("created_at")
        if not timestamp or not since <= instant(timestamp) <= until:
            continue
        events.append({
            "id": f"{kind}:{row['id']}", "kind": kind,
            "at": timestamp, "created_at": row.get("created_at"),
            "author": (row.get("user") or row.get("actor") or {}).get("login"),
            "author_association": row.get("author_association"),
            "url": row.get("html_url") or row.get("url"),
            "event": row.get("event"), "review_state": row.get("state"),
            "body": row.get("body"),
        })
    return events


def collect(watchlist, since, until, fetch=github):
    report = {"schema_version": 1, "since": since.isoformat(), "collected_at": until.isoformat(),
              "complete": True, "threads": [], "discovery": [], "errors": []}
    for thread in watchlist["threads"]:
        repo, number = thread["repo"], thread["number"]
        base = f"repos/{repo}"
        issue_path = f"{base}/issues/{number}"
        entry = {**thread, "activity": [], "errors": []}
        report["threads"].append(entry)
        try:
            issue = fetch(issue_path)
            entry.update({key: issue.get(key) for key in ["title", "html_url", "state", "updated_at", "closed_at"]})
            entry["author"] = issue["user"]["login"]
            endpoints = [("comment", issue_path + "/comments"), ("issue_event", issue_path + "/events")]
            if "pull_request" in issue:
                pr_path = f"{base}/pulls/{number}"
                try:
                    pr = fetch(pr_path)
                    entry.update({key: pr.get(key) for key in ["merged_at", "draft", "merge_commit_sha"]})
                except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
                    entry["errors"].append(str(error))
                endpoints += [("review", pr_path + "/reviews"), ("review_comment", pr_path + "/comments")]
            for kind, endpoint in endpoints:
                try:
                    rows = pages(endpoint, fetch)
                    entry["activity"].extend(recent_activity(rows, kind, since, until))
                except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
                    entry["errors"].append(str(error))
            entry["activity"].sort(key=lambda event: (event["at"], event["id"]))
        except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            entry["errors"].append(str(error))
        if entry["errors"]:
            report["complete"] = False
    # Search catches new threads and conversations outside the fixed watchlist.
    # These are candidates, not news: updated_at may reflect unrelated activity.
    for account in watchlist.get("discovery_accounts", []):
        for org in watchlist.get("discovery_orgs", []):
            query = f"is:public involves:{account} org:{org} updated:>={since.date().isoformat()}"
            try:
                from urllib.parse import urlencode
                result = fetch("search/issues?" + urlencode({"q": query, "per_page": 100}))
                report["discovery"].append({"query": query, "total_count": result["total_count"],
                    "truncated": result["total_count"] > len(result["items"]),
                    "incomplete_results": result.get("incomplete_results", False),
                    "candidates": [{key: item.get(key) for key in ["html_url", "title", "updated_at", "state"]}
                                   for item in result["items"]]})
                if result["total_count"] > len(result["items"]) or result.get("incomplete_results"):
                    report["complete"] = False
            except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
                report["complete"] = False
                report["errors"].append({"query": query, "error": str(error)})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watchlist", type=Path, default=Path(__file__).with_name("thread-watchlist.json"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--hours", type=float, default=26)
    args = parser.parse_args()
    if args.hours <= 0:
        parser.error("--hours must be positive")
    now = dt.datetime.now(dt.timezone.utc)
    report = collect(json.loads(args.watchlist.read_text()), now - dt.timedelta(hours=args.hours), now)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(args.output)
    print(json.dumps({"output": str(args.output), "complete": report["complete"],
                      "threads": len(report["threads"]),
                      "activity": sum(len(t["activity"]) for t in report["threads"])}))


if __name__ == "__main__":
    main()
