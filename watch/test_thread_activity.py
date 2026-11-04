"""Offline controls for discussion collection; no provider requests or posting."""
import datetime as dt
import unittest
from thread_activity import collect, pages, recent_activity

SINCE = dt.datetime(2026, 10, 24, 13, tzinfo=dt.timezone.utc)
UNTIL = SINCE + dt.timedelta(hours=26)

class ThreadActivityTests(unittest.TestCase):
    def test_old_comment_new_edit_and_review_are_captured(self):
        old = {"id": 1, "created_at": "2026-08-10T00:00:00Z", "updated_at": "2026-10-24T14:00:00Z",
               "user": {"login": "reviewer"}, "body": "edited", "html_url": "https://github.com/a/b/issues/1#issuecomment-1"}
        stale = {**old, "id": 2, "updated_at": "2026-10-23T14:00:00Z"}
        future = {**old, "id": 3, "updated_at": "2026-10-26T14:00:00Z"}
        events = recent_activity([old, stale, future], "comment", SINCE, UNTIL)
        self.assertEqual([x["id"] for x in events], ["comment:1"])
        self.assertEqual(events[0]["url"], old["html_url"])
        review = {"id": 4, "submitted_at": "2026-10-25T00:00:00Z", "state": "CHANGES_REQUESTED"}
        self.assertEqual(recent_activity([review], "review", SINCE, UNTIL)[0]["review_state"], "CHANGES_REQUESTED")

    def test_pagination_does_not_drop_late_replies(self):
        calls = []
        def fetch(endpoint):
            calls.append(endpoint)
            return list(range(100)) if endpoint.endswith("page=1") else ["late reply"]
        self.assertEqual(pages("repos/a/b/issues/1/comments", fetch)[-1], "late reply")
        self.assertEqual(len(calls), 2)

    def test_failure_preserves_other_thread_and_marks_partial(self):
        def fetch(endpoint):
            if endpoint == "repos/a/b/issues/1":
                raise RuntimeError("unavailable")
            if endpoint.endswith("/issues/2"):
                return {"user": {"login": "amiller"}, "state": "closed", "pull_request": {}}
            if endpoint.endswith("/pulls/2"):
                return {"merged_at": "2026-10-25T00:00:00Z"}
            if "/events?" in endpoint:
                return [{"id": 5, "event": "closed", "created_at": "2026-10-25T00:00:00Z", "actor": {"login": "maintainer"}}]
            return []
        report = collect({"threads": [{"repo": "a/b", "number": 1}, {"repo": "a/b", "number": 2}]}, SINCE, UNTIL, fetch)
        self.assertFalse(report["complete"])
        self.assertTrue(report["threads"][0]["errors"])
        self.assertEqual(report["threads"][1]["activity"][0]["event"], "closed")
        self.assertEqual(report["threads"][1]["merged_at"], "2026-10-25T00:00:00Z")

    def test_pr_metadata_failure_does_not_drop_replies(self):
        def fetch(endpoint):
            if endpoint.endswith("/issues/2"):
                return {"user": {"login": "amiller"}, "pull_request": {}}
            if endpoint.endswith("/pulls/2"):
                raise RuntimeError("PR metadata unavailable")
            if "/issues/2/comments?" in endpoint:
                return [{"id": 6, "created_at": "2026-10-25T00:00:00Z", "body": "provider reply"}]
            return []
        report = collect({"threads": [{"repo": "a/b", "number": 2}]}, SINCE, UNTIL, fetch)
        self.assertFalse(report["complete"])
        self.assertEqual(report["threads"][0]["activity"][0]["body"], "provider reply")

    def test_discovery_truncation_is_not_reported_as_complete(self):
        result = collect({"threads": [], "discovery_accounts": ["amiller"], "discovery_orgs": ["nearai"]},
                         SINCE, UNTIL, lambda _: {"total_count": 101, "items": [], "incomplete_results": False})
        self.assertFalse(result["complete"])
        self.assertTrue(result["discovery"][0]["truncated"])
        self.assertTrue(result["discovery"][0]["query"].startswith("is:public "))

if __name__ == "__main__":
    unittest.main()
