"""The workflow's glue (tools/ci.py), against a local git remote and a fake GitHub API."""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))
sys.path.insert(0, HERE)
import ci  # noqa: E402
import claims as C  # noqa: E402
import test_claims as T  # noqa: E402


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


class FakeGitHub:
    def __init__(self, pr, files, comments=(), labels=()):
        self.pr, self.files, self.comments, self.labels, self.calls = pr, files, list(comments), list(labels), []

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and path.endswith("/pulls/1"):
            return self.pr
        if method == "GET" and "/pulls/1/files" in path:
            return self.files
        if method == "GET" and "/comments" in path:
            return self.comments
        if method == "GET" and path.endswith("/labels"):
            return [{"name": n} for n in self.labels]
        return {}


class CI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.remote, self.work = os.path.join(d, "remote.git"), os.path.join(d, "work")
        git(d, "init", "-q", "--bare", self.remote)
        git(d, "clone", "-q", self.remote, self.work)

    def tearDown(self):
        self.tmp.cleanup()

    def push_pr(self, files):
        """Commits `files` on a branch and publishes it as refs/pull/1/head, as GitHub does."""
        git(self.work, "commit", "-q", "--allow-empty", "-m", "base")
        git(self.work, "checkout", "-q", "-b", "claim")
        for path, content in files.items():
            os.makedirs(os.path.dirname(os.path.join(self.work, path)), exist_ok=True)
            with open(os.path.join(self.work, path), "w") as f:
                f.write(content)
        git(self.work, "add", "-A")
        git(self.work, "commit", "-q", "-m", "claim")
        git(self.work, "push", "-q", "origin", "HEAD:refs/pull/1/head")
        return git(self.work, "rev-parse", "HEAD")

    def run_check(self, claim_files, labels=(), status="added", head=None):
        sha = self.push_pr(claim_files)
        pr = {"state": "open", "head": {"sha": head or sha, "ref": "claim/x", "repo": {"full_name": "o/r"}},
              "user": {"login": "someone"}, "labels": [{"name": n} for n in labels]}
        files = [{"filename": p, "status": status} for p in claim_files]
        out = os.path.join(self.tmp.name, "result.json")
        env = {"GITHUB_REPOSITORY": "o/r", "PR": "1", "HEAD_SHA": sha, "GH_TOKEN": "x"}
        cwd = os.getcwd()
        os.chdir(self.work)
        try:
            with mock.patch.dict(os.environ, env), mock.patch.object(ci, "gh", FakeGitHub(pr, files)), \
                    mock.patch.object(C, "HoldfastChain", lambda *a: T.Chain()), mock.patch.object(C, "ctaz_names", lambda: []), \
                    mock.patch("sys.stdout"):
                ci.check(mock.Mock(out=out))
        finally:
            os.chdir(cwd)
        with open(out) as f:
            return json.load(f)

    def test_a_good_claim(self):
        claim = T.make()
        r = self.run_check({"claims/%s.json" % claim["anchor"]: json.dumps(claim, indent=2)})
        self.assertEqual(r["verdict"], "merge", r.get("checks"))
        self.assertEqual(r["checks"][0]["check"], "It changes only its own claim file")
        self.assertIn("<!-- claim-check ", r["comment"])

    def test_more_than_one_file(self):
        claim = T.make()
        r = self.run_check({"claims/%s.json" % claim["anchor"]: json.dumps(claim), "tools/claims.py": "evil"})
        self.assertEqual(r["verdict"], "reject")

    def test_not_json(self):
        claim = T.make()
        self.assertEqual(self.run_check({"claims/%s.json" % claim["anchor"]: "{nope"})["verdict"], "reject")

    def test_removal_refused(self):
        claim = T.make()
        r = self.run_check({"claims/%s.json" % claim["anchor"]: json.dumps(claim)}, status="removed")
        self.assertIn("open an issue", r["checks"][0]["detail"])

    def test_moved_on_is_stale(self):
        claim = T.make()
        r = self.run_check({"claims/%s.json" % claim["anchor"]: json.dumps(claim)}, head="0" * 40)
        self.assertEqual(r["verdict"], "stale")

    def test_review_then_approved(self):
        claim = T.make(name="Shielded Labs")
        files = {"claims/%s.json" % claim["anchor"]: json.dumps(claim)}
        self.assertEqual(self.run_check(files)["verdict"], "review")
        self.tearDown()
        self.setUp()
        self.assertEqual(self.run_check(files, labels=["review-approved"])["verdict"], "merge")

    def apply(self, result, comments=(), labels=(), bot=""):
        fake = FakeGitHub({}, [], comments, labels)
        env = {"GITHUB_REPOSITORY": "o/r", "GH_TOKEN": "x", "CLAIM_BOT": bot,
               "RESULT": base64.b64encode(json.dumps(result).encode()).decode()}
        with mock.patch.dict(os.environ, env), mock.patch.object(ci, "gh", fake), mock.patch("sys.stdout"):
            ci.apply(None)
        return [(m, p, b) for m, p, b in fake.calls if m != "GET"]

    def result(self, verdict, **kw):
        r = {"verdict": verdict, "pr": 1, "head": "abc", "name": "Halyard", "anchor": "zfinv1abcdefghijkl", "comment": "body",
             "author": "someone", "same_repo": True, "branch": "claim/x"}
        r.update(kw)
        return r

    def test_apply_merge(self):
        calls = self.apply(self.result("merge"), labels=["needs-review"])
        self.assertIn(("DELETE", "/repos/o/r/issues/1/labels/needs-review", None), calls)
        merge = [c for c in calls if c[0] == "PUT"][0]
        self.assertEqual((merge[1], merge[2]["sha"], merge[2]["merge_method"]), ("/repos/o/r/pulls/1/merge", "abc", "squash"))

    def test_apply_updates_its_comment(self):
        mine = {"id": 7, "user": {"login": "github-actions[bot]"}, "body": "x <!-- claim-check {} -->"}
        calls = self.apply(self.result("reject"), comments=[mine])
        self.assertIn(("PATCH", "/repos/o/r/issues/comments/7", {"body": "body"}), calls)
        self.assertIn(("POST", "/repos/o/r/issues/1/labels", {"labels": ["rejected"]}), calls)
        self.assertFalse([c for c in calls if c[0] == "PUT"])

    def test_apply_closes_the_bots_rejected_claim(self):
        calls = self.apply(self.result("reject", author="holdfast[bot]"), bot="holdfast[bot]")
        self.assertIn(("PATCH", "/repos/o/r/pulls/1", {"state": "closed"}), calls)
        self.assertIn(("DELETE", "/repos/o/r/git/refs/heads/claim/x", None), calls)
        self.assertFalse([c for c in self.apply(self.result("reject")) if c[1] == "/repos/o/r/pulls/1"])

    def test_apply_stale_does_nothing(self):
        self.assertEqual(self.apply({"verdict": "stale", "pr": 1}), [])


if __name__ == "__main__":
    unittest.main()
