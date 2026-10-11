#!/usr/bin/env python3
"""The claim pull request workflow (.github/workflows/claim.yml), in two steps:

    ci.py check --out result.json   read-only: fetch the pull request's claim file, run every check
    ci.py apply                     with write access: comment, label, and merge or close

`check` reads the pull request as data and never runs anything from it. `apply` uses only the
standard library, so the job holding the write token installs no packages.
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
MARKER = "<!-- claim-check "
LABELS = {"reject": "rejected", "review": "needs-review"}


def gh(method, path, body=None):
    req = urllib.request.Request(
        API + path, method=method, data=None if body is None else json.dumps(body).encode(),
        headers={"authorization": "Bearer " + os.environ["GH_TOKEN"], "accept": "application/vnd.github+json",
                 "x-github-api-version": "2022-11-28", "user-agent": "crosslink-profiles-ci"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
            return json.loads(data) if data else None
    except urllib.error.HTTPError as e:
        if e.code == 404 and method == "DELETE":
            return None
        raise SystemExit("GitHub %s %s: HTTP %d %s" % (method, path, e.code, e.read()[:300].decode("utf-8", "replace")))


def pr_files(repo, n):
    files, page = [], 1
    while True:
        batch = gh("GET", "/repos/%s/pulls/%d/files?per_page=100&page=%d" % (repo, n, page))
        files += batch
        if len(batch) < 100 or page >= 30:
            return files
        page += 1


def check(args):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import claims as C

    repo, n, head = os.environ["GITHUB_REPOSITORY"], int(os.environ["PR"]), os.environ["HEAD_SHA"]
    pr = gh("GET", "/repos/%s/pulls/%d" % (repo, n))
    labels = {l["name"] for l in pr["labels"]}

    def finish(result):
        result.update({"pr": n, "head": head, "author": pr["user"]["login"],
                       "same_repo": pr["head"]["repo"] is not None and pr["head"]["repo"]["full_name"] == repo,
                       "branch": pr["head"]["ref"]})
        result["comment"] = C.comment(result)
        with open(args.out, "w") as f:
            json.dump(result, f)
        print(result["verdict"])
        for c in result["checks"]:
            print(("  ok   " if c["ok"] else "  FAIL ") + c["check"] + ("" if c["ok"] else ": " + c["detail"]))

    if pr["state"] != "open" or pr["head"]["sha"] != head:
        with open(args.out, "w") as f:
            json.dump({"verdict": "stale", "pr": n}, f)
        print("stale: the pull request moved on or closed; its newer run decides")
        return

    files = pr_files(repo, n)
    only = [] if len(files) == 1 else ["a claim pull request changes exactly one file (this one changes %d)" % len(files)]
    path = files[0]["filename"] if len(files) == 1 else None
    if path and not re.fullmatch(r"claims/[A-Za-z0-9_-]+\.json", path):
        only.append("the file must be claims/<anchor address>.json")
    if path and files[0]["status"] not in ("added", "modified"):
        only.append("a claim can be added or replaced here, not %s; open an issue to remove one" % files[0]["status"])
    first = {"check": "It changes only its own claim file", "ok": not only, "detail": "; ".join(only)}
    if only:
        return finish({"verdict": "reject", "checks": [first], "review": [], "notes": [], "anchor": None, "name": None})

    # The file at the pull request's head, read as data. Nothing from the pull request runs.
    subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin", "+refs/pull/%d/head:refs/claim/pr" % n], check=True)
    sha = subprocess.run(["git", "rev-parse", "refs/claim/pr"], check=True, capture_output=True, text=True).stdout.strip()
    if sha != head:
        with open(args.out, "w") as f:
            json.dump({"verdict": "stale", "pr": n}, f)
        print("stale: the pull request moved on; its newer run decides")
        return
    size = int(subprocess.run(["git", "cat-file", "-s", "%s:%s" % (sha, path)], check=True, capture_output=True, text=True).stdout)
    claim = None
    if size <= C.MAX_FILE_BYTES:
        raw = subprocess.run(["git", "cat-file", "blob", "%s:%s" % (sha, path)], check=True, capture_output=True).stdout
        try:
            claim = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            claim = "not JSON"
    if not isinstance(claim, dict):
        why = "the file is larger than %d KB" % (C.MAX_FILE_BYTES // 1024) if size > C.MAX_FILE_BYTES else "the file isn't a JSON object"
        return finish({"verdict": "reject", "checks": [first, {"check": "The file is a well-formed claim", "ok": False, "detail": why}],
                       "review": [], "notes": [], "anchor": None, "name": None})

    base, _ = C.load_dir(os.path.join(C.ROOT, "claims"))
    chain = C.HoldfastChain(os.environ.get("CHAIN_API") or C.DEFAULT_CHAIN_API)
    result = C.check_claim(path, claim, base, chain, approved="review-approved" in labels, ctaz=C.ctaz_names())
    result["checks"].insert(0, first)
    if result["verdict"] == "merge" and "review-approved" in labels:
        result["notes"].append("A maintainer approved the name.")
    finish(result)


def apply(args):
    repo = os.environ["GITHUB_REPOSITORY"]
    result = json.loads(base64.b64decode(os.environ["RESULT"]))
    verdict, n = result["verdict"], int(result["pr"])
    if verdict == "stale":
        print("nothing to do: a newer run decides")
        return

    # One comment per pull request, updated on every run.
    comments = gh("GET", "/repos/%s/issues/%d/comments?per_page=100" % (repo, n))
    mine = [c for c in comments if c["user"]["login"] == "github-actions[bot]" and MARKER in c["body"]]
    if mine:
        gh("PATCH", "/repos/%s/issues/comments/%d" % (repo, mine[-1]["id"]), {"body": result["comment"]})
    else:
        gh("POST", "/repos/%s/issues/%d/comments" % (repo, n), {"body": result["comment"]})

    want = LABELS.get(verdict)
    have = {l["name"] for l in gh("GET", "/repos/%s/issues/%d/labels" % (repo, n))}
    for label in set(LABELS.values()) & have - {want}:
        gh("DELETE", "/repos/%s/issues/%d/labels/%s" % (repo, n, label))
    if want and want not in have:
        gh("POST", "/repos/%s/issues/%d/labels" % (repo, n), {"labels": [want]})

    if verdict == "merge":
        # Merges exactly the commit that was checked: a push after the check makes this fail.
        gh("PUT", "/repos/%s/pulls/%d/merge" % (repo, n), {
            "merge_method": "squash", "sha": result["head"],
            "commit_title": "Claim: %s (%s…)" % (result["name"], result["anchor"][:12]),
            "commit_message": "Checked by the claim workflow. Pull request #%d." % n})
        print("merged")
    elif verdict == "reject" and result.get("author") and result["author"] == os.environ.get("CLAIM_BOT"):
        # Nobody can push a fix to a pull request the explorer opened: close it, and drop its branch.
        gh("PATCH", "/repos/%s/pulls/%d" % (repo, n), {"state": "closed"})
        if result.get("same_repo") and result.get("branch", "").startswith("claim/"):
            gh("DELETE", "/repos/%s/git/refs/heads/%s" % (repo, result["branch"]))
        print("closed")
    else:
        print(verdict)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--out", required=True)
    sub.add_parser("apply")
    args = ap.parse_args()
    check(args) if args.cmd == "check" else apply(args)


if __name__ == "__main__":
    main()
