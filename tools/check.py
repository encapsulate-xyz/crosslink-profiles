#!/usr/bin/env python3
"""Checks claim files the way CI does, or prints the whole registry resolved.

    python3 tools/check.py claims/<anchor>.json         check a claim against the chain and registry
    python3 tools/check.py --rpc http://127.0.0.1:<port> claims/<anchor>.json   use your own node
    python3 tools/check.py --index                      every live claim, resolved, as JSON

Needs the cryptography package (pip install -r tools/requirements.txt).
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import claims as C  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("files", nargs="*", help="claim files to check")
    ap.add_argument("--index", action="store_true", help="print the resolved registry as JSON")
    ap.add_argument("--dir", default=os.path.join(C.ROOT, "claims"), help="the registry's claims folder")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--holdfast", default=C.DEFAULT_CHAIN_API, help="read the chain from this Holdfast (default)")
    src.add_argument("--rpc", help="read the chain from this node's JSON-RPC instead")
    ap.add_argument("--any-age", action="store_true", help="don't apply the age limit (for claims already merged)")
    args = ap.parse_args(argv)

    base, bad = C.load_dir(args.dir)
    if args.index:
        for fn, why in bad.items():
            print("skipped %s: %s" % (fn, why), file=sys.stderr)
        print(json.dumps(C.index(base), indent=2))
        return 0
    if not args.files:
        ap.error("give claim files to check, or --index")

    chain = C.NodeChain(args.rpc) if args.rpc else C.HoldfastChain(args.holdfast)
    ctaz = C.ctaz_names()
    worst = 0
    for path in args.files:
        with open(path, "rb") as f:
            raw = f.read(C.MAX_FILE_BYTES + 1)
        try:
            claim = json.loads(raw.decode("utf-8")) if len(raw) <= C.MAX_FILE_BYTES else None
        except (ValueError, UnicodeDecodeError) as e:
            print("%s: not JSON (%s)" % (path, e))
            worst = 1
            continue
        rel = "claims/" + os.path.basename(path)
        b = dict(base)
        if isinstance(claim, dict) and b.get(claim.get("anchor")) == claim:
            del b[claim["anchor"]]  # re-checking a claim that's already in the registry
        r = C.check_claim(rel, claim, b, chain, approved=args.any_age, ctaz=ctaz)
        print("%s: %s" % (path, r["verdict"]))
        for c in r["checks"]:
            print("  %s %s%s" % ("✓" if c["ok"] else "✗", c["check"], "" if c["ok"] else ": " + c["detail"]))
        for x in r["review"]:
            print("  review: " + x)
        for n in r["notes"]:
            print("  note: " + n)
        if r["verdict"] in ("reject", "error"):
            worst = 1
    return worst


if __name__ == "__main__":
    sys.exit(main())
