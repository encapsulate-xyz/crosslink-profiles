"""Tests for the signing script and the checks. Run: python3 -m unittest discover tests

tests/vectors.json comes from tests/vectors (Rust, with the crates the node itself uses:
rand 0.8, ed25519-zebra, bip39, zcash_transparent): `cargo run --release > ../vectors.json`.
"""

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import claims as C  # noqa: E402

_spec = importlib.util.spec_from_file_location("crosslink_claim", os.path.join(ROOT, "crosslink-claim.py"))
S = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(S)

with open(os.path.join(HERE, "vectors.json")) as f:
    VECTORS = json.load(f)

SEED_A = bytes(range(32))  # a finalizer node: its finalizer key and its wallet
SEED_B = bytes(range(100, 132))  # a second mining server
SEED_C = bytes(range(200, 232))  # someone else


class Chain:
    def __init__(self, tip=40000):
        self.tip_ = tip
        self.label = "a test chain"

    def tip(self):
        return self.tip_

    def hash_at(self, h):
        return hashlib.sha256(b"block %d" % h).hexdigest()


def block(h):
    return {"height": h, "hash": Chain().hash_at(h)}


def keys(entropy):
    fk = S.finalizer_key(S.default_bft_key_seed(entropy).encode())
    return {"finalizer": S.finalizer_address(fk), "fkey": fk, "wallet": S.wallet_keys(entropy, 3)}


def sign_lines(view, entropy):
    """What crosslink-claim.py prints for this seed, without the prompt."""
    k, out = keys(entropy), []
    for addr in [view["anchor"]] + view.get("members", []):
        msg = S.anchor_message(view) if addr == view["anchor"] else S.member_message(addr, view["anchor"], view["block"])
        if addr == k["finalizer"]:
            pub, sig = S.raw_public(k["fkey"]), k["fkey"].sign(msg)
        else:
            w = [w for w in k["wallet"] if w[0] == addr]
            if not w:
                continue
            pub, sig = w[0][1], w[0][2].sign(msg, S.ec.ECDSA(S.hashes.SHA256()))
        out.append("crosslink-claim-v1 %s %d %s %s" % (addr, view["block"]["height"], pub.hex(), sig.hex()))
    return out


def make(name="Halyard", entropy=SEED_A, members=(), height=39990, signers=None, **fields):
    k = keys(entropy)
    view = {"anchor": k["finalizer"], "name": name, "block": block(height), "members": sorted(members)}
    view.update(fields)
    lines = []
    for e in signers or [entropy]:
        lines += sign_lines(view, e)
    return C.assemble(view, lines)


def check(claim, base=None, **kw):
    path = "claims/%s.json" % claim.get("anchor")
    kw.setdefault("ctaz", [])
    return C.check_claim(path, claim, base or {}, Chain(), **kw)


def failed(result):
    return {c["check"]: c["detail"] for c in result["checks"] if not c["ok"]}


class Derivation(unittest.TestCase):
    def test_against_the_node_crates(self):
        for v in VECTORS:
            e = bytes.fromhex(v["entropy"])
            self.assertEqual(S.default_bft_key_seed(e), v["seed_text"])
            k = S.finalizer_key(v["seed_text"].encode())
            self.assertEqual(S.raw_public(k).hex(), v["finalizer_pubkey"])
            self.assertEqual(k.sign(S.FINALIZER_ADDRESS_MSG).hex(), v["address_sig"])
            self.assertEqual(S.mnemonic(e), v["mnemonic"])
            self.assertEqual([w[1].hex() for w in S.wallet_keys(e, 3)], v["transparent_pubkeys"])

    def test_explicit_bft_key_seed(self):
        self.assertEqual(S.raw_public(S.finalizer_key(b"encapsulate-test-seed")).hex(),
                         "8262c5578dfba3d3b77b3d6fda4950632a0e7be72a65ed9d5a8a166c55e70e94")

    def test_addresses_parse(self):
        k = keys(SEED_A)
        a = C.parse_address(k["finalizer"])
        self.assertEqual((a.kind, a.key), ("finalizer", S.raw_public(k["fkey"])))
        self.assertEqual(C.parse_address(k["wallet"][0][0]).kind, "miner")
        self.assertTrue(k["wallet"][0][0].startswith("tm"))

    def test_faucet_is_blocked(self):
        self.assertIn("tmRB9AEVsxNAQsqtJPqJUje9KCaAijpS77z", C.read_list("names/blocked-addresses.txt"))

    def test_bad_addresses(self):
        k = keys(SEED_A)
        forged = k["finalizer"][:-4] + ("AAAA" if not k["finalizer"].endswith("AAAA") else "BBBB")
        for bad, why in [(forged, "doesn't verify"), ("utest1abc", "shielded"), (k["wallet"][0][0][:-1] + "x", "checksum"),
                         ("t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi", "script address")]:
            with self.assertRaises(C.ClaimError) as cm:
                C.parse_address(bad)
            self.assertIn(why, str(cm.exception))


class Messages(unittest.TestCase):
    def test_script_and_checker_build_the_same_bytes(self):
        view = {"anchor": keys(SEED_A)["finalizer"], "name": "Halyard", "description": "Nodes since 2020.",
                "website": "https://halyard.example", "x": "https://x.com/halyard", "github": "https://github.com/halyard",
                "security_contact": "security@halyard.example", "logo": {"url": "https://halyard.example/l.png", "sha256": "ab" * 32},
                "members": [keys(SEED_A)["wallet"][0][0]], "block": block(39100)}
        self.assertEqual(S.anchor_message(view), C.anchor_message(view))
        claim = C.assemble(view, sign_lines(view, SEED_A))
        self.assertEqual(C.anchor_message(C.signed_view(claim)), S.anchor_message(view))
        m = view["members"][0]
        self.assertEqual(S.member_message(m, view["anchor"], view["block"]), C.member_message(m, view["anchor"], view["block"]))

    def test_message_text(self):
        view = {"anchor": "zfinv1X", "name": "Encapsulate", "website": "https://encapsulate.xyz", "members": ["tmA", "tmB"],
                "block": {"height": 39100, "hash": "00" * 32}}
        self.assertEqual(C.anchor_message(view).decode(), "\n".join([
            "Crosslink profile claim v1", "Network: Crosslink v14", "Anchor: zfinv1X", "Name: Encapsulate",
            "Website: https://encapsulate.xyz", "Members: tmA, tmB", "Block: 39100 " + "00" * 32]))

    def test_challenge_round_trip(self):
        view = {"anchor": keys(SEED_A)["finalizer"], "name": "Halyard", "block": block(39100), "members": []}
        c = S.decode_challenge(C.encode_challenge(view))
        self.assertEqual(S.anchor_message(c), C.anchor_message(view))

    def test_challenge_rejects_injected_lines(self):
        view = {"anchor": keys(SEED_A)["finalizer"], "name": "Halyard", "block": block(39100),
                "description": "ok\nMembers: tmEvil"}
        with self.assertRaises(S.ClaimError):
            S.decode_challenge(C.encode_challenge(view))


class Checks(unittest.TestCase):
    def test_a_good_claim_merges(self):
        k = keys(SEED_A)
        r = check(make(members=[k["wallet"][0][0]], website="https://halyard.example"))
        self.assertEqual(r["verdict"], "merge", failed(r))

    def test_a_miner_anchor(self):
        b = keys(SEED_B)["wallet"]
        view = {"anchor": b[0][0], "name": "Copperhead", "block": block(39990), "members": [b[1][0]]}
        r = check(C.assemble(view, sign_lines(view, SEED_B)))
        self.assertEqual(r["verdict"], "merge", failed(r))

    def test_members_from_another_server(self):
        b = keys(SEED_B)["wallet"][0][0]
        k = keys(SEED_A)
        view = {"anchor": k["finalizer"], "name": "Halyard", "block": block(39990), "members": [b]}
        with self.assertRaises(C.ClaimError):  # the second server hasn't signed yet
            C.assemble(view, sign_lines(view, SEED_A))
        claim = C.assemble(view, sign_lines(view, SEED_A) + sign_lines(view, SEED_B))
        self.assertEqual(check(claim)["verdict"], "merge")

    def test_tampering_is_caught(self):
        claim = make(website="https://halyard.example")
        claim["website"] = "https://evil.example"
        self.assertIn("The anchor's signature is valid", failed(check(claim)))
        claim = make(members=[keys(SEED_A)["wallet"][0][0]])
        claim["members"][0]["signature"] = claim["members"][0]["signature"][:-2] + "00"
        self.assertIn("Each member's signature is valid", failed(check(claim)))

    def test_a_member_the_anchor_never_listed(self):
        claim = make()
        c = keys(SEED_C)["wallet"][0][0]
        claim["members"] = [{"address": c, "block": block(39990), "pubkey": "02" + "00" * 32, "signature": "00"}]
        self.assertIn("The anchor's signature is valid", failed(check(claim)))

    def test_field_rules(self):
        for field, value in [("website", "http://halyard.example"), ("x", "https://twitter.com/h"), ("github", "https://gitlab.com/h"),
                             ("security_contact", "not an email"), ("description", "see https://x.example"),
                             ("description", "two\nlines"), ("description", "x" * 281), ("description", "rtl ‮ trick")]:
            claim = make()
            claim[field] = value
            self.assertTrue(C.field_problems(claim), (field, value))
        self.assertIn("The name follows the rules", failed(check(make(name="Unnamed"))))
        self.assertIn("The name follows the rules", failed(check(make(name="Halyard "))))

    def test_old_and_wrong_blocks(self):
        self.assertIn("The blocks are on the chain and recent", failed(check(make(height=40000 - C.MAX_AGE - 1))))
        self.assertEqual(check(make(height=40000 - C.MAX_AGE))["verdict"], "merge")
        self.assertIn("The blocks are on the chain and recent", failed(check(make(height=40001))))
        claim = make()
        view = C.signed_view(claim)
        view["block"] = {"height": 39990, "hash": "11" * 32}
        self.assertIn("The blocks are on the chain and recent", failed(check(C.assemble(view, sign_lines(view, SEED_A)))))

    def test_name_taken_and_lookalikes(self):
        base = {c["anchor"]: c for c in [make(name="Halyard", entropy=SEED_C)]}
        self.assertIn("The name and addresses are free", failed(check(make(name="halyard"), base)))
        self.assertIn("The name and addresses are free", failed(check(make(name="Hal-yard"), base)))
        r = check(make(name="Ha1yard"), base)
        self.assertEqual(r["verdict"], "review")
        r = check(make(name="Ha1yard"), base, approved=True)
        self.assertEqual(r["verdict"], "merge")

    def test_known_organisations_need_review(self):
        self.assertEqual(check(make(name="Shielded Labs"))["verdict"], "review")
        self.assertEqual(check(make(name="Figment Nodes"))["verdict"], "review")
        self.assertEqual(check(make(name="Shie1ded Labs"))["verdict"], "review")
        r = check(make(name="Tidewater"), ctaz=[(keys(SEED_C)["finalizer"], "Tidewater")])
        self.assertEqual(r["verdict"], "review")
        r = check(make(name="Tidewater"), ctaz=[(keys(SEED_A)["finalizer"], "Tidewater")])
        self.assertEqual(r["verdict"], "merge")  # the same address's own ctaz.cash name

    def test_faucet_refused(self):
        claim = make()
        claim["members"] = [{"address": "tmRB9AEVsxNAQsqtJPqJUje9KCaAijpS77z", "block": block(39990), "pubkey": "02" + "00" * 32, "signature": "00"}]
        self.assertIn("No address has a public key anyone can sign with", failed(check(claim)))

    def test_replacing_a_claim(self):
        old = make(name="Halyard", height=39000)
        base = {old["anchor"]: old}
        self.assertEqual(check(make(name="Halyard Nodes", height=39500), base)["verdict"], "merge")
        self.assertIn("It replaces the older claim with a later one", failed(check(make(name="Halyard", height=39000), base)))

    def test_kept_member_signature_can_be_old(self):
        w = keys(SEED_A)["wallet"]
        old = make(members=[w[0][0]], height=30000)
        new_view = dict(C.signed_view(old), block=block(39990), name="Halyard Nodes", members=[w[0][0], w[1][0]])
        lines = [l for l in sign_lines(new_view, SEED_A) if w[0][0] not in l]
        new = C.assemble(new_view, lines, previous=old)
        self.assertEqual(new["members"][0]["block"]["height"], 30000)
        self.assertEqual(check(new, {old["anchor"]: old})["verdict"], "merge", failed(check(new, {old["anchor"]: old})))
        self.assertIn("The blocks are on the chain and recent", failed(check(new, {})))  # without the old claim, it's stale

    def test_a_member_that_has_its_own_claim(self):
        b = keys(SEED_B)["wallet"]
        own_view = {"anchor": b[0][0], "name": "Copperhead", "block": block(39000), "members": []}
        own = C.assemble(own_view, sign_lines(own_view, SEED_B))
        claim = make(members=[b[0][0]], signers=[SEED_A, SEED_B])
        self.assertIn("The name and addresses are free", failed(check(claim, {own["anchor"]: own})))

    def test_a_member_moves(self):
        b = keys(SEED_B)["wallet"][0][0]
        first = make(name="Basalt", entropy=SEED_C, members=[b], height=39000, signers=[SEED_C, SEED_B])
        r = check(make(name="Halyard", members=[b], signers=[SEED_A, SEED_B]), {first["anchor"]: first})
        self.assertEqual(r["verdict"], "merge", failed(r))
        self.assertTrue(any("moves to this claim" in n for n in r["notes"]))

    def test_logo(self):
        png = b"\x89PNG\r\n\x1a\n" + b"x" * 100
        logo = {"url": "https://halyard.example/logo.png", "sha256": hashlib.sha256(png).hexdigest()}
        self.assertEqual(check(make(logo=logo), fetch=lambda u, n: png)["verdict"], "merge")
        self.assertIn("The logo is the image that was signed", failed(check(make(logo=logo), fetch=lambda u, n: png + b"!")))
        self.assertIn("The logo is the image that was signed", failed(check(make(logo=logo), fetch=lambda u, n: b"<svg/>")))

    def test_comment_carries_the_results(self):
        r = check(make(name="Unnamed"))
        body = C.comment(r)
        self.assertIn("✗", body)
        machine = json.loads(body.split("<!-- claim-check ")[1].rsplit(" -->", 1)[0])
        self.assertEqual(machine["verdict"], "reject")


class Resolution(unittest.TestCase):
    def test_latest_signature_wins(self):
        b = keys(SEED_B)["wallet"][0][0]
        first = make(name="Basalt", entropy=SEED_C, members=[b], height=39000, signers=[SEED_C, SEED_B])
        second = make(name="Halyard", members=[b], height=39500, signers=[SEED_A, SEED_B])
        r = C.resolve({first["anchor"]: first, second["anchor"]: second})
        self.assertEqual(r["holder"][b], second["anchor"])
        self.assertEqual(r["live"][first["anchor"]][1], [])
        self.assertEqual(r["live"][second["anchor"]][1], [b])

    def test_an_anchor_that_moved_voids_its_claim(self):
        b = keys(SEED_B)["wallet"]
        own_view = {"anchor": b[0][0], "name": "Copperhead", "block": block(39000), "members": []}
        own = C.assemble(own_view, sign_lines(own_view, SEED_B))
        later = make(members=[b[0][0]], height=39500, signers=[SEED_A, SEED_B])
        r = C.resolve({own["anchor"]: own, later["anchor"]: later})
        self.assertIn(own["anchor"], r["void"])

    def test_name_clash_earlier_wins(self):
        a, c = make(name="Halyard", height=39500), make(name="halyard", entropy=SEED_C, height=39000)
        r = C.resolve({a["anchor"]: a, c["anchor"]: c})
        self.assertIn(c["anchor"], r["live"])
        self.assertIn(a["anchor"], r["void"])

    def test_bad_claims_are_skipped(self):
        a = make()
        a["name"] = "Changed"
        self.assertIn(a["anchor"], C.resolve({a["anchor"]: a})["skipped"])

    def test_index(self):
        a = make(website="https://halyard.example", members=[keys(SEED_A)["wallet"][0][0]])
        doc = C.index({a["anchor"]: a})
        self.assertEqual(doc["claims"][0]["name"], "Halyard")
        self.assertEqual(doc["claims"][0]["members"], [keys(SEED_A)["wallet"][0][0]])


class Script(unittest.TestCase):
    def run_script(self, args, answer="y\n"):
        return subprocess.run([sys.executable, os.path.join(ROOT, "crosslink-claim.py")] + args,
                              input=answer, capture_output=True, text=True, timeout=120)

    def test_end_to_end(self):
        k = keys(SEED_A)
        view = {"anchor": k["finalizer"], "name": "Halyard", "block": block(39990), "members": [k["wallet"][1][0]],
                "website": "https://halyard.example"}
        with tempfile.TemporaryDirectory() as d:
            seed = os.path.join(d, "secret.seed")
            with open(seed, "wb") as f:
                f.write(SEED_A)
            p = self.run_script(["--seed-file", seed, "--challenge", C.encode_challenge(view)])
            self.assertEqual(p.returncode, 0, p.stderr)
            lines = p.stdout.strip().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertNotIn(SEED_A.hex(), p.stdout + p.stderr)
            self.assertNotIn(S.default_bft_key_seed(SEED_A), p.stdout + p.stderr)
            self.assertEqual(check(C.assemble(view, lines))["verdict"], "merge")

            p = self.run_script(["--seed-file", seed, "--challenge", C.encode_challenge(view)], answer="n\n")
            self.assertEqual((p.returncode, p.stdout), (2, ""))

    def test_explicit_seed_file(self):
        fk = S.finalizer_key(b"my explicit seed")
        view = {"anchor": S.finalizer_address(fk), "name": "Halyard", "block": block(39990)}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bft")
            with open(p, "w") as f:
                f.write("my explicit seed\n")
            r = self.run_script(["--bft-key-seed-file", p, "--challenge", C.encode_challenge(view)])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(check(C.assemble(view, r.stdout.strip().splitlines()))["verdict"], "merge")

    def test_wrong_seed_says_why(self):
        view = {"anchor": keys(SEED_C)["finalizer"], "name": "Halyard", "block": block(39990)}
        with tempfile.TemporaryDirectory() as d:
            seed = os.path.join(d, "secret.seed")
            with open(seed, "wb") as f:
                f.write(SEED_A)
            r = self.run_script(["--seed-file", seed, "--challenge", C.encode_challenge(view)])
            self.assertEqual(r.returncode, 2)
            self.assertIn("holds none of the claim's addresses", r.stderr)
            self.assertIn("explicit_bft_key_seed", r.stderr)


if __name__ == "__main__":
    unittest.main()
