"""Crosslink profile claims: the file format, the message each key signs, and every check a claim
has to pass. CI runs these on each pull request; anyone can run them to re-check the registry
(see tools/check.py).

The messages here must stay byte-for-byte the same as crosslink-claim.py's, which signs them;
tests/test_claims.py checks that they are.
"""

import base64
import hashlib
import json
import os
import re
import unicodedata
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

HEADER = "Crosslink profile claim v1"
NETWORK = "Crosslink v14"
MAX_AGE = 3456  # blocks a signature stays usable for: about a day at 25 s blocks
MAX_MEMBERS = 100
MAX_FILE_BYTES = 32 * 1024
MAX_LOGO_BYTES = 1024 * 1024
FINALIZER_ADDRESS_MSG = b"Zcash Crosslink Finalizer Address v1"
DEFAULT_CHAIN_API = "https://holdfast.crosslink.encapsulate.xyz"
CTAZ_LABELS = "https://ctaz.cash/v14/api/labels"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIELDS = [  # optional profile fields, in the order the anchor's message lists them
    ("description", "Description"),
    ("website", "Website"),
    ("x", "X"),
    ("github", "GitHub"),
    ("security_contact", "Security contact"),
]
TOP_KEYS = {"version", "network", "anchor", "name", "logo", "block", "pubkey", "signature", "members"} | {k for k, _ in FIELDS}
REQUIRED = {"version", "network", "anchor", "name", "block", "pubkey", "signature"}
MEMBER_KEYS = {"address", "block", "pubkey", "signature"}

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TESTNET_P2PKH = bytes.fromhex("1d25")  # tm…
TESTNET_P2SH = bytes.fromhex("1cba")  # t2…


class ClaimError(Exception):
    pass


def short(addr):
    return addr[:10] + "…" + addr[-6:] if isinstance(addr, str) and len(addr) > 20 else str(addr)


# ---- Addresses -------------------------------------------------------------------------------

class Address:
    def __init__(self, kind, text, key):
        self.kind = kind  # "finalizer" or "miner"
        self.text = text
        self.key = key  # finalizer: the ed25519 public key; miner: HASH160 of the public key


def _ed25519_ok(pub, sig, msg):
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def b58check_decode(s):
    n = 0
    for ch in s:
        i = B58.find(ch)
        if i < 0:
            raise ClaimError("%s isn't base58" % short(s))
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    body = b"\0" * (len(s) - len(s.lstrip("1"))) + body
    if len(body) < 5 or hashlib.sha256(hashlib.sha256(body[:-4]).digest()).digest()[:4] != body[-4:]:
        raise ClaimError("%s has a bad checksum: a character is wrong or missing" % short(s))
    return body[:-4]


def parse_address(s):
    """An address that can sign a claim: a finalizer (zfinv1…) or a transparent key address (tm…)."""
    if not isinstance(s, str) or not s:
        raise ClaimError("an address must be a non-empty string")
    if s.startswith("zfinv1"):
        if not re.fullmatch(r"zfinv1[A-Za-z0-9_-]{128}", s):
            raise ClaimError("%s isn't a finalizer address: those are zfinv1 and 128 more characters" % short(s))
        raw = base64.urlsafe_b64decode(s[6:])
        if not _ed25519_ok(raw[:32], raw[32:], FINALIZER_ADDRESS_MSG):
            raise ClaimError("%s isn't a valid finalizer address: its built-in signature doesn't verify" % short(s))
        return Address("finalizer", s, raw[:32])
    if s.startswith(("utest", "ztestsapling", "u1", "zs1", "zc")):
        raise ClaimError("%s is a shielded address. Only finalizer (zfinv1…) and miner (tm…) addresses can be claimed" % short(s))
    if re.fullmatch(r"t[1-9A-HJ-NP-Za-km-z]{25,40}", s):
        body = b58check_decode(s)
        if body[:2] == TESTNET_P2PKH and len(body) == 22:
            return Address("miner", s, body[2:])
        if body[:2] == TESTNET_P2SH:
            raise ClaimError("%s is a script address (t2…), which has no key to sign with. Claim a key address (tm…)" % short(s))
    raise ClaimError("%s isn't a finalizer (zfinv1…) or miner (tm…) address on this network" % short(s))


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


# ---- Messages ----------------------------------------------------------------------------------

def signed_view(claim):
    """The claim as its anchor signs it: member objects reduced to their addresses."""
    v = {k: claim[k] for k in ("anchor", "name", "block", "logo") if k in claim}
    v.update({k: claim[k] for k, _ in FIELDS if k in claim})
    v["members"] = [m["address"] for m in claim.get("members", [])]
    return v


def anchor_message(view):
    lines = [HEADER, "Network: " + NETWORK, "Anchor: " + view["anchor"], "Name: " + view["name"]]
    for key, label in FIELDS:
        if view.get(key):
            lines.append(label + ": " + view[key])
    if view.get("logo"):
        lines.append("Logo: %s sha256:%s" % (view["logo"]["url"], view["logo"]["sha256"]))
    if view.get("members"):
        lines.append("Members: " + ", ".join(view["members"]))
    lines.append("Block: %d %s" % (view["block"]["height"], view["block"]["hash"]))
    return "\n".join(lines).encode()


def member_message(member, anchor, block):
    return "\n".join([
        HEADER,
        "Network: " + NETWORK,
        "Member: " + member,
        "Anchor: " + anchor,
        "Block: %d %s" % (block["height"], block["hash"]),
    ]).encode()


def signature_problem(addr, pubkey_hex, sig_hex, msg):
    """None if the signature is valid for this address and message, else what's wrong."""
    if not isinstance(pubkey_hex, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", pubkey_hex):
        return "its public key isn't lowercase hex"
    if not isinstance(sig_hex, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", sig_hex):
        return "its signature isn't lowercase hex"
    pub, sig = bytes.fromhex(pubkey_hex), bytes.fromhex(sig_hex)
    if addr.kind == "finalizer":
        if pub != addr.key:
            return "its public key isn't the one in the address"
        if len(sig) != 64 or not _ed25519_ok(pub, sig, msg):
            return "the ed25519 signature doesn't verify"
        return None
    if len(pub) != 33 or pub[0] not in (2, 3):
        return "its public key isn't a compressed secp256k1 key (33 bytes, starting 02 or 03)"
    if hash160(pub) != addr.key:
        return "its public key doesn't belong to the address"
    if len(sig) > 72:
        return "the signature is too long for a DER ECDSA signature"
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub).verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return "the ECDSA signature doesn't verify"
    return None


# ---- From the claim page to a claim file -------------------------------------------------------
# The page builds a challenge from the form and a recent block; crosslink-claim.py signs it and
# prints one line per key; the page turns the lines into the claim file. The explorer's own code
# does the same; these are the reference.

def encode_challenge(view):
    """The --challenge code: base64url (no padding) of the signed view as compact JSON."""
    c = {"v": 1, "network": NETWORK}
    c.update({k: v for k, v in view.items() if v not in (None, "", [])})
    return base64.urlsafe_b64encode(json.dumps(c, separators=(",", ":"), ensure_ascii=False).encode()).decode().rstrip("=")


LINE_RE = re.compile(r"crosslink-claim-v1 (\S+) ([0-9]+) ([0-9a-f]+) ([0-9a-f]+)")


def parse_line(line):
    """(address, block height, public key hex, signature hex) from a line crosslink-claim.py printed."""
    m = LINE_RE.fullmatch(line.strip())
    if not m:
        raise ClaimError("that isn't a line crosslink-claim.py printed: it starts crosslink-claim-v1, then four fields")
    return m.group(1), int(m.group(2)), m.group(3), m.group(4)


def assemble(view, lines, previous=None):
    """The claim file from the signed view and the pasted lines. A member that didn't sign again
    keeps its signature from `previous`, the claim being replaced."""
    got = {}
    for line in lines:
        addr, height, pub, sig = parse_line(line)
        if height != view["block"]["height"]:
            raise ClaimError("the line for %s was signed for block %d, not this challenge's %d" % (short(addr), height, view["block"]["height"]))
        got[addr] = (pub, sig)
    if view["anchor"] not in got:
        raise ClaimError("no line for the anchor, %s" % short(view["anchor"]))
    old = {m["address"]: m for m in (previous or {}).get("members", [])}
    members = []
    for a in view.get("members", []):
        if a in got:
            members.append({"address": a, "block": view["block"], "pubkey": got[a][0], "signature": got[a][1]})
        elif a in old:
            members.append(old[a])
        else:
            raise ClaimError("no line for the member %s" % short(a))
    claim = {"version": 1, "network": NETWORK, "anchor": view["anchor"], "name": view["name"]}
    claim.update({k: view[k] for k, _ in FIELDS if view.get(k)})
    if view.get("logo"):
        claim["logo"] = view["logo"]
    claim.update({"block": view["block"], "pubkey": got[view["anchor"]][0], "signature": got[view["anchor"]][1]})
    if members:
        claim["members"] = members
    return claim


# ---- The fields --------------------------------------------------------------------------------

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}")
HOST = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
HTTPS_RE = re.compile(r"https://" + HOST + r"(?::[0-9]{1,5})?(?:[/?#][A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?")
X_RE = re.compile(r"https://x\.com/[A-Za-z0-9_]{1,15}")
GITHUB_RE = re.compile(r"https://github\.com/[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}(?:/[A-Za-z0-9._-]{1,100})?")
EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@" + HOST)
BAD_CATEGORIES = {"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"}


def name_problems(name):
    if not isinstance(name, str):
        return ["the name must be text"]
    if not NAME_RE.fullmatch(name):
        return ["a name is 1 to 32 characters: letters, digits, spaces, '.', '_' and '-', starting with a letter or digit"]
    if name != name.rstrip() or "  " in name:
        return ["a name can't end with a space or hold two spaces in a row"]
    return []


def field_problems(claim):
    out = []
    d = claim.get("description")
    if d is not None:
        if not isinstance(d, str) or not d.strip():
            out.append("description: give text, or leave the field out")
        else:
            if len(d) > 280:
                out.append("description: at most 280 characters (this one has %d)" % len(d))
            if d != d.strip():
                out.append("description: no spaces at the start or end")
            if any(unicodedata.category(ch) in BAD_CATEGORIES for ch in d):
                out.append("description: no line breaks, tabs or invisible formatting characters")
            if re.search(r"://|www\.", d, re.I):
                out.append("description: no links (put a website in the website field)")
    rules = {
        "website": (lambda v: len(v) <= 200 and HTTPS_RE.fullmatch(v), "an https:// link with a lowercase domain, at most 200 characters"),
        "x": (X_RE.fullmatch, "an X profile link: https://x.com/<handle>"),
        "github": (GITHUB_RE.fullmatch, "a GitHub link: https://github.com/<account> or https://github.com/<account>/<repo>"),
        "security_contact": (lambda v: len(v) <= 254 and (EMAIL_RE.fullmatch(v) or HTTPS_RE.fullmatch(v)), "an email address, or an https:// link"),
    }
    for key, (ok, want) in rules.items():
        v = claim.get(key)
        if v is not None and not (isinstance(v, str) and ok(v)):
            out.append("%s: must be %s" % (key.replace("_", " "), want))
    logo = claim.get("logo")
    if logo is not None:
        if not (isinstance(logo, dict) and set(logo) == {"url", "sha256"}):
            out.append("logo: must hold exactly url and sha256")
        else:
            if not (isinstance(logo["url"], str) and len(logo["url"]) <= 300 and HTTPS_RE.fullmatch(logo["url"])):
                out.append("logo: the url must be an https:// link of at most 300 characters")
            if not (isinstance(logo["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", logo["sha256"])):
                out.append("logo: sha256 must be the image's SHA-256 in lowercase hex")
    return out


def _block_problem(b, where):
    if not (isinstance(b, dict) and set(b) == {"height", "hash"}):
        return "%s: block must hold exactly height and hash" % where
    if type(b["height"]) is not int or b["height"] < 0:
        return "%s: the block height must be a whole number" % where
    if not (isinstance(b["hash"], str) and re.fullmatch(r"[0-9a-f]{64}", b["hash"])):
        return "%s: the block hash must be 64 lowercase hex characters" % where
    return None


def structure_problems(claim):
    """The file's shape. Content rules (name, fields, signatures) are checked separately."""
    if not isinstance(claim, dict):
        return ["the file must hold one JSON object"]
    out = []
    unknown = sorted(set(claim) - TOP_KEYS)
    if unknown:
        out.append("unknown keys: " + ", ".join(unknown))
    missing = sorted(REQUIRED - set(claim))
    if missing:
        out.append("missing keys: " + ", ".join(missing))
    if claim.get("version") != 1:
        out.append("version must be 1")
    if claim.get("network") != NETWORK:
        out.append("network must be %r" % NETWORK)
    if "block" in claim:
        p = _block_problem(claim["block"], "the claim")
        if p:
            out.append(p)
    members = claim.get("members", [])
    if not isinstance(members, list):
        out.append("members must be a list")
        return out
    if len(members) > MAX_MEMBERS:
        out.append("at most %d members" % MAX_MEMBERS)
    for i, m in enumerate(members):
        if not (isinstance(m, dict) and set(m) == MEMBER_KEYS):
            out.append("member %d must hold exactly address, block, pubkey and signature" % (i + 1))
            continue
        p = _block_problem(m["block"], "member %d" % (i + 1))
        if p:
            out.append(p)
    addrs = [m.get("address") for m in members if isinstance(m, dict)]
    if all(isinstance(a, str) for a in addrs):
        if addrs != sorted(set(addrs)):
            out.append("members must be sorted by address, each listed once")
        if claim.get("anchor") in addrs:
            out.append("the anchor can't also be a member")
    return out


# ---- Names -------------------------------------------------------------------------------------

def name_key(name):
    """Two names with the same key are the same name: case, spaces, '.', '_' and '-' don't count."""
    return re.sub(r"[ ._-]", "", name.casefold())


_LOOKALIKE = str.maketrans({"0": "o", "1": "l", "i": "l", "5": "s", "3": "e", "4": "a", "7": "t", "8": "b", "9": "g"})


def skeleton(name):
    """Names that look alike share a skeleton: digits for letters, rn for m, doubled letters."""
    k = name_key(name).translate(_LOOKALIKE).replace("rn", "m").replace("vv", "w")
    return re.sub(r"(.)\1+", r"\1", k)


def read_list(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]


# ---- Reading the registry ----------------------------------------------------------------------

def load_dir(path):
    """{anchor: claim} for every claims/*.json, plus {file: problem} for files that don't parse."""
    claims, bad = {}, {}
    if not os.path.isdir(path):
        return claims, bad
    for fn in sorted(os.listdir(path)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(path, fn), "rb") as f:
                c = json.loads(f.read(MAX_FILE_BYTES + 1).decode("utf-8"))
            if not isinstance(c, dict) or c.get("anchor") + ".json" != fn:
                raise ClaimError("the file name isn't its anchor")
            claims[c["anchor"]] = c
        except (ValueError, TypeError, ClaimError, UnicodeDecodeError) as e:
            bad[fn] = str(e)
    return claims, bad


def own_problems(claim):
    """Everything about a claim that needs nothing but the claim itself, as a list of problems.
    Members whose own signature fails are reported separately, by address."""
    probs = structure_problems(claim)
    if probs:
        return probs, {}
    probs += name_problems(claim["name"])
    probs += field_problems(claim)
    try:
        anchor = parse_address(claim["anchor"])
    except ClaimError as e:
        return probs + ["anchor: %s" % e], {}
    p = signature_problem(anchor, claim["pubkey"], claim["signature"], anchor_message(signed_view(claim)))
    if p:
        probs.append("the anchor's signature: " + p)
    bad_members = {}
    for m in claim.get("members", []):
        try:
            a = parse_address(m["address"])
            if a.kind != "miner":
                raise ClaimError("members must be miner addresses (tm…)")
            p = signature_problem(a, m["pubkey"], m["signature"], member_message(a.text, claim["anchor"], m["block"]))
            if p:
                raise ClaimError(p)
        except ClaimError as e:
            bad_members[m["address"]] = str(e)
    return probs, bad_members


def resolve(claims):
    """Who holds which name, from {anchor: claim}. The rules every reader applies:
      1. A claim whose own checks fail is skipped; so is a member whose signature fails.
      2. An address belongs to the claim where it signed at the latest block: its own claim as
         the anchor, or another as a member. At the same block its own claim wins.
      3. A claim whose anchor now belongs to another claim is void.
      4. If two live claims hold the same name, the one signed at the earlier block keeps it and
         the other is void.
    Returns {"live": {anchor: (claim, [member addresses it holds])}, "void": {anchor: reason},
    "skipped": {anchor: [problems]}, "holder": {address: anchor}}."""
    ok, skipped = {}, {}
    for anchor, c in claims.items():
        probs, bad_members = own_problems(c)
        if probs:
            skipped[anchor] = probs
            continue
        ok[anchor] = (c, [m for m in c.get("members", []) if m["address"] not in bad_members])
    void = {}
    while True:
        best = {}
        for anchor, (c, members) in ok.items():
            if anchor in void:
                continue
            for addr, height, own in [(anchor, c["block"]["height"], 1)] + [(m["address"], m["block"]["height"], 0) for m in members]:
                rank = (height, own, [-ord(ch) for ch in anchor])
                if addr not in best or rank > best[addr][0]:
                    best[addr] = (rank, anchor)
        holder = {a: v[1] for a, v in best.items()}
        new = {}
        for anchor in ok:
            if anchor not in void and holder.get(anchor) != anchor:
                new[anchor] = "its anchor signed into the claim %s at a later block" % short(holder.get(anchor))
        by_name = {}
        for anchor, (c, _) in ok.items():
            if anchor not in void and anchor not in new:
                by_name.setdefault(name_key(c["name"]), []).append(anchor)
        for anchors in by_name.values():
            anchors.sort(key=lambda a: (ok[a][0]["block"]["height"], a))
            for a in anchors[1:]:
                new[a] = "the name is already held by %s, signed at an earlier block" % short(anchors[0])
        if not new:
            break
        void.update(new)
    live = {a: (c, [m["address"] for m in ms if holder.get(m["address"]) == a]) for a, (c, ms) in ok.items() if a not in void}
    return {"live": live, "void": void, "skipped": skipped, "holder": holder}


def index(claims, commit=None):
    """The resolved registry as one JSON document, for explorers that don't run these checks."""
    r = resolve(claims)
    out = []
    for anchor in sorted(r["live"]):
        c, held = r["live"][anchor]
        entry = {"anchor": anchor, "role": "finalizer" if anchor.startswith("zfinv1") else "miner", "name": c["name"]}
        entry.update({k: c[k] for k, _ in FIELDS if k in c})
        if "logo" in c:
            entry["logo"] = c["logo"]
        entry.update({"members": held, "block": c["block"], "file": "claims/%s.json" % anchor})
        if anchor.startswith("zfinv1"):
            entry["pubkey"] = c["pubkey"]
        out.append(entry)
    doc = {"network": NETWORK, "claims": out, "void": [{"anchor": a, "reason": why} for a, why in sorted(r["void"].items())],
           "skipped": [{"anchor": a, "problems": p} for a, p in sorted(r["skipped"].items())]}
    if commit:
        doc["commit"] = commit
    return doc


# ---- The chain ---------------------------------------------------------------------------------

def _get_json(url, data=None, timeout=20):
    req = urllib.request.Request(url, data=data, headers={"user-agent": "crosslink-profiles-check", "content-type": "application/json"})
    last = None
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read(4 * 1024 * 1024))
        except (OSError, ValueError) as e:
            last = e
    raise ClaimError("couldn't read %s: %s" % (url.split("?")[0], last))


class HoldfastChain:
    """The chain as Holdfast's public API serves it."""

    def __init__(self, base=DEFAULT_CHAIN_API):
        self.base = base.rstrip("/")
        self.label = "Holdfast (%s)" % self.base

    def tip(self):
        return int(_get_json(self.base + "/api/tip")["tip"])

    def hash_at(self, height):
        rows = _get_json("%s/api/blocks?h=%d" % (self.base, height))
        return rows[0]["hash"] if rows else None


class NodeChain:
    """The chain as a node's JSON-RPC serves it (getblockcount, getblockhash)."""

    def __init__(self, url):
        self.url = url
        self.label = "the node at %s" % url

    def _call(self, method, params):
        r = _get_json(self.url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode())
        if r.get("error"):
            return None
        return r.get("result")

    def tip(self):
        return int(self._call("getblockcount", []))

    def hash_at(self, height):
        return self._call("getblockhash", [height])


def fetch_bytes(url, limit):
    req = urllib.request.Request(url, headers={"user-agent": "crosslink-profiles-check"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ClaimError("the logo is larger than %d KB" % (limit // 1024))
    return data


def ctaz_names():
    """[(address, name)] from ctaz.cash's claims, or None if it can't be read."""
    try:
        doc = _get_json(CTAZ_LABELS, timeout=15)
        return [(l["address"], l["name"]) for l in doc.get("labels", []) if isinstance(l, dict) and isinstance(l.get("name"), str)]
    except (ClaimError, KeyError, TypeError, AttributeError):
        return None


# ---- Checking a submitted claim ----------------------------------------------------------------

def check_claim(path, claim, base, chain, approved=False, ctaz=None, fetch=fetch_bytes):
    """Checks a claim file submitted at `path` against the registry `base` ({anchor: claim}, before
    the change) and the chain. Returns {"verdict": "merge" | "review" | "reject", "checks": [...],
    "review": [reasons], "notes": [...]}. `approved` (a maintainer's review-approved label) skips
    the name review and the age limit, which a review can outlast."""
    checks, review, notes = [], [], []

    def add(label, problems):
        checks.append({"check": label, "ok": not problems, "detail": "; ".join(problems)})
        return not problems

    def done():
        verdict = "reject" if not all(c["ok"] for c in checks) else ("review" if review else "merge")
        return {"verdict": verdict, "checks": checks, "review": review, "notes": notes,
                "anchor": claim.get("anchor") if isinstance(claim, dict) else None,
                "name": claim.get("name") if isinstance(claim, dict) else None}

    if not add("The file is a well-formed claim", structure_problems(claim)):
        return done()
    anchor_text = claim["anchor"]
    add("The file is named after its anchor", [] if path == "claims/%s.json" % anchor_text else
        ["the file must be claims/<anchor address>.json"])

    reserved = {name_key(n) for n in read_list("names/reserved.txt")}
    np = name_problems(claim["name"])
    if not np and name_key(claim["name"]) in reserved:
        np = ["%r is reserved: it would mislead people about who runs the address" % claim["name"]]
    add("The name follows the rules", np)
    add("The profile fields follow the rules", field_problems(claim))

    try:
        anchor = parse_address(anchor_text)
        ap = []
    except ClaimError as e:
        anchor, ap = None, [str(e)]
    if anchor:
        p = signature_problem(anchor, claim["pubkey"], claim["signature"], anchor_message(signed_view(claim)))
        if p:
            ap.append(p)
    add("The anchor's signature is valid", ap)

    mp = []
    for m in claim.get("members", []):
        try:
            a = parse_address(m["address"])
        except ClaimError as e:
            mp.append(str(e))
            continue
        if a.kind != "miner":
            mp.append("%s: members must be miner addresses (tm…)" % short(m["address"]))
            continue
        p = signature_problem(a, m["pubkey"], m["signature"], member_message(a.text, anchor_text, m["block"]))
        if p:
            mp.append("%s: %s" % (short(m["address"]), p))
    if claim.get("members"):
        add("Each member's signature is valid", mp)

    blocked = set(read_list("names/blocked-addresses.txt"))
    addrs = [anchor_text] + [m["address"] for m in claim.get("members", [])]
    add("No address has a public key anyone can sign with",
        ["%s is the shared faucet wallet or another wallet whose seed is public: anyone could sign for it" % short(a)
         for a in addrs if a in blocked])

    # The blocks: on the chain, and recent for every signature that's new in this change.
    old = base.get(anchor_text)
    old_members = {m["address"]: m for m in (old or {}).get("members", [])}
    bp = []
    try:
        tip = chain.tip()
        fresh = [("the claim", claim["block"])] + [
            (short(m["address"]), m["block"]) for m in claim.get("members", []) if old_members.get(m["address"]) != m]
        for who, b in fresh:
            if b["height"] > tip:
                bp.append("%s: block %d is past the tip (%d)" % (who, b["height"], tip))
                continue
            h = chain.hash_at(b["height"])
            if h != b["hash"]:
                bp.append("%s: block %d on the chain is %s, not the hash signed" % (who, b["height"], (h or "missing")[:16] + "…"))
            elif tip - b["height"] > MAX_AGE and not approved:
                bp.append("%s: block %d is %d blocks old; a signature is good for %d. Sign a new challenge" % (who, b["height"], tip - b["height"], MAX_AGE))
        notes.append("Chain read from %s at block %d." % (chain.label, tip))
    except ClaimError as e:
        return {"verdict": "error", "checks": checks, "review": [], "notes": [str(e)], "anchor": anchor_text, "name": claim["name"]}
    add("The blocks are on the chain and recent", bp)

    if old is not None:
        add("It replaces the older claim with a later one",
            [] if claim["block"]["height"] > old["block"]["height"] else
            ["the current claim is signed at block %d; a replacement must be signed at a later block" % old["block"]["height"]])

    # The registry as it stands, without this claim's current version.
    others = {a: c for a, c in base.items() if a != anchor_text}
    r = resolve(others)
    live = r["live"]
    rp = []
    key = name_key(claim["name"])
    for a, (c, _) in live.items():
        if name_key(c["name"]) == key:
            rp.append("%r is already claimed by %s (claims/%s.json)" % (c["name"], short(a), a))
    if anchor and anchor.kind == "finalizer":
        for a, c in others.items():
            if a.startswith("zfinv1") and c.get("pubkey") == anchor.key.hex():
                rp.append("this finalizer key already has a claim, under another form of its address (claims/%s.json)" % a)
    for m in claim.get("members", []):
        if m["address"] in live:
            rp.append("%s has its own claim (%r); it can't also be a member of another" % (short(m["address"]), live[m["address"]][0]["name"]))
        elif r["holder"].get(m["address"]) in live:
            notes.append("%s moves to this claim from %r." % (short(m["address"]), live[r["holder"][m["address"]]][0]["name"]))
    if r["holder"].get(anchor_text) in live:
        notes.append("%s leaves %r to anchor this claim." % (short(anchor_text), live[r["holder"][anchor_text]][0]["name"]))
    add("The name and addresses are free", rp)

    # A logo has to be the image whose hash was signed.
    logo = claim.get("logo")
    if logo and not field_problems({"logo": logo}) and (old is None or old.get("logo") != logo):
        lp = []
        try:
            data = fetch(logo["url"], MAX_LOGO_BYTES)
            if not (data.startswith(b"\x89PNG\r\n\x1a\n") or data.startswith(b"\xff\xd8\xff") or (data[:4] == b"RIFF" and data[8:12] == b"WEBP")):
                lp.append("the logo must be a PNG, JPEG or WebP image")
            elif hashlib.sha256(data).hexdigest() != logo["sha256"]:
                lp.append("the image at the logo's url doesn't match the signed sha256")
        except (ClaimError, OSError, ValueError) as e:
            lp.append("couldn't fetch the logo: %s" % e)
        add("The logo is the image that was signed", lp)

    # Names that need a person to look: like a known organisation's, or like another's name.
    if not approved and not np:
        sk = skeleton(claim["name"])
        for org in read_list("names/review.txt"):
            ok_ = skeleton(org)
            if sk == ok_ or (len(ok_) >= 5 and ok_ in sk):
                review.append("%r resembles %r, a known organisation's name" % (claim["name"], org))
        for a, (c, _) in live.items():
            if name_key(c["name"]) != key and skeleton(c["name"]) == sk:
                review.append("%r looks like %r, claimed by %s" % (claim["name"], c["name"], short(a)))
        if ctaz is not None:
            mine = set(addrs)
            for addr, n in ctaz:
                if addr not in mine and (name_key(n) == key or skeleton(n) == sk):
                    review.append("%r matches %r, which %s claimed on ctaz.cash" % (claim["name"], n, short(addr)))
        else:
            notes.append("ctaz.cash's claims couldn't be read, so names weren't compared with them.")
    return done()


def comment(result):
    """The pull request comment: each check's result, then what happens next."""
    v = result["verdict"]
    head = {
        "merge": "All checks passed. Merging; the explorer shows the profile within about 5 minutes.",
        "review": "All checks passed, but the name needs a maintainer to look at it first. It isn't rejected.",
        "reject": "Not merged: a check failed. Fix it and sign a new challenge on the claim page.",
        "error": "This claim couldn't be checked right now. A maintainer will run the check again.",
    }[v]
    lines = ["**%s**" % head, ""]
    if result.get("name"):
        lines += ["Claim: **%s** for `%s`" % (result["name"], short(result.get("anchor"))), ""]
    if result["checks"]:
        lines += ["| Check | Result |", "|---|---|"]
        for c in result["checks"]:
            lines.append("| %s | %s |" % (c["check"], "✓" if c["ok"] else "✗ " + c["detail"].replace("|", "\\|")))
        lines.append("")
    if result["review"]:
        lines += ["Why it needs a review:", ""] + ["- " + r for r in result["review"]] + [""]
        lines += ["A maintainer adds the `review-approved` label once they've checked the name belongs to whoever runs these addresses.", ""]
    if result["notes"]:
        lines += ["- " + n for n in result["notes"]] + [""]
    machine = {k: result.get(k) for k in ("verdict", "checks", "review", "notes", "anchor", "name")}
    lines.append("<!-- claim-check %s -->" % json.dumps(machine, ensure_ascii=True).replace("--", "-\\u002d"))
    return "\n".join(lines)
