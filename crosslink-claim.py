#!/usr/bin/env python3
"""Signs a Crosslink profile claim with the keys a node's seed holds. Offline: it reads the seed,
prints what it will sign, asks first, and prints one line per key. Nothing is sent anywhere, and
nothing it signs can move funds.

    python3 crosslink-claim.py --seed-file <path to secret.seed> --challenge <code>

The claim page (https://holdfast.crosslink.encapsulate.xyz) builds the code. Paste the lines this
prints back into it.

secret.seed is in the network's folder inside the node's cache directory:
    Linux    ~/.cache/zebra/crosslink_featurenet_20260929/secret.seed
    macOS    ~/Library/Caches/zebra/crosslink_featurenet_20260929/secret.seed
    Windows  %LOCALAPPDATA%\\zebra\\crosslink_featurenet_20260929\\secret.seed
A node that sets cache_dir under [state] keeps it in that folder instead.

From one secret.seed it derives the keys the node itself derives: the finalizer key (unless the
node sets explicit_bft_key_seed: pass that value in a file with --bft-key-seed-file) and the
wallet's transparent addresses (m/44'/1'/0'/0/i). It signs only the claim's lines whose address
is one of those keys.

Needs Python 3.8 or later and the cryptography package:
    sudo apt install python3-cryptography      (Debian, Ubuntu)
    python3 -m pip install --user cryptography (anywhere else)
"""

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
except ImportError:
    sys.exit(
        "This needs the Python cryptography package:\n"
        "  sudo apt install python3-cryptography       (Debian, Ubuntu)\n"
        "  python3 -m pip install --user cryptography  (anywhere else)"
    )

HEADER = "Crosslink profile claim v1"
NETWORK = "Crosslink v14"
FINALIZER_ADDRESS_MSG = b"Zcash Crosslink Finalizer Address v1"
WALLET_ADDRESSES = 20  # transparent addresses checked per seed: m/44'/1'/0'/0/0 to /19
FIELDS = [  # optional profile fields, in the order the anchor's message lists them
    ("description", "Description"),
    ("website", "Website"),
    ("x", "X"),
    ("github", "GitHub"),
    ("security_contact", "Security contact"),
]


class ClaimError(Exception):
    """A problem to show the operator. Its message never holds key material."""


# ---- Messages: the exact text each key signs ------------------------------------------------
# tools/claims.py builds the same messages to check the signatures; tests keep the two equal.

def anchor_message(claim):
    lines = [HEADER, "Network: " + NETWORK, "Anchor: " + claim["anchor"], "Name: " + claim["name"]]
    for key, label in FIELDS:
        if claim.get(key):
            lines.append(label + ": " + claim[key])
    if claim.get("logo"):
        lines.append("Logo: %s sha256:%s" % (claim["logo"]["url"], claim["logo"]["sha256"]))
    if claim.get("members"):
        lines.append("Members: " + ", ".join(claim["members"]))
    lines.append("Block: %d %s" % (claim["block"]["height"], claim["block"]["hash"]))
    return "\n".join(lines).encode()


def member_message(member, anchor, block):
    return "\n".join([
        HEADER,
        "Network: " + NETWORK,
        "Member: " + member,
        "Anchor: " + anchor,
        "Block: %d %s" % (block["height"], block["hash"]),
    ]).encode()


# ---- The finalizer key, as zcash_primitives bft::finalizer_key_from_seed derives it ---------
# Rust: DefaultHasher (SipHash-1-3, zero keys) over the seed string, StdRng::seed_from_u64 of
# that (rand_core's PCG32 expansion into a ChaCha12 key), then ed25519_zebra::SigningKey::new,
# which takes the first 32 bytes the RNG produces as the ed25519 seed.

MASK64 = (1 << 64) - 1


def _rotl64(x, b):
    return ((x << b) | (x >> (64 - b))) & MASK64


def siphash13(data):
    v0, v1, v2, v3 = 0x736F6D6570736575, 0x646F72616E646F6D, 0x6C7967656E657261, 0x7465646279746573

    def rounds(n):
        nonlocal v0, v1, v2, v3
        for _ in range(n):
            v0 = (v0 + v1) & MASK64
            v1 = _rotl64(v1, 13) ^ v0
            v0 = _rotl64(v0, 32)
            v2 = (v2 + v3) & MASK64
            v3 = _rotl64(v3, 16) ^ v2
            v0 = (v0 + v3) & MASK64
            v3 = _rotl64(v3, 21) ^ v0
            v2 = (v2 + v1) & MASK64
            v1 = _rotl64(v1, 17) ^ v2
            v2 = _rotl64(v2, 32)

    end = len(data) - len(data) % 8
    for i in range(0, end, 8):
        m = int.from_bytes(data[i:i + 8], "little")
        v3 ^= m
        rounds(1)
        v0 ^= m
    last = ((len(data) & 0xFF) << 56) | int.from_bytes(data[end:] + bytes(8 - len(data) + end), "little")
    v3 ^= last
    rounds(1)
    v0 ^= last
    v2 ^= 0xFF
    rounds(3)
    return v0 ^ v1 ^ v2 ^ v3


def _seed_from_u64(state):
    out = b""
    while len(out) < 32:
        state = (state * 6364136223846793005 + 11634580027462260723) & MASK64
        xorshifted = (((state >> 18) ^ state) >> 27) & 0xFFFFFFFF
        rot = state >> 59
        out += (((xorshifted >> rot) | (xorshifted << ((32 - rot) & 31))) & 0xFFFFFFFF).to_bytes(4, "little")
    return out


def _chacha12_first32(key):
    def rotl32(x, b):
        return ((x << b) | (x >> (32 - b))) & 0xFFFFFFFF

    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st += [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)] + [0, 0, 0, 0]
    w = list(st)

    def qr(a, b, c, d):
        w[a] = (w[a] + w[b]) & 0xFFFFFFFF
        w[d] = rotl32(w[d] ^ w[a], 16)
        w[c] = (w[c] + w[d]) & 0xFFFFFFFF
        w[b] = rotl32(w[b] ^ w[c], 12)
        w[a] = (w[a] + w[b]) & 0xFFFFFFFF
        w[d] = rotl32(w[d] ^ w[a], 8)
        w[c] = (w[c] + w[d]) & 0xFFFFFFFF
        w[b] = rotl32(w[b] ^ w[c], 7)

    for _ in range(6):
        qr(0, 4, 8, 12), qr(1, 5, 9, 13), qr(2, 6, 10, 14), qr(3, 7, 11, 15)
        qr(0, 5, 10, 15), qr(1, 6, 11, 12), qr(2, 7, 8, 13), qr(3, 4, 9, 14)
    return b"".join(((w[i] + st[i]) & 0xFFFFFFFF).to_bytes(4, "little") for i in range(8))


def default_bft_key_seed(entropy):
    """The string a node derives its finalizer key from when explicit_bft_key_seed isn't set:
    Rust's format!("Crosslink default finalizer identity seed {:?}", seed) over secret.seed."""
    return "Crosslink default finalizer identity seed [" + ", ".join(str(b) for b in entropy) + "]"


def finalizer_key(bft_key_seed):
    return ed25519.Ed25519PrivateKey.from_private_bytes(_chacha12_first32(_seed_from_u64(siphash13(bft_key_seed))))


def raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def finalizer_address(key):
    """zfinv1 + base64url(public key, its signature over the fixed address message)."""
    payload = raw_public(key) + key.sign(FINALIZER_ADDRESS_MSG)
    return "zfinv1" + base64.urlsafe_b64encode(payload).decode()


def finalizer_pubkey_of(address):
    if not re.fullmatch(r"zfinv1[A-Za-z0-9_-]{128}", address):
        raise ClaimError("the anchor isn't a finalizer address (zfinv1 and 128 characters)")
    return base64.urlsafe_b64decode(address[6:])[:32]


# ---- The wallet's transparent keys, as the node's wallet derives them ----------------------
# Crosslink wallet/lib.rs: the 32 bytes of secret.seed are BIP39 entropy for an English phrase;
# the wallet seed is the first 32 bytes of that phrase's BIP39 seed (empty passphrase); the
# transparent keys are BIP44 m/44'/1'/0'/0/i (testnet coin type 1), as UnifiedSpendingKey uses.

WORDS = """\
abandon ability able about above absent absorb abstract absurd abuse access accident account
accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict
address adjust admit adult advance advice aerobic affair afford afraid again age agent agree
ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha
already also alter always amateur amazing among amount amused analyst anchor ancient anger angle
angry animal ankle announce annual another answer antenna antique anxiety any apart apology
appear apple approve april arch arctic area arena argue arm armed armor army around arrange
arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma
athlete atom attack attend attitude attract auction audit august aunt author auto autumn average
avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance
balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean
beauty because become beef before begin behave behind believe below belt bench benefit best
betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame
blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb
bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass
brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother
brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst
bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp
can canal cancel candy cannon canoe canvas canyon capable capital captain car carbon card cargo
carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause
caution cave ceiling celery cement census century cereal certain chair chalk champion change
chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney
choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap
clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth
cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color
column combine come comfort comic common company concert conduct confirm congress connect
consider control convince cook cool copper copy coral core corn correct cost cotton couch
country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy
cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise
crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion
custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris
decade december decide decline decorate decrease deer defense define defy degree delay deliver
demand demise denial dentist deny depart depend deposit depth deputy derive describe desert
design desk despair destroy detail detect develop device devote diagram dial diamond diary dice
diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease
dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll
dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream
dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf
dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate
effort egg eight either elbow elder electric elegant element elephant elevator elite else embark
embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy energy
enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry
envelope episode equal equip era erase erode erosion error erupt escape essay essence estate
eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse
execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose
express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family
famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february
federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film
filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame
flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil
fold follow food foot force forest forget fork fortune forum forward fossil foster found fox
fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny
furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas
gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle
ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue
goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape
grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt
guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk
hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint
hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse
hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt
husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense
immune impact impose improve impulse inch include income increase index indicate indoor industry
infant inflict inform inhale inherit initial inject injury inmate inner innocent input inquiry
insane insect inside inspire install intact interest into invest invite involve iron island
isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey
joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind
kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake
lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader
leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson
letter level liar liberty library license life lift light like limb limit link lion liquid list
little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love
loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main
major make mammal man manage mandate mango mansion manual maple marble march margin marine
market marriage mask mass master match material math matrix matter maximum maze meadow mean
measure meat mechanic medal media melody melt member memory mention menu mercy merge merit merry
mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle
mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey
monster month moon moral more morning mosquito mother motion motor mountain mouse move movie
much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive
name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest
net network neutral never news next nice night noble noise nominee noodle normal north nose
notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure
observe obtain obvious occur ocean october odor off offer office often oil okay old olive
olympic omit once one onion online only open opera opinion oppose option orange orbit orchard
order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven
over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther
paper parade parent park parrot party pass patch path patient patrol pattern pause pave payment
peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet
phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe
pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet
point polar pole police pond pony pool popular portion position possible post potato pottery
poverty powder power practice praise predict prefer prepare present pretty prevent price pride
primary print priority prison private prize problem process produce profit program project
promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin
punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter
question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp
ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall
receive recipe record recycle reduce reflect reform refuse region regret regular reject relax
release relief rely remain remember remind remove render renew rent reopen repair repeat replace
report require rescue resemble resist resource response result retire retreat return reunion
reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple
risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate
rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad
salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan
scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea
search season seat second secret section security seed seek segment select sell seminar senior
sense sentence series service session settle setup seven shadow shaft shallow share shed shell
sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug
shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since
sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep
slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack
snake snap sniff snow soap soccer social sock soda soft solar soldier solid solution solve
someone song soon sorry sort soul sound soup source south space spare spatial spawn speak
special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport
spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp
stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool
story stove strategy street strike strong struggle student stuff stumble style subject submit
subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply
supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm
swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail
talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term
test text thank that theme then theory there they thing this thought three thrive throw thumb
thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today
toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic
topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic
tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim
trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel
turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware
uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until
unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless
usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle
velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious
victory video view village vintage violin virtual virus visa visit visual vital vivid vocal
voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior
wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird
welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win
window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool
word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young
youth zebra zero zone zoo
""".split()
assert hashlib.sha256(("\n".join(WORDS) + "\n").encode()).hexdigest() == \
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", "BIP39 word list damaged"

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def mnemonic(entropy):
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(256) + bin(hashlib.sha256(entropy).digest()[0])[2:].zfill(8)
    return " ".join(WORDS[int(bits[i:i + 11], 2)] for i in range(0, 264, 11))


def _compressed(k):
    return ec.derive_private_key(k, ec.SECP256K1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def _ckd(k, chain, index):
    data = (b"\0" + k.to_bytes(32, "big")) if index >= 1 << 31 else _compressed(k)
    i = hmac.new(chain, data + index.to_bytes(4, "big"), hashlib.sha512).digest()
    left = int.from_bytes(i[:32], "big")
    child = (left + k) % SECP256K1_N
    if left >= SECP256K1_N or child == 0:
        raise ClaimError("this seed hits an invalid BIP32 child key (vanishingly rare); it can't be used here")
    return child, i[32:]


def wallet_keys(entropy, count=WALLET_ADDRESSES):
    """[(tm address, compressed public key, private key)] for m/44'/1'/0'/0/0 .. count-1."""
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic(entropy).encode(), b"mnemonic", 2048)[:32]
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, chain = int.from_bytes(i[:32], "big"), i[32:]
    if not 0 < k < SECP256K1_N:
        raise ClaimError("this seed gives an invalid BIP32 master key (vanishingly rare); it can't be used here")
    for index in (44 + (1 << 31), 1 + (1 << 31), 0 + (1 << 31), 0):
        k, chain = _ckd(k, chain, index)
    out = []
    for n in range(count):
        child, _ = _ckd(k, chain, n)
        pub = _compressed(child)
        out.append((p2pkh_address(pub), pub, ec.derive_private_key(child, ec.SECP256K1())))
    return out


def p2pkh_address(pub):
    raw = bytes.fromhex("1d25") + hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


# ---- The challenge ---------------------------------------------------------------------------

def decode_challenge(code):
    if len(code) > 8192 or not re.fullmatch(r"[A-Za-z0-9_-]+", code):
        raise ClaimError("that isn't a challenge code: copy it again from the claim page")
    try:
        c = json.loads(base64.urlsafe_b64decode(code + "=" * (-len(code) % 4)))
    except ValueError:
        raise ClaimError("that challenge code is damaged: copy it again from the claim page")
    known = {"v", "network", "anchor", "name", "members", "block", "logo"} | {k for k, _ in FIELDS}
    if not isinstance(c, dict) or c.get("v") != 1 or not set(c) <= known:
        raise ClaimError("this challenge is for a different version of this script: download it again")
    if c.get("network") != NETWORK:
        raise ClaimError("this challenge is for another network (%r); this script signs for %s" % (c.get("network"), NETWORK))
    name, anchor, block = c.get("name"), c.get("anchor"), c.get("block")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}", name) or name != name.strip():
        raise ClaimError("the challenge's name doesn't follow the name rules")
    if not isinstance(anchor, str) or not (anchor.startswith("zfinv1") or anchor.startswith("tm")):
        raise ClaimError("the challenge's anchor isn't a finalizer (zfinv1…) or miner (tm…) address")
    if not (isinstance(block, dict) and isinstance(block.get("height"), int) and block["height"] >= 0
            and isinstance(block.get("hash"), str) and re.fullmatch(r"[0-9a-f]{64}", block["hash"])):
        raise ClaimError("the challenge's block is malformed")
    members = c.get("members", [])
    if not isinstance(members, list) or not all(isinstance(m, str) and re.fullmatch(r"tm[1-9A-HJ-NP-Za-km-z]{33}", m) for m in members):
        raise ClaimError("the challenge's members must be miner addresses (tm…)")
    if members != sorted(set(members)) or anchor in members:
        raise ClaimError("the challenge's members are out of order or repeated")
    for k, _ in FIELDS:
        if k in c and (not isinstance(c[k], str) or any(ord(ch) < 32 or ord(ch) == 127 for ch in c[k])):
            raise ClaimError("the challenge's %s holds a line break or another control character" % k)
    logo = c.get("logo")
    if logo is not None and not (isinstance(logo, dict) and set(logo) == {"url", "sha256"} and isinstance(logo["url"], str)
                                 and re.fullmatch(r"https://\S+", logo["url"]) and isinstance(logo["sha256"], str)
                                 and re.fullmatch(r"[0-9a-f]{64}", logo["sha256"])):
        raise ClaimError("the challenge's logo is malformed")
    return c


# ---- Main --------------------------------------------------------------------------------------

def read_seed_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read(33)
    except OSError as e:
        raise ClaimError("can't read %s: %s (run this as the user that owns the node's files)" % (path, e.strerror))
    if len(data) != 32:
        raise ClaimError("%s isn't a secret.seed: that file holds exactly 32 bytes" % path)
    return data


def read_bft_key_seed(path):
    try:
        with open(path, "rb") as f:
            raw = f.read(4097)
    except OSError as e:
        raise ClaimError("can't read %s: %s" % (path, e.strerror))
    if len(raw) > 4096:
        raise ClaimError("%s is too long to be an explicit_bft_key_seed value" % path)
    # The value as the config holds it. A file saved with a trailing newline, or with spaces
    # around the value, is tried both ways, and the one that matches the claim is used.
    exact = raw.rstrip(b"\r\n")
    return [exact] + ([raw.strip()] if raw.strip() != exact else [])


def short(addr):
    return addr[:10] + "…" + addr[-6:]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Signs a Crosslink profile claim offline with the keys a node's seed holds.")
    ap.add_argument("--challenge", required=True, help="the code from the claim page")
    ap.add_argument("--seed-file", help="the node's secret.seed")
    ap.add_argument("--bft-key-seed-file", help="a file holding the node's explicit_bft_key_seed, if it sets one")
    args = ap.parse_args(argv)
    if not args.seed_file and not args.bft_key_seed_file:
        ap.error("give --seed-file (and --bft-key-seed-file if the node sets explicit_bft_key_seed)")

    try:
        c = decode_challenge(args.challenge)
        anchor, block, members = c["anchor"], c["block"], c.get("members", [])
        entropy = read_seed_file(args.seed_file) if args.seed_file else None

        # What this seed holds: the finalizer key, and the wallet's transparent addresses.
        signers = {}  # address -> ("finalizer", key) or ("miner", (pubkey, key))
        own_finalizer = None
        bft_seeds = read_bft_key_seed(args.bft_key_seed_file) if args.bft_key_seed_file else [default_bft_key_seed(entropy).encode()]
        if anchor.startswith("zfinv1"):
            want = finalizer_pubkey_of(anchor)
            for s in bft_seeds:
                key = finalizer_key(s)
                if raw_public(key) == want:
                    signers[anchor] = ("finalizer", key)
                    break
            else:
                own_finalizer = finalizer_address(finalizer_key(bft_seeds[0]))
        if entropy is not None:
            wanted = set(members) | ({anchor} if anchor.startswith("tm") else set())
            for addr, pub, key in wallet_keys(entropy):
                if addr in wanted:
                    signers[addr] = ("miner", (pub, key))

        print("The claim:\n", file=sys.stderr)
        print("  " + anchor_message(c).decode().replace("\n", "\n  ") + "\n", file=sys.stderr)
        if not signers:
            lines = ["This seed holds none of the claim's addresses."]
            if own_finalizer:
                lines.append("Its finalizer address is %s, not the anchor." % short(own_finalizer))
                if not args.bft_key_seed_file:
                    lines.append("If the node sets explicit_bft_key_seed, put that value in a file and pass --bft-key-seed-file.")
            if entropy is not None:
                lines.append("Its wallet's first transparent address is %s." % wallet_keys(entropy, 1)[0][0])
            lines.append("Run this on the server whose node holds the key for each address.")
            raise ClaimError("\n".join(lines))

        print("This seed signs for:", file=sys.stderr)
        for addr in [anchor] + members:
            if addr in signers:
                role = "anchor: the name, the profile and its members" if addr == anchor else "member of " + short(anchor)
                print("  %s (%s)" % (addr, role), file=sys.stderr)
        missing = [a for a in [anchor] + members if a not in signers]
        if missing:
            print("Sign the rest on the servers that hold them:", file=sys.stderr)
            for a in missing:
                print("  " + a, file=sys.stderr)
        print("\nNothing is sent anywhere, and nothing signed here can move funds.", file=sys.stderr)
        sys.stderr.write("Sign? [y/N] ")  # stderr, so stdout holds only the signed lines
        sys.stderr.flush()
        answer = sys.stdin.readline()
        if answer.strip().lower() not in ("y", "yes"):
            raise ClaimError("not signed")

        out = []
        for addr in [anchor] + members:
            if addr not in signers:
                continue
            msg = anchor_message(c) if addr == anchor else member_message(addr, anchor, block)
            kind, key = signers[addr]
            if kind == "finalizer":
                pub, sig = raw_public(key), key.sign(msg)
            else:
                pub, sig = key[0], key[1].sign(msg, ec.ECDSA(hashes.SHA256()))
            out.append("crosslink-claim-v1 %s %d %s %s" % (addr, block["height"], pub.hex(), sig.hex()))
        print("\nPaste these lines into the claim page:\n", file=sys.stderr)
        print("\n".join(out))
        return 0
    except ClaimError as e:
        print("Not signed: %s" % e, file=sys.stderr)
        return 2
    except Exception as e:  # never print a traceback: its frames could sit next to key material
        print("Not signed: unexpected %s. Nothing was printed from the seed." % type(e).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
