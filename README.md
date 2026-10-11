# Crosslink profiles

Names and profiles for Crosslink finalizers and miners, each signed by the keys of the addresses it names. Anyone can claim one, any explorer can read them, and anyone can check every signature themselves.

This is for the Crosslink v14 Feature Net. [Holdfast](https://holdfast.crosslink.encapsulate.xyz) shows these profiles and has the page that makes a claim; the registry doesn't depend on it.

## Claim a profile

1. Open the claim page on [Holdfast](https://holdfast.crosslink.encapsulate.xyz), from your finalizer's or miner address's page. Fill in a name, the addresses it covers, and any profile fields.
2. The page gives you a command. Run it on each server that holds one of the keys:

   ```sh
   curl -O https://raw.githubusercontent.com/encapsulate-xyz/crosslink-profiles/main/crosslink-claim.py
   python3 crosslink-claim.py --seed-file <path to secret.seed> --challenge <code>
   ```

   It shows exactly what it will sign, asks first, and prints one line per key. It works offline: it sends nothing anywhere, and nothing it signs can move funds. It needs Python 3.8 or later and the `cryptography` package (`sudo apt install python3-cryptography`, or `python3 -m pip install --user cryptography`). Read it before you run it: it's one file.
3. Paste the lines back into the page and submit. The page opens a pull request here, or you open it from your own GitHub account.
4. The checks run on the pull request. When they pass, it merges by itself, and Holdfast shows the profile within about 5 minutes.

`secret.seed` is in the network's folder inside the node's cache directory:

| OS | Path |
|---|---|
| Linux | `~/.cache/zebra/crosslink_featurenet_20260929/secret.seed` |
| macOS | `~/Library/Caches/zebra/crosslink_featurenet_20260929/secret.seed` |
| Windows | `%LOCALAPPDATA%\zebra\crosslink_featurenet_20260929\secret.seed` |

A node that sets `cache_dir` under `[state]` keeps it in that folder instead. If your node sets `explicit_bft_key_seed`, put that value in a file and add `--bft-key-seed-file <file>`.

From one `secret.seed` the script derives the same keys the node does: the finalizer key, and the wallet's transparent addresses (`m/44'/1'/0'/0/0` to `/19`). It signs only for the claim's addresses that are among them. `tests/vectors` checks this against the node's own crates.

## What a claim is

A claim is a group of addresses under one name.

- **The anchor** is a finalizer address (`zfinv1…`), or a miner address (`tm…`) if the claim has no finalizer. Its key signs the name, the profile fields and the list of members.
- **Each member** is a miner address (`tm…`). Its key signs that it belongs to the anchor.

Both signatures are needed: nobody can put an address under a name without that address's key, and nobody can attach their address to a name without the anchor's key. On a default node the finalizer key and the wallet come from the same seed, so one run signs both. Every other mining server signs its own line where its key lives; seeds never move.

**The fields.** Only the name is required.

| Field | Rule |
|---|---|
| `name` | 1 to 32 characters: letters, digits, spaces, `.`, `_` and `-`, starting with a letter or digit |
| `description` | Plain text, up to 280 characters, one line, no links |
| `website` | An `https://` link |
| `x` | `https://x.com/<handle>` |
| `github` | `https://github.com/<account>` or `https://github.com/<account>/<repo>` |
| `security_contact` | An email address or an `https://` link, for reporting problems with the node |
| `logo` | An `https://` link to a PNG, JPEG or WebP image, with its SHA-256. The key signs the hash, so the image can't change after signing. Holdfast doesn't display third-party logos; it's here for explorers that do |

## The checks

Every pull request is checked before it merges:

- It changes only its own file, `claims/<anchor address>.json`.
- Every signature is valid, and each public key belongs to its address.
- The block a signature names is on the chain, and no more than 3,456 blocks (about a day) below the tip. A member that didn't sign again in an update keeps its earlier signature.
- The name follows the rules, isn't taken (case, spaces, `.`, `_` and `-` don't count), and isn't reserved ([names/reserved.txt](names/reserved.txt)).
- A replacement is signed by the same anchor, at a later block.
- No address is one whose key is public, such as the shared faucet wallet ([names/blocked-addresses.txt](names/blocked-addresses.txt)).
- A member doesn't have its own claim.
- A logo is the image whose hash was signed.

A name that matches or resembles a known organisation's ([names/review.txt](names/review.txt)), another claim's name, or a name someone else claimed on ctaz.cash waits for a maintainer. That isn't a rejection. The maintainer checks that the name belongs to whoever runs the addresses, then adds the `review-approved` label, and the claim merges.

The workflow comments on the pull request with the result of each check. The comment ends with the same result as JSON in an HTML comment (`<!-- claim-check {...} -->`), for the claim page to read.

## Updating, moving, removing

- **Update:** sign a new claim from the same anchor. Changing the name or a field needs only the anchor's signature. Adding a member needs that member's signature too.
- **Move an address:** an address belongs to the claim where it signed most recently, so signing into another claim moves it there.
- **Remove a claim:** [open an issue](https://github.com/encapsulate-xyz/crosslink-profiles/issues). Removals aren't automatic, because a removal carries no signature.

## The files

`claims/<anchor>.json`:

```json
{
  "version": 1,
  "network": "Crosslink v14",
  "anchor": "zfinv1…",
  "name": "Halyard",
  "website": "https://halyard.example",
  "block": { "height": 39100, "hash": "00002abd…" },
  "pubkey": "<the anchor's public key, hex>",
  "signature": "<the anchor's signature, hex>",
  "members": [
    { "address": "tm…", "block": { "height": 39100, "hash": "00002abd…" }, "pubkey": "02…", "signature": "3045…" }
  ]
}
```

Optional fields that are empty are left out. Members are sorted by address. [schema/claim-v1.json](schema/claim-v1.json) describes the shape.

**What the anchor signs**, as UTF-8 lines joined by `\n`, with no newline at the end. Empty fields are left out; the order is fixed:

```text
Crosslink profile claim v1
Network: Crosslink v14
Anchor: zfinv1…
Name: Halyard
Description: …
Website: https://halyard.example
X: https://x.com/…
GitHub: https://github.com/…
Security contact: …
Logo: https://… sha256:<hex>
Members: tm…, tm…
Block: 39100 00002abd…
```

**What each member signs:**

```text
Crosslink profile claim v1
Network: Crosslink v14
Member: tm…
Anchor: zfinv1…
Block: 39100 00002abd…
```

**Signatures.**
- A finalizer signs with ed25519. Its public key is the first 32 bytes of the address: `zfinv1` is followed by the base64url encoding of the key and the key's signature over `Zcash Crosslink Finalizer Address v1`.
- A miner address signs with ECDSA on secp256k1 over SHA-256 of the message, DER-encoded. Its public key is the compressed key whose HASH160 is the address.

The message names Crosslink rather than any explorer, so any explorer can accept the same claims.

## Reading the registry

Explorers should check the signatures themselves rather than trust this repository. `tools/claims.py` is the reference; `python3 tools/check.py --index` prints the whole registry, checked and resolved, as JSON. Every reader applies the same rules:

1. Skip a claim whose own signatures or fields fail, and a member whose signature fails.
2. An address belongs to the claim where it signed at the latest block: as the anchor of its own claim, or as a member of another. At the same block, its own claim wins.
3. A claim whose anchor now belongs to another claim is void.
4. If two claims hold the same name, the one signed at the earlier block keeps it, and the other is void.

To link to a claim's proof, link to the file at a fixed commit: `https://github.com/encapsulate-xyz/crosslink-profiles/blob/<commit>/claims/<anchor>.json`.

To check a claim yourself against your own node: `python3 tools/check.py --rpc http://127.0.0.1:<rpc port> claims/<anchor>.json`. Without `--rpc`, the chain comes from Holdfast's public API.

## Maintainers

- `.github/workflows/claim.yml` runs on every pull request that touches `claims/`. It runs the workflow and `tools/` from `main`, and reads the pull request's file only as data. The check job can only read; the apply job, which comments, labels and merges, installs nothing. It merges exactly the commit it checked.
- Labels: `rejected`, `needs-review`, and `review-approved`, which a maintainer adds to approve a name.
- Repository variables: `CHAIN_API` (the chain source, by default Holdfast) and `CLAIM_BOT` (the login of the GitHub App the claim page submits with). Pull requests from `CLAIM_BOT` that fail are closed, since nobody can push a fix to them.
- Tests: `pip install --require-hashes -r tools/requirements.txt`, then `python3 -m unittest discover tests`.

Report a problem with the registry or the script by [opening an issue](https://github.com/encapsulate-xyz/crosslink-profiles/issues), or privately through the repository's Security tab (Report a vulnerability).

## License

MIT. See [LICENSE](LICENSE).
