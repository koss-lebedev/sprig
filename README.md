# Seed phrase toolkit

| Script                | What it does                                                            |
|-----------------------|-------------------------------------------------------------------------|
| `generate_seed.rb`    | Generate a fresh BIP-39 seed phrase from secure random entropy.         |
| `wallet_addresses.rb` | Derive the first receive address for several chains from a seed phrase. |
| `slip39_shares.rb`    | Split the seed into 2-of-3 SLIP-0039 shares, and recover it from any 2. |

Pure Ruby — only the standard library (`openssl`, `digest`, `securerandom`) is
required. **No gems need to be installed.** Base58, Keccak-256, Ed25519, the
BIP-32/SLIP-10 derivations, and the SLIP-0039 machinery (GF(256) Shamir, RS1024,
Feistel encryption) are all implemented in the scripts.

## Requirements

- Ruby (any recent version; tested on Ruby 4.0). Check with `ruby -v`.
- No gems, no network access.
- `generate_seed.rb` needs `bip39_english.txt` (the official 2048-word BIP-39
  English list) sitting **beside the script** — it's included in this repo.
- `slip39_shares.rb` additionally needs `slip39_wordlist.txt` (the official
  1024-word SLIP-0039 list) sitting **beside the script** — it's included in
  this repo.

## Security notes

- A seed phrase controls real funds. Ideally run these on an **offline /
  air-gapped** machine. The scripts never transmit anything, but the safest
  posture is to keep the phrase off any networked device.
- Prefer `read -rs` over env-var assignment or command-line arguments, so the
  phrase never appears on screen, in shell history, or in `ps` output.
- Always `unset` the variables (or close the shell) when finished.
- Derived **addresses are public** and safe to copy out; the **seed phrase and
  the SLIP-0039 shares must never leave the trusted machine**.

## Tests

All verification lives in one file, `test.rb`, which loads the three scripts
and checks them against authoritative test vectors:

```bash
ruby test.rb
```

It exits non-zero if any check fails. What each script is checked against is
described in its "How it's verified" section below.

---

# `generate_seed.rb`

Generate a brand-new BIP-39 seed phrase from cryptographically secure random
entropy (the OS CSPRNG, via Ruby's `SecureRandom`), with a correct BIP-39
checksum.

## Running

```bash
ruby generate_seed.rb          # 24 words (256-bit) — the default
ruby generate_seed.rb 12       # or 12 / 15 / 18 / 21 / 24
```

The phrase is printed to **stdout**; You you can capture it into an env variable:

```bash
PHRASE="$(ruby generate_seed.rb)" 
```

| Words | Entropy  |
|-------|----------|
| 12    | 128-bit  |
| 15    | 160-bit  |
| 18    | 192-bit  |
| 21    | 224-bit  |
| 24    | 256-bit  |

Generate on an **offline, trusted machine**, write the words down, and keep them
off any networked device — anyone who sees the phrase controls the wallet. You
can pipe the result straight into the other scripts, e.g.
`MNEMONIC="$PHRASE" ruby wallet_addresses.rb`.

## How it's verified

Checked (in `test.rb`) against the official BIP-39 test vectors — fixed entropy
values (all zeros, all `0x7f`, all `0xff`, all `0x80`, …) produce the exact
published mnemonics — confirming the checksum and 11-bit word mapping are
correct. The tests also confirm each supported length generates the right word
count.

---

# `wallet_addresses.rb`

Derive the first receive address for **Bitcoin, Ethereum, Litecoin, Dash, Tron,
and Solana** from a single BIP-39 seed phrase.

| Chain    | Derivation path      | Encoding                          |
|----------|----------------------|-----------------------------------|
| Bitcoin  | `m/44'/0'/0'/0/0`    | P2PKH, base58check                |
| Ethereum | `m/44'/60'/0'/0/0`   | keccak256 + EIP-55 checksum       |
| Litecoin | `m/44'/2'/0'/0/0`    | P2PKH, base58check                |
| Dash     | `m/44'/5'/0'/0/0`    | P2PKH, base58check                |
| Tron     | `m/44'/195'/0'/0/0`  | keccak256 + `0x41` prefix, base58check |
| Solana   | `m/44'/501'/0'/0'`   | SLIP-0010 ed25519, base58         |

## Running — recommended

This is the safest way: the phrase is **never echoed to the screen** and
**never written to your shell history**.

```bash
read -rs MNEMONIC          # -s = silent (no echo), -r = don't mangle backslashes
export MNEMONIC
ruby wallet_addresses.rb
unset MNEMONIC             # clear it from the environment when you're done
```

Step by step:

1. Run `read -rs MNEMONIC`. The terminal waits silently — nothing is displayed.
2. Type or paste your 12/24-word phrase, then press **Enter**.
3. `export MNEMONIC` makes it visible to the Ruby process.
4. `ruby wallet_addresses.rb` reads `MNEMONIC` and prints the addresses.
5. `unset MNEMONIC` removes it from the current shell session.

Example output (using the well-known `abandon … about` test phrase):

```
Seed phrase words: 12

Bitcoin  (m/44'/0'/0'/0/0)     1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
Ethereum (m/44'/60'/0'/0/0)    0x9858EfFD232B4033E47d90003D41EC34EcaEda94
Litecoin (m/44'/2'/0'/0/0)     LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez
Dash     (m/44'/5'/0'/0/0)     XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5
Tron     (m/44'/195'/0'/0/0)   TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH
Solana   (m/44'/501'/0'/0')    HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk
```

### With a BIP-39 passphrase (optional "25th word")

If your wallet uses a passphrase, provide it the same way:

```bash
read -rs MNEMONIC;    export MNEMONIC
read -rs PASSPHRASE;  export PASSPHRASE
ruby wallet_addresses.rb
unset MNEMONIC PASSPHRASE
```

## Other ways to run

**From a file** (kept off every command line, then securely deleted):

```bash
MNEMONIC="$(cat seed.txt)" ruby wallet_addresses.rb
shred -u seed.txt        # Linux; on macOS use: rm -P seed.txt
```

**As a command-line argument** — convenient but **not recommended**: the phrase
lands in your shell history and is visible to other users via `ps`.

```bash
ruby wallet_addresses.rb "word1 word2 ... word12" [passphrase]
```

## How it's verified

The derivation is checked (in `test.rb`) against independent, authoritative
test vectors:

- All six chain addresses for the `abandon … about` mnemonic match their known
  values (e.g. Ethereum `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`, the
  canonical vector).
- Base58Check reproduces the Bitcoin genesis address
  `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`.
- `keccak256("")` = `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`
  (confirming Ethereum's original Keccak padding, not NIST SHA3).

---

# `slip39_shares.rb`

Split a BIP-39 seed phrase into **2-of-3 [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
shares** — any two of the three recover it, no single share reveals anything —
and recover the seed from any two.

## What gets split (read this first)

BIP-39 and SLIP-0039 turn a secret into a wallet by two different paths, so it
matters *what* you split:

- A BIP-39 wallet derives addresses from `seed = PBKDF2(words, …, 2048 rounds)`,
  a **64-byte** value.
- SLIP-0039 recovery (Trezor and others) uses the recovered **master secret
  directly as the BIP-32 seed** — there is no PBKDF2-over-words step.

This script splits the **64-byte BIP-39 seed** (the same value
`wallet_addresses.rb` derives) as the SLIP-0039 master secret. The consequences:

- ✅ **Recovery returns the 64-byte seed** (hex). Any software SLIP-0039 tool
  that uses the recovered secret directly as the BIP-32 seed will reproduce the
  **same addresses** — a genuine drop-in backup.
- ❌ **You never get the original words back.** PBKDF2 is one-way; the seed
  cannot be turned back into your 12/24 words.
- ❌ **It will not import into a Trezor.** Trezor firmware only accepts 128- or
  256-bit SLIP-0039 secrets; a 512-bit (64-byte) seed is rejected. Use a
  software SLIP-0039 implementation instead.

## Two independent passphrases

| Passphrase                       | Env var             | When it's used                                  |
|----------------------------------|---------------------|-------------------------------------------------|
| BIP-39 passphrase ("25th word")  | `PASSPHRASE`        | Only at **split**, when deriving the 64-byte seed. Not needed to recover. |
| SLIP-0039 passphrase             | `SLIP39_PASSPHRASE` | Encrypts the shares. Needed at **recovery** and at any drop-in import.    |

Note: SLIP-0039 offers plausible deniability — *every* passphrase decrypts to
*some* seed without error. A wrong `SLIP39_PASSPHRASE` silently yields a
different, wrong seed rather than failing. Double-check it.

## Splitting a seed phrase

```bash
read -rs MNEMONIC;          export MNEMONIC
read -rs SLIP39_PASSPHRASE; export SLIP39_PASSPHRASE   # optional
# read -rs PASSPHRASE;      export PASSPHRASE          # only if your wallet uses a BIP-39 passphrase
ruby slip39_shares.rb split
unset MNEMONIC SLIP39_PASSPHRASE PASSPHRASE
```

Output — three shares, each a **59-word** list (the seed is 512 bits); the
words after the first few differ per share. Store each share in a separate
place:

```
Seed phrase words: 12
2-of-3 SLIP-0039 shares (any 2 recover the seed):

Share 1:
  freshman category academic acid academic repair cylinder … (59 words)

Share 2:
  freshman category academic agency acne fancy failure … (59 words)

Share 3:
  freshman category academic always acid alpha ruler … (59 words)
```

Every share is regenerated with a fresh random identifier each run, so your
output will differ from any example.

## Recovering the seed

Provide any **two** shares. Recovery prints the 64-byte seed as hex.

```bash
# as arguments (quote each share):
ruby slip39_shares.rb recover "<share 1 words>" "<share 3 words>"

# or pipe them on stdin, one share per line:
ruby slip39_shares.rb recover        # then paste, one per line, Ctrl-D to finish

# or via an env var (newline- or semicolon-separated):
SHARES="<share1>
<share2>" ruby slip39_shares.rb recover

# add SLIP39_PASSPHRASE=… if one was used at split time
```

## How it's verified

Checked in `test.rb`:

- **Official SLIP-0039 test vectors** (128- and 256-bit, standard and
  extendable) recover to their published master secrets — confirming the shares
  this script produces are spec-compliant SLIP-0039, hence usable by other
  SLIP-0039 software.
- The 64-byte seed matches the canonical `abandon … about` BIP-39 vector.
- Round-trip: every 2-of-3 combination recovers the seed, with and without a
  SLIP-0039 passphrase.
