# wallet_addresses.rb

Derive the first receive address for **Bitcoin, Ethereum, Litecoin, Dash, Tron, and Solana**
from a single BIP-39 seed phrase.

Pure Ruby — only the standard library (`openssl` + `digest`) is required. Base58,
Keccak-256, and Ed25519 are implemented in the script, so **no gems need to be installed.**

| Chain    | Derivation path      | Encoding                          |
|----------|----------------------|-----------------------------------|
| Bitcoin  | `m/44'/0'/0'/0/0`    | P2PKH, base58check                |
| Ethereum | `m/44'/60'/0'/0/0`   | keccak256 + EIP-55 checksum       |
| Litecoin | `m/44'/2'/0'/0/0`    | P2PKH, base58check                |
| Dash     | `m/44'/5'/0'/0/0`    | P2PKH, base58check                |
| Tron     | `m/44'/195'/0'/0/0`  | keccak256 + `0x41` prefix, base58check |
| Solana   | `m/44'/501'/0'/0'`   | SLIP-0010 ed25519, base58         |

## Requirements

- Ruby (any recent version; tested on Ruby 4.0). Check with `ruby -v`.
- No gems, no network access.

## Running — recommended

This is the safest way: the phrase is **never echoed to the screen** and **never
written to your shell history**.

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

**As a command-line argument** — convenient but **not recommended**: the phrase lands
in your shell history and is visible to other users via `ps`.

```bash
ruby wallet_addresses.rb "word1 word2 ... word12" [passphrase]
```

## Security notes

- A seed phrase controls real funds. Ideally run this on an **offline / air-gapped**
  machine. The script only *reads* the phrase to compute **public** addresses — it never
  transmits anything — but the safest posture is to keep the phrase off any networked device.
- Prefer `read -rs` over both env-var assignment and command-line arguments, so the phrase
  never appears on screen, in history, or in `ps` output.
- Always `unset` the variables (or close the shell) when finished.
- The derived **addresses are public information** and safe to copy out; the **seed phrase
  must never leave the trusted machine**.

## How it's verified

The derivation was checked against independent, authoritative test vectors:

- Ethereum `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` — the canonical vector for the
  `abandon … about` mnemonic.
- Base58Check reproduces the Bitcoin genesis address `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`.
- `keccak256("")` = `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`
  (confirming Ethereum's original Keccak padding, not NIST SHA3).
