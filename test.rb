#!/usr/bin/env ruby
# frozen_string_literal: true
#
# test.rb
#
# Verification for the whole toolkit. Loads all three scripts as libraries and
# checks them against authoritative test vectors.
#
#   ruby test.rb
#
# Exits 0 if everything passes, non-zero otherwise.

require_relative "generate_seed"    # BIP39.encode / BIP39.generate, Bip39Wordlist
require_relative "wallet_addresses" # derive_all, Base58, Keccak256, BIP39.to_seed
require_relative "slip39_shares"    # SLIP39.split / SLIP39.combine, Slip39Wordlist

# ---------------------------------------------------------------------------
# Tiny assertion harness
# ---------------------------------------------------------------------------
FAILURES = [0]

def check(name, got, want)
  ok = got == want
  FAILURES[0] += 1 unless ok
  puts format("  [%s] %s", ok ? "PASS" : "FAIL", name)
  puts "        got:  #{got.inspect}\n        want: #{want.inspect}" unless ok
end

def section(title)
  puts "\n#{title}"
end

ABANDON = (["abandon"] * 11 + ["about"]).join(" ")
ABANDON_SEED = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" \
               "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

# ---------------------------------------------------------------------------
# generate_seed.rb — official BIP-39 vectors (fixed entropy -> mnemonic)
# ---------------------------------------------------------------------------
BIP39_VECTORS = [
  ["00000000000000000000000000000000",
   "abandon abandon abandon abandon abandon abandon abandon abandon " \
   "abandon abandon abandon about"],
  ["7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
   "legal winner thank year wave sausage worth useful legal winner " \
   "thank yellow"],
  ["ffffffffffffffffffffffffffffffff",
   "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"],
  ["0000000000000000000000000000000000000000000000000000000000000000",
   "abandon abandon abandon abandon abandon abandon abandon abandon " \
   "abandon abandon abandon abandon abandon abandon abandon abandon " \
   "abandon abandon abandon abandon abandon abandon abandon art"],
  ["8080808080808080808080808080808080808080808080808080808080808080",
   "letter advice cage absurd amount doctor acoustic avoid letter advice " \
   "cage absurd amount doctor acoustic avoid letter advice cage absurd " \
   "amount doctor acoustic bless"]
].freeze

section "generate_seed.rb — BIP-39 vectors (entropy -> mnemonic):"
BIP39_VECTORS.each_with_index do |(hex, expected), i|
  check("vector #{i + 1} (#{expected.split.length} words)", BIP39.encode([hex].pack("H*")), expected)
end

section "generate_seed.rb — generated phrases have valid lengths:"
BIP39::STRENGTHS.each_key do |wc|
  check("generate(#{wc}) -> #{wc} words", BIP39.generate(wc).split.length, wc)
end

# ---------------------------------------------------------------------------
# wallet_addresses.rb — primitives and full derivation
# ---------------------------------------------------------------------------
section "wallet_addresses.rb — primitives:"
check("keccak256(\"\")",
      Keccak256.hexdigest(""),
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
check("base58check reproduces Bitcoin genesis address",
      Base58.check_encode([0x00] + ["62e907b15cbf27d5425399ebf6f0fb50ebb88f18"].pack("H*").bytes),
      "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

# Known first receive addresses for the canonical abandon...about mnemonic.
EXPECTED_ADDRESSES = {
  "Bitcoin"  => "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
  "Ethereum" => "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
  "Litecoin" => "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez",
  "Dash"     => "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5",
  "Tron"     => "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
  "Solana"   => "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
}.freeze

section "wallet_addresses.rb — derive_all(abandon...about):"
addresses = derive_all(ABANDON)
EXPECTED_ADDRESSES.each do |chain, want|
  key = addresses.keys.find { |k| k.start_with?(chain) }
  check(chain, addresses[key], want)
end

# ---------------------------------------------------------------------------
# slip39_shares.rb — official SLIP-0039 vectors + round-trip
# [master_secret_hex, extendable, [mnemonic, mnemonic]]; passphrase "TREZOR".
# ---------------------------------------------------------------------------
SLIP39_VECTORS = [
  ["b43ceb7e57a0ea8766221624d01b0864", false, [
    "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
    "shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking"
  ]],
  ["c938b319067687e990e05e0da0ecce1278f75ff58d9853f19dcaeed5de104aae", false, [
    "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
    "humidity disease academic agency actress jacket gross physics cylinder solution fake mortgage benefit public busy prepare sharp friar change work slow purchase ruler again tricycle involve viral wireless mixture anatomy desert cargo upgrade"
  ]],
  ["48b1a4b80b8c209ad42c33672bdaa428", true, [
    "enemy favorite academic acid cowboy phrase havoc level response walnut budget painting inside trash adjust froth kitchen learn tidy punish",
    "enemy favorite academic always academic sniff script carpet romp kind promise scatter center unfair training emphasis evening belong fake enforce"
  ]],
  ["8dc652d6d6cd370d8c963141f6d79ba440300f25c467302c1d966bff8f62300d", true, [
    "western apart academic always artist resident briefing sugar woman oven coding club ajar merit pecan answer prisoner artist fraction amount desktop mild false necklace muscle photo wealthy alpha category unwrap spew losing making",
    "western apart academic acid answer ancient auction flip image penalty oasis beaver multiple thunder problem switch alive heat inherit superior teaspoon explain blanket pencil numb lend punish endless aunt garlic humidity kidney observe"
  ]]
].freeze

section "slip39_shares.rb — official SLIP-0039 vectors (recover -> master secret):"
SLIP39_VECTORS.each_with_index do |(secret_hex, ext, mnemonics), i|
  got = SLIP39.combine(mnemonics, passphrase: "TREZOR".b).unpack1("H*")
  check("vector #{i + 1} (#{ext ? 'extendable' : 'standard'})", got, secret_hex)
end

section "slip39_shares.rb — round-trip split -> recover (2-of-3, seed-split path):"
seed = BIP39.to_seed(ABANDON)
check("seed hex matches canonical vector", seed.unpack1("H*"), ABANDON_SEED)
[nil, "correct horse"].each do |pass|
  pass_b = (pass || "").b
  shares = SLIP39.split(seed, passphrase: pass_b)
  [[0, 1], [0, 2], [1, 2]].each do |a, b|
    got = SLIP39.combine([shares[a], shares[b]], passphrase: pass_b).unpack1("H*")
    check("shares #{a + 1}+#{b + 1}, slip39-pass=#{pass.inspect}", got, ABANDON_SEED)
  end
end

# ---------------------------------------------------------------------------
puts(FAILURES[0].zero? ? "\nAll tests passed." : "\n#{FAILURES[0]} test(s) FAILED.")
exit(FAILURES[0].zero? ? 0 : 1)
