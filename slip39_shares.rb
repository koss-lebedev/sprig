#!/usr/bin/env ruby
# frozen_string_literal: true

require "openssl"
require "securerandom"

RADIX_BITS = 10

# ---------------------------------------------------------------------------
# SLIP-0039 wordlist (1024 words), loaded from a file beside this script.
# ---------------------------------------------------------------------------
module Slip39Wordlist
  PATH = File.join(__dir__, "slip39_wordlist.txt")

  unless File.exist?(PATH)
    abort "Missing wordlist: #{PATH}\n" \
          "Fetch it from https://github.com/satoshilabs/slips/blob/master/slip-0039/wordlist.txt"
  end

  WORDS = File.readlines(PATH).map(&:strip).reject(&:empty?).freeze
  unless WORDS.length == 1024
    abort "Wordlist must contain exactly 1024 words, found #{WORDS.length}"
  end
  INDEX = WORDS.each_with_index.to_h.freeze
end

# ---------------------------------------------------------------------------
# GF(256) arithmetic (Rijndael field, reducing polynomial x^8+x^4+x^3+x+1).
# Shamir shares are interpolated byte-by-byte over this field.
# ---------------------------------------------------------------------------
module GF256
  EXP = Array.new(255, 0)
  LOG = Array.new(256, 0)
  poly = 1
  255.times do |i|
    EXP[i] = poly
    LOG[poly] = i
    poly = (poly << 1) ^ poly       # multiply by the generator (x + 1)
    poly ^= 0x11B if poly & 0x100 != 0
  end
  EXP.freeze
  LOG.freeze

  module_function

  # shares: array of [x, value_bytes(Array<Integer>)]; returns the value
  # (Array<Integer>) of the interpolating polynomial evaluated at x.
  def interpolate(shares, x)
    if (hit = shares.find { |xi, _| xi == x })
      return hit[1]
    end

    len = shares.first[1].length
    log_prod = shares.sum { |xi, _| LOG[xi ^ x] }
    result = Array.new(len, 0)

    shares.each do |xi, val|
      log_basis = (
        log_prod - LOG[xi ^ x] - shares.sum { |xj, _| LOG[xi ^ xj] }
      ) % 255
      val.each_with_index do |b, j|
        result[j] ^= (b.zero? ? 0 : EXP[(LOG[b] + log_basis) % 255])
      end
    end
    result
  end
end

# ---------------------------------------------------------------------------
# SLIP-0039 Shamir secret sharing with digest (x=254) and secret (x=255)
# reserved indices.
# ---------------------------------------------------------------------------
module Shamir
  DIGEST_LENGTH  = 4
  SECRET_INDEX   = 255
  DIGEST_INDEX   = 254
  MAX_SHARE_COUNT = 16

  module_function

  def digest(random_data, shared_secret) # both binary strings -> 4-byte string
    OpenSSL::HMAC.digest("SHA256", random_data, shared_secret)[0, DIGEST_LENGTH]
  end

  # secret: binary string. Returns array of [index, share_binary_string].
  def split_secret(threshold, count, secret)
    unless (1..count).cover?(threshold) && count <= MAX_SHARE_COUNT
      raise "invalid Shamir parameters: #{threshold}-of-#{count}"
    end
    return (0...count).map { |i| [i, secret] } if threshold == 1

    random_share_count = threshold - 2
    low_shares = (0...random_share_count).map { |i| [i, SecureRandom.random_bytes(secret.bytesize)] }
    random_part = SecureRandom.random_bytes(secret.bytesize - DIGEST_LENGTH)
    dg = digest(random_part, secret)

    base = low_shares.map { |i, s| [i, s.bytes] } +
           [[DIGEST_INDEX, (dg + random_part).bytes], [SECRET_INDEX, secret.bytes]]

    shares = low_shares.dup
    (random_share_count...count).each do |i|
      shares << [i, GF256.interpolate(base, i).pack("C*")]
    end
    shares
  end

  # shares: array of [index, share_binary_string]. Returns secret binary string.
  def recover_secret(threshold, shares)
    return shares.first[1] if threshold == 1

    bytes = shares.map { |i, s| [i, s.bytes] }
    secret = GF256.interpolate(bytes, SECRET_INDEX)
    dg_share = GF256.interpolate(bytes, DIGEST_INDEX)

    secret_str = secret.pack("C*")
    dg = dg_share[0, DIGEST_LENGTH].pack("C*")
    random_part = dg_share[DIGEST_LENGTH..].pack("C*")
    if digest(random_part, secret_str) != dg
      raise "share digest mismatch (wrong, corrupted, or mismatched shares)"
    end
    secret_str
  end
end

# ---------------------------------------------------------------------------
# SLIP-0039 encryption: 4-round Feistel network keyed by PBKDF2-HMAC-SHA256.
# ---------------------------------------------------------------------------
module Cipher
  BASE_ITERATION_COUNT = 10_000
  ROUND_COUNT = 4

  module_function

  def salt(identifier, extendable)
    return "".b if extendable
    "shamir".b + [identifier].pack("n") # 15-bit id serialized as 2 bytes
  end

  def round_function(round, passphrase, exponent, salt, right)
    password = [round].pack("C") + passphrase
    iterations = (BASE_ITERATION_COUNT << exponent) / ROUND_COUNT
    OpenSSL::PKCS5.pbkdf2_hmac(password, salt + right, iterations, right.bytesize,
                               OpenSSL::Digest::SHA256.new)
  end

  def xor(a, b)
    a.bytes.zip(b.bytes).map { |x, y| x ^ y }.pack("C*")
  end

  def encrypt(master_secret, passphrase, exponent, identifier, extendable)
    half = master_secret.bytesize / 2
    l = master_secret[0, half]
    r = master_secret[half..]
    s = salt(identifier, extendable)
    ROUND_COUNT.times do |i|
      l, r = r, xor(l, round_function(i, passphrase, exponent, s, r))
    end
    r + l
  end

  def decrypt(ems, passphrase, exponent, identifier, extendable)
    half = ems.bytesize / 2
    l = ems[0, half]
    r = ems[half..]
    s = salt(identifier, extendable)
    (ROUND_COUNT - 1).downto(0) do |i|
      l, r = r, xor(l, round_function(i, passphrase, exponent, s, r))
    end
    r + l
  end
end

# ---------------------------------------------------------------------------
# RS1024 checksum (Reed-Solomon over GF(1024)).
# ---------------------------------------------------------------------------
module RS1024
  GEN = [
    0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009,
    0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120
  ].freeze

  module_function

  def polymod(values)
    chk = 1
    values.each do |v|
      b = chk >> 20
      chk = ((chk & 0xFFFFF) << 10) ^ v
      10.times { |i| chk ^= (((b >> i) & 1) != 0 ? GEN[i] : 0) }
    end
    chk
  end

  def customization(extendable)
    (extendable ? "shamir_extendable" : "shamir").bytes
  end

  def create(data, extendable)
    values = customization(extendable) + data + [0, 0, 0]
    polymod = polymod(values) ^ 1
    (0...3).map { |i| (polymod >> (RADIX_BITS * (2 - i))) & 1023 }
  end

  def verify(data, extendable)
    polymod(customization(extendable) + data) == 1
  end
end

# ---------------------------------------------------------------------------
# Share mnemonic encoding / decoding (bit-field header + padded value + csum).
#   id(15) ext(1) e(4) group_index(4) group_threshold-1(4)
#   group_count-1(4) member_index(4) member_threshold-1(4)  = 40 bits (4 words)
# ---------------------------------------------------------------------------
module Share
  MIN_WORDS = 20 # smallest valid share (128-bit secret)

  module_function

  def bits_to_words(bits)
    (bits + RADIX_BITS - 1) / RADIX_BITS
  end

  def encode(id:, ext:, exponent:, group_index:, group_threshold:, group_count:,
             member_index:, member_threshold:, value:)
    header = (id << 25) | ((ext ? 1 : 0) << 24) | (exponent << 20) |
             (group_index << 16) | ((group_threshold - 1) << 12) |
             ((group_count - 1) << 8) | (member_index << 4) | (member_threshold - 1)
    header_words = (0...4).map { |k| (header >> (RADIX_BITS * (3 - k))) & 1023 }

    vwc = bits_to_words(value.bytesize * 8)
    vint = value.bytes.inject(0) { |acc, b| (acc << 8) | b }
    value_words = (0...vwc).map { |k| (vint >> (RADIX_BITS * (vwc - 1 - k))) & 1023 }

    data = header_words + value_words
    data += RS1024.create(data, ext)
    data.map { |i| Slip39Wordlist::WORDS[i] }.join(" ")
  end

  def decode(mnemonic)
    words = mnemonic.strip.split(/\s+/)
    raise "share too short (#{words.length} words)" if words.length < MIN_WORDS
    idxs = words.map { |w| Slip39Wordlist::INDEX[w] or raise "invalid word in share: #{w.inspect}" }

    header = idxs[0, 4].inject(0) { |acc, x| (acc << RADIX_BITS) | x }
    ext = ((header >> 24) & 1) == 1
    raise "invalid share checksum" unless RS1024.verify(idxs, ext)

    value_words = idxs[4...-3]
    total_bits = value_words.length * RADIX_BITS
    padding = total_bits % 16
    raise "invalid share (bad padding)" if padding > 8
    vint = value_words.inject(0) { |acc, x| (acc << RADIX_BITS) | x }
    value_bits = total_bits - padding
    raise "invalid share (nonzero padding)" unless (vint >> value_bits).zero?
    vbytes = value_bits / 8
    value = Array.new(vbytes) { |i| (vint >> (8 * (vbytes - 1 - i))) & 0xFF }.pack("C*")

    {
      id: (header >> 25) & 0x7FFF,
      ext: ext,
      exponent: (header >> 20) & 0xF,
      group_index: (header >> 16) & 0xF,
      group_threshold: ((header >> 12) & 0xF) + 1,
      group_count: ((header >> 8) & 0xF) + 1,
      member_index: (header >> 4) & 0xF,
      member_threshold: (header & 0xF) + 1,
      value: value
    }
  end
end

# ---------------------------------------------------------------------------
# SLIP-0039 top level: split a master secret and combine shares back.
# ---------------------------------------------------------------------------
module SLIP39
  module_function

  # Returns a flat array of mnemonic strings.
  def split(master_secret, passphrase: "".b, extendable: false, exponent: 0,
            group_threshold: 1, groups: [[2, 3]])
    if master_secret.bytesize < 16 || master_secret.bytesize.odd?
      raise "master secret must be an even number of bytes, at least 16"
    end

    id = SecureRandom.random_number(1 << 15)
    ems = Cipher.encrypt(master_secret, passphrase, exponent, id, extendable)
    group_shares = Shamir.split_secret(group_threshold, groups.length, ems)

    group_shares.flat_map do |group_index, group_secret|
      member_threshold, member_count = groups[group_index]
      Shamir.split_secret(member_threshold, member_count, group_secret).map do |member_index, value|
        Share.encode(
          id: id, ext: extendable, exponent: exponent,
          group_index: group_index, group_threshold: group_threshold,
          group_count: groups.length, member_index: member_index,
          member_threshold: member_threshold, value: value
        )
      end
    end
  end

  # Returns the recovered master secret (binary string).
  def combine(mnemonics, passphrase: "".b)
    raise "need at least one share" if mnemonics.empty?
    shares = mnemonics.map { |m| Share.decode(m) }
    first = shares.first
    shares.each do |s|
      %i[id ext exponent group_threshold group_count].each do |k|
        raise "shares are not from the same split" unless s[k] == first[k]
      end
    end

    group_secrets = shares.group_by { |s| s[:group_index] }.map do |gi, members|
      mt = members.first[:member_threshold]
      members.each { |m| raise "inconsistent member threshold" unless m[:member_threshold] == mt }
      uniq = members.uniq { |m| m[:member_index] }
      if uniq.length < mt
        raise "group #{gi}: need #{mt} shares, have #{uniq.length}"
      end
      secret = Shamir.recover_secret(mt, uniq.first(mt).map { |m| [m[:member_index], m[:value]] })
      [gi, secret]
    end

    gt = first[:group_threshold]
    raise "need #{gt} groups, have #{group_secrets.length}" if group_secrets.length < gt
    ems = Shamir.recover_secret(gt, group_secrets.first(gt))
    Cipher.decrypt(ems, passphrase, first[:exponent], first[:id], first[:ext])
  end
end

# ---------------------------------------------------------------------------
# BIP-39: seed phrase -> 64-byte seed (same derivation as wallet_addresses.rb).
# ---------------------------------------------------------------------------
module BIP39
  module_function

  def to_seed(mnemonic, passphrase = "")
    norm = mnemonic.strip.split(/\s+/).join(" ")
    OpenSSL::PKCS5.pbkdf2_hmac(norm, "mnemonic#{passphrase}", 2048, 64,
                               OpenSSL::Digest::SHA512.new)
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def read_shares(argv)
  if argv.length > 1
    argv[1..]
  elsif (env = ENV["SHARES"])
    env.split(/[\n;]+/)
  else
    warn "Paste shares, one per line, then Ctrl-D:"
    $stdin.read.split(/\n+/)
  end.map(&:strip).reject(&:empty?)
end

def usage
  warn <<~USAGE
    Usage:
      Split a seed phrase into 2-of-3 SLIP-0039 shares:
        read -rs MNEMONIC;          export MNEMONIC
        read -rs SLIP39_PASSPHRASE; export SLIP39_PASSPHRASE   # optional
        ruby #{File.basename($PROGRAM_NAME)} split
        unset MNEMONIC SLIP39_PASSPHRASE

      Recover the 64-byte seed from any 2 shares:
        ruby #{File.basename($PROGRAM_NAME)} recover "<share 1>" "<share 2>"
        # or pipe shares on stdin (one per line), or set SHARES env var
        # set SLIP39_PASSPHRASE if one was used at split time
  USAGE
  exit 1
end

if $PROGRAM_NAME == __FILE__
  begin
  case ARGV[0]
  when "split"
    mnemonic = ENV["MNEMONIC"]
    usage if mnemonic.nil? || mnemonic.strip.empty?
    bip39_pass = ENV["PASSPHRASE"] || ""
    slip39_pass = (ENV["SLIP39_PASSPHRASE"] || "").b

    seed = BIP39.to_seed(mnemonic, bip39_pass)
    shares = SLIP39.split(seed, passphrase: slip39_pass)

    puts "Seed phrase words: #{mnemonic.strip.split(/\s+/).length}"
    puts "2-of-3 SLIP-0039 shares (any 2 recover the seed):"
    puts
    shares.each_with_index do |share, i|
      puts "Share #{i + 1}:"
      puts "  #{share}"
      puts
    end
    warn "Reminder: recovery yields the 64-byte SEED, not your original words."

  when "recover"
    shares = read_shares(ARGV)
    usage if shares.empty?
    slip39_pass = (ENV["SLIP39_PASSPHRASE"] || "").b
    seed = SLIP39.combine(shares, passphrase: slip39_pass)
    puts seed.unpack1("H*")

  else
    usage
  end
  rescue RuntimeError => e
    abort "Error: #{e.message}"
  end
end
