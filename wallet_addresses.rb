#!/usr/bin/env ruby
# frozen_string_literal: true
#
# wallet_addresses.rb
#
# Derive the first receive address for several chains from a BIP-39 seed phrase.
#
#   Bitcoin   (BIP44  m/44'/0'/0'/0/0   P2PKH, base58check)
#   Ethereum  (BIP44  m/44'/60'/0'/0/0  keccak256, EIP-55 checksum)
#   Litecoin  (BIP44  m/44'/2'/0'/0/0   P2PKH, base58check)
#   Dash      (BIP44  m/44'/5'/0'/0/0   P2PKH, base58check)
#   Tron      (BIP44  m/44'/195'/0'/0/0 keccak256 + prefix 0x41, base58check)
#   Solana    (SLIP-0010 ed25519  m/44'/501'/0'/0'  base58)
#
# Pure Ruby: only the stdlib (openssl + digest) is required. Base58, Keccak-256
# and Ed25519 are implemented below so no gems need to be installed.
#
# Usage:
#   ruby wallet_addresses.rb "word1 word2 ... word12" [passphrase]
#   MNEMONIC="word1 ... word12" ruby wallet_addresses.rb
#
# WARNING: A seed phrase controls real funds. Run this only on an offline,
# trusted machine. Never paste a phrase that secures assets into a shared shell.

require "openssl"
require "digest"

# ---------------------------------------------------------------------------
# Base58 / Base58Check
# ---------------------------------------------------------------------------
module Base58
  ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  module_function

  def encode(bytes)
    n = bytes.inject(0) { |acc, b| (acc << 8) + b }
    out = +""
    while n > 0
      n, rem = n.divmod(58)
      out.prepend(ALPHABET[rem])
    end
    # Preserve leading zero bytes as '1'.
    bytes.each { |b| b.zero? ? out.prepend(ALPHABET[0]) : break }
    out
  end

  def check_encode(bytes)
    checksum = Digest::SHA256.digest(Digest::SHA256.digest(bytes.pack("C*")))[0, 4]
    encode(bytes + checksum.bytes)
  end
end

# ---------------------------------------------------------------------------
# Keccac-256 (Ethereum's hash; NOT the NIST SHA3-256 padding)
# ---------------------------------------------------------------------------
module Keccak256
  MASK = (1 << 64) - 1
  ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
  ].freeze
  RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
  ].freeze

  module_function

  def rotl(x, n)
    n.zero? ? x : (((x << n) | (x >> (64 - n))) & MASK)
  end

  def keccak_f(a) # a is 5x5 array of 64-bit lanes, a[x][y]
    24.times do |rnd|
      # theta
      c = Array.new(5) { |x| a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] }
      d = Array.new(5) { |x| c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1) }
      5.times { |x| 5.times { |y| a[x][y] ^= d[x] } }
      # rho + pi
      b = Array.new(5) { Array.new(5, 0) }
      5.times do |x|
        5.times do |y|
          b[y][(2 * x + 3 * y) % 5] = rotl(a[x][y], ROT[x][y])
        end
      end
      # chi
      5.times do |x|
        5.times do |y|
          a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) & MASK
        end
      end
      # iota
      a[0][0] ^= RC[rnd]
    end
    a
  end

  def digest(message)
    rate = 136 # bytes (1088 bits) for Keccak-256
    msg = message.bytes
    q = rate - (msg.length % rate)
    pad = Array.new(q, 0)
    pad[0] |= 0x01
    pad[q - 1] |= 0x80
    msg += pad

    state = Array.new(5) { Array.new(5, 0) }
    msg.each_slice(rate) do |block|
      17.times do |i| # 17 lanes = 136 bytes
        lane = 0
        8.times { |k| lane |= block[i * 8 + k] << (8 * k) } # little-endian
        state[i % 5][i / 5] ^= lane
      end
      keccak_f(state)
    end

    out = []
    4.times do |i| # 4 lanes = 32 bytes of output
      lane = state[i % 5][i / 5]
      8.times { |k| out << ((lane >> (8 * k)) & 0xff) }
    end
    out.pack("C*")
  end

  def hexdigest(message)
    digest(message).unpack1("H*")
  end
end

# ---------------------------------------------------------------------------
# Ed25519 public key from a 32-byte seed (RFC 8032)
# ---------------------------------------------------------------------------
module Ed25519
  P = (2**255) - 19
  D = (-121665 * (121666.pow(P - 2, P))) % P
  BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
  BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960
  B = [BX % P, BY % P].freeze

  module_function

  def inv(x)
    x.pow(P - 2, P)
  end

  # Twisted Edwards addition, curve a = -1.
  def edwards_add(p1, p2)
    x1, y1 = p1
    x2, y2 = p2
    dxy = (D * x1 * x2 * y1 * y2) % P
    x3 = ((x1 * y2 + x2 * y1) * inv((1 + dxy) % P)) % P
    y3 = ((y1 * y2 + x1 * x2) * inv((1 - dxy) % P)) % P
    [x3, y3]
  end

  def scalarmult(point, e)
    result = [0, 1] # identity element
    addend = point
    while e > 0
      result = edwards_add(result, addend) if e.odd?
      addend = edwards_add(addend, addend)
      e >>= 1
    end
    result
  end

  def encode_point(point)
    x, y = point
    bytes = Array.new(32, 0)
    32.times { |i| bytes[i] = (y >> (8 * i)) & 0xff }
    bytes[31] |= 0x80 if x.odd?
    bytes.pack("C*")
  end

  # Public key (32 bytes) from a 32-byte secret seed.
  def public_key(seed)
    h = Digest::SHA512.digest(seed).bytes
    a = h[0, 32]
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    scalar = a.each_with_index.inject(0) { |acc, (byte, i)| acc + (byte << (8 * i)) }
    encode_point(scalarmult(B, scalar))
  end
end

# ---------------------------------------------------------------------------
# BIP-39: mnemonic -> seed
# ---------------------------------------------------------------------------
module BIP39
  module_function

  def to_seed(mnemonic, passphrase = "")
    norm = mnemonic.strip.split(/\s+/).join(" ")
    salt = "mnemonic#{passphrase}"
    OpenSSL::PKCS5.pbkdf2_hmac(norm, salt, 2048, 64, OpenSSL::Digest::SHA512.new)
  end
end

# ---------------------------------------------------------------------------
# BIP-32 HD derivation over secp256k1 (Bitcoin / Ethereum / Litecoin / Polygon)
# ---------------------------------------------------------------------------
module BIP32
  HARDENED = 0x80000000
  GROUP = OpenSSL::PKey::EC::Group.new("secp256k1")
  ORDER = GROUP.order.to_i

  Node = Struct.new(:key, :chain_code) # key: Integer scalar, chain_code: binary string

  module_function

  def ser256(int)
    [int.to_s(16).rjust(64, "0")].pack("H*")
  end

  def ser32(int)
    [int].pack("N")
  end

  # Compressed public key (33 bytes) for a private scalar.
  def public_point_compressed(scalar)
    point = GROUP.generator.mul(OpenSSL::BN.new(scalar.to_s))
    point.to_octet_string(:compressed)
  end

  # Uncompressed public key (65 bytes, 0x04||X||Y).
  def public_point_uncompressed(scalar)
    point = GROUP.generator.mul(OpenSSL::BN.new(scalar.to_s))
    point.to_octet_string(:uncompressed)
  end

  def master(seed)
    i = OpenSSL::HMAC.digest("SHA512", "Bitcoin seed", seed)
    Node.new(bytes_to_int(i[0, 32]), i[32, 32])
  end

  def ckd_priv(parent, index)
    data =
      if index >= HARDENED
        "\x00".b + ser256(parent.key) + ser32(index)
      else
        public_point_compressed(parent.key) + ser32(index)
      end
    i = OpenSSL::HMAC.digest("SHA512", parent.chain_code, data)
    il = bytes_to_int(i[0, 32])
    child_key = (il + parent.key) % ORDER
    Node.new(child_key, i[32, 32])
  end

  def derive_path(seed, path)
    node = master(seed)
    path.each { |index| node = ckd_priv(node, index) }
    node
  end

  def bytes_to_int(str)
    str.unpack1("H*").to_i(16)
  end
end

# ---------------------------------------------------------------------------
# SLIP-0010 ed25519 HD derivation (Solana); every level is hardened.
# ---------------------------------------------------------------------------
module SLIP10Ed25519
  HARDENED = 0x80000000

  Node = Struct.new(:key, :chain_code) # key: 32-byte binary, chain_code: 32-byte binary

  module_function

  def master(seed)
    i = OpenSSL::HMAC.digest("SHA512", "ed25519 seed", seed)
    Node.new(i[0, 32], i[32, 32])
  end

  def ckd(parent, index)
    index |= HARDENED # ed25519 only supports hardened derivation
    data = "\x00".b + parent.key + [index].pack("N")
    i = OpenSSL::HMAC.digest("SHA512", parent.chain_code, data)
    Node.new(i[0, 32], i[32, 32])
  end

  def derive_path(seed, path)
    node = master(seed)
    path.each { |index| node = ckd(node, index) }
    node
  end
end

# ---------------------------------------------------------------------------
# Address encoders
# ---------------------------------------------------------------------------
module Address
  module_function

  # secp256k1 pubkey hash: RIPEMD160(SHA256(compressed_pubkey)).
  def hash160(compressed_pubkey)
    sha = Digest::SHA256.digest(compressed_pubkey)
    OpenSSL::Digest.digest("RIPEMD160", sha)
  end

  def base58check_p2pkh(scalar, version_byte)
    pub = BIP32.public_point_compressed(scalar)
    payload = [version_byte] + hash160(pub).bytes
    Base58.check_encode(payload)
  end

  def bitcoin(scalar)
    base58check_p2pkh(scalar, 0x00)
  end

  def litecoin(scalar)
    base58check_p2pkh(scalar, 0x30)
  end

  def dash(scalar)
    base58check_p2pkh(scalar, 0x4c)
  end

  # Tron: keccak256 of the 64-byte pubkey, last 20 bytes, prefix 0x41, base58check.
  def tron(scalar)
    pub = BIP32.public_point_uncompressed(scalar)[1, 64] # drop 0x04 prefix
    hash160_20 = Keccak256.digest(pub)[-20, 20].bytes
    Base58.check_encode([0x41] + hash160_20)
  end

  # Ethereum / EVM: keccak256 of the 64-byte pubkey, last 20 bytes, EIP-55.
  def ethereum(scalar)
    pub = BIP32.public_point_uncompressed(scalar)[1, 64] # drop 0x04 prefix
    hash = Keccak256.digest(pub)
    addr = hash[-20, 20].unpack1("H*")
    to_eip55(addr)
  end

  def to_eip55(hex_addr)
    hash = Keccak256.hexdigest(hex_addr)
    checksummed = hex_addr.chars.each_with_index.map do |ch, i|
      if ch =~ /[a-f]/ && hash[i].to_i(16) >= 8
        ch.upcase
      else
        ch
      end
    end.join
    "0x#{checksummed}"
  end

  def solana(seed)
    node = SLIP10Ed25519.derive_path(seed, [
      44 | SLIP10Ed25519::HARDENED,
      501 | SLIP10Ed25519::HARDENED,
      0 | SLIP10Ed25519::HARDENED,
      0 | SLIP10Ed25519::HARDENED
    ])
    Base58.encode(Ed25519.public_key(node.key).bytes)
  end
end

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def derive_all(mnemonic, passphrase = "")
  seed = BIP39.to_seed(mnemonic, passphrase)
  h = BIP32::HARDENED

  btc = BIP32.derive_path(seed, [44 | h, 0 | h, 0 | h, 0, 0]).key
  eth = BIP32.derive_path(seed, [44 | h, 60 | h, 0 | h, 0, 0]).key
  ltc = BIP32.derive_path(seed, [44 | h, 2 | h, 0 | h, 0, 0]).key
  dash = BIP32.derive_path(seed, [44 | h, 5 | h, 0 | h, 0, 0]).key
  trx = BIP32.derive_path(seed, [44 | h, 195 | h, 0 | h, 0, 0]).key

  {
    "Bitcoin  (m/44'/0'/0'/0/0)"   => Address.bitcoin(btc),
    "Ethereum (m/44'/60'/0'/0/0)"  => Address.ethereum(eth),
    "Litecoin (m/44'/2'/0'/0/0)"   => Address.litecoin(ltc),
    "Dash     (m/44'/5'/0'/0/0)"   => Address.dash(dash),
    "Tron     (m/44'/195'/0'/0/0)" => Address.tron(trx),
    "Solana   (m/44'/501'/0'/0')"  => Address.solana(seed)
  }
end

if $PROGRAM_NAME == __FILE__
  mnemonic = ARGV[0] || ENV["MNEMONIC"]
  passphrase = ARGV[1] || ENV["PASSPHRASE"] || ""

  if mnemonic.nil? || mnemonic.strip.empty?
    warn <<~USAGE
      Usage:
        ruby #{File.basename($PROGRAM_NAME)} "word1 word2 ... word12" [passphrase]
        MNEMONIC="word1 ... word12" ruby #{File.basename($PROGRAM_NAME)}
    USAGE
    exit 1
  end

  puts "Seed phrase words: #{mnemonic.strip.split(/\s+/).length}"
  puts
  derive_all(mnemonic, passphrase).each do |label, addr|
    puts format("%-30s %s", label, addr)
  end
end
