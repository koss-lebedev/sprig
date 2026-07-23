#!/usr/bin/env ruby
# frozen_string_literal: true

require "securerandom"
require "digest"

# ---------------------------------------------------------------------------
# BIP-39 English wordlist (2048 words), loaded from a file beside this script.
# ---------------------------------------------------------------------------
module Bip39Wordlist
  PATH = File.join(__dir__, "bip39_english.txt")

  unless File.exist?(PATH)
    abort "Missing wordlist: #{PATH}\n" \
          "Fetch it from https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt"
  end

  WORDS = File.readlines(PATH).map(&:strip).reject(&:empty?).freeze
  unless WORDS.length == 2048
    abort "Wordlist must contain exactly 2048 words, found #{WORDS.length}"
  end
end

# ---------------------------------------------------------------------------
# BIP-39 mnemonic generation.
#   entropy bits (ENT) -> ENT/32 checksum bits -> 11-bit groups -> words
# ---------------------------------------------------------------------------
module BIP39
  # word count => entropy bytes
  STRENGTHS = { 12 => 16, 15 => 20, 18 => 24, 21 => 28, 24 => 32 }.freeze

  module_function

  # Encode raw entropy bytes into a mnemonic. entropy length must be one of the
  # BIP-39 sizes (16, 20, 24, 28, or 32 bytes).
  def encode(entropy)
    ent_bits = entropy.bytesize * 8
    unless STRENGTHS.value?(entropy.bytesize)
      raise "entropy must be 16, 20, 24, 28, or 32 bytes (got #{entropy.bytesize})"
    end

    checksum_bits = ent_bits / 32
    hash_first = Digest::SHA256.digest(entropy).bytes.first
    checksum = hash_first >> (8 - checksum_bits) # top `checksum_bits` bits

    combined = entropy.bytes.inject(0) { |acc, b| (acc << 8) | b }
    combined = (combined << checksum_bits) | checksum
    total_bits = ent_bits + checksum_bits

    word_count = total_bits / 11
    (0...word_count).map do |i|
      index = (combined >> (total_bits - 11 * (i + 1))) & 0x7FF
      Bip39Wordlist::WORDS[index]
    end.join(" ")
  end

  # Generate a fresh mnemonic with the given number of words (default 24).
  def generate(word_count = 24)
    bytes = STRENGTHS[word_count]
    raise "word count must be one of #{STRENGTHS.keys.join(', ')}" unless bytes
    encode(SecureRandom.random_bytes(bytes))
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if $PROGRAM_NAME == __FILE__
  word_count = ARGV[0].nil? ? 24 : ARGV[0].to_i
  unless BIP39::STRENGTHS.key?(word_count)
    warn <<~USAGE
      Usage:
        ruby #{File.basename($PROGRAM_NAME)} [#{BIP39::STRENGTHS.keys.join(' | ')}]
        (default: 24 words)
    USAGE
    exit 1
  end

  mnemonic = BIP39.generate(word_count)
  puts mnemonic
end
