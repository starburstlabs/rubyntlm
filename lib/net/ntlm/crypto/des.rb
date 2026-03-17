# Pure-Ruby DES-CBC cipher with an OpenSSL::Cipher-compatible interface.
# Required because OpenSSL 3.x disables DES by default.
#
# NTLM uses DES-CBC (with a zero IV and no padding) to compute LM hashes
# and the legacy NTLM response.  Each plaintext is exactly one 8-byte DES
# block, so CBC with a zero IV is equivalent to ECB for these operations.
#
# Reference: FIPS 46-3 / ANSI X3.92

module Net
  module NTLM
    module Crypto
      class DES
        # ── DES lookup tables (all indices are 1-based per the FIPS spec) ──

        # PC-1: 64-bit key → 56-bit C||D halves
        PC1 = [
          57, 49, 41, 33, 25, 17,  9,
           1, 58, 50, 42, 34, 26, 18,
          10,  2, 59, 51, 43, 35, 27,
          19, 11,  3, 60, 52, 44, 36,
          63, 55, 47, 39, 31, 23, 15,
           7, 62, 54, 46, 38, 30, 22,
          14,  6, 61, 53, 45, 37, 29,
          21, 13,  5, 28, 20, 12,  4
        ].freeze

        # PC-2: 56-bit C||D → 48-bit subkey
        PC2 = [
          14, 17, 11, 24,  1,  5,
           3, 28, 15,  6, 21, 10,
          23, 19, 12,  4, 26,  8,
          16,  7, 27, 20, 13,  2,
          41, 52, 31, 37, 47, 55,
          30, 40, 51, 45, 33, 48,
          44, 49, 39, 56, 34, 53,
          46, 42, 50, 36, 29, 32
        ].freeze

        # Initial Permutation
        IP = [
          58, 50, 42, 34, 26, 18, 10,  2,
          60, 52, 44, 36, 28, 20, 12,  4,
          62, 54, 46, 38, 30, 22, 14,  6,
          64, 56, 48, 40, 32, 24, 16,  8,
          57, 49, 41, 33, 25, 17,  9,  1,
          59, 51, 43, 35, 27, 19, 11,  3,
          61, 53, 45, 37, 29, 21, 13,  5,
          63, 55, 47, 39, 31, 23, 15,  7
        ].freeze

        # Final Permutation (IP⁻¹)
        FP = [
          40,  8, 48, 16, 56, 24, 64, 32,
          39,  7, 47, 15, 55, 23, 63, 31,
          38,  6, 46, 14, 54, 22, 62, 30,
          37,  5, 45, 13, 53, 21, 61, 29,
          36,  4, 44, 12, 52, 20, 60, 28,
          35,  3, 43, 11, 51, 19, 59, 27,
          34,  2, 42, 10, 50, 18, 58, 26,
          33,  1, 41,  9, 49, 17, 57, 25
        ].freeze

        # Expansion E: 32-bit R half → 48 bits
        E_TABLE = [
          32,  1,  2,  3,  4,  5,
           4,  5,  6,  7,  8,  9,
           8,  9, 10, 11, 12, 13,
          12, 13, 14, 15, 16, 17,
          16, 17, 18, 19, 20, 21,
          20, 21, 22, 23, 24, 25,
          24, 25, 26, 27, 28, 29,
          28, 29, 30, 31, 32,  1
        ].freeze

        # P permutation applied after S-box substitution
        P_TABLE = [
          16,  7, 20, 21,
          29, 12, 28, 17,
           1, 15, 23, 26,
           5, 18, 31, 10,
           2,  8, 24, 14,
          32, 27,  3,  9,
          19, 13, 30,  6,
          22, 11,  4, 25
        ].freeze

        # S-boxes S1..S8 (indexed [box][row][col])
        SBOX = [
          [ # S1
            [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
            [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
            [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
            [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]
          ],
          [ # S2
            [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
            [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
            [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
            [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]
          ],
          [ # S3
            [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
            [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
            [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
            [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]
          ],
          [ # S4
            [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
            [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
            [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
            [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]
          ],
          [ # S5
            [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
            [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
            [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
            [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]
          ],
          [ # S6
            [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
            [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
            [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
            [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]
          ],
          [ # S7
            [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
            [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
            [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
            [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]
          ],
          [ # S8
            [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
            [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
            [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
            [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]
          ]
        ].freeze

        # Left-rotation amounts for each of the 16 key schedule rounds
        ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1].freeze

        # ── Public interface (OpenSSL::Cipher compatible) ──

        attr_writer :padding

        def initialize
          @encrypt = true
          @padding = 1
          @iv = "\x00" * 8
          @subkeys = nil
        end

        def key=(k)
          @subkeys = generate_subkeys(k.b)
          self
        end

        def encrypt
          @encrypt = true
          self
        end

        def decrypt
          @encrypt = false
          self
        end

        # Processes +data+ in 8-byte CBC blocks and returns the result.
        # +data+ must be a multiple of 8 bytes (padding = 0 is NTLM's usage).
        def update(data)
          result = ''.b
          prev   = @iv.b.bytes

          data.b.bytes.each_slice(8) do |block|
            if @encrypt
              input = block.zip(prev).map { |a, b| a ^ b }
              enc   = des_ecb_encrypt(input.pack('C*'))
              result << enc
              prev = enc.bytes
            else
              dec  = des_ecb_decrypt(block.pack('C*'))
              xord = dec.bytes.zip(prev).map { |a, b| a ^ b }
              result << xord.pack('C*')
              prev = block
            end
          end

          result
        end

        def final
          ''.b
        end

        private

        # ── Bit-level helpers ──

        # Convert a byte string to an array of bits (MSB first per byte).
        def to_bits(data)
          data.bytes.flat_map { |byte| 8.times.map { |i| (byte >> (7 - i)) & 1 } }
        end

        # Convert an array of bits back to a byte string.
        def from_bits(bits)
          bits.each_slice(8).map { |b| b.each_with_index.reduce(0) { |acc, (bit, i)| acc | (bit << (7 - i)) } }.pack('C*')
        end

        # Apply a permutation table (1-based indices) to a bit array.
        def permute(bits, table)
          table.map { |i| bits[i - 1] }
        end

        def rotate_left(bits, n)
          bits[n..] + bits[0, n]
        end

        # ── Key schedule ──

        def generate_subkeys(key)
          cd = permute(to_bits(key), PC1)  # 56 bits
          c  = cd[0, 28]
          d  = cd[28, 28]
          ROTATIONS.map do |r|
            c = rotate_left(c, r)
            d = rotate_left(d, r)
            permute(c + d, PC2)  # 48-bit subkey
          end
        end

        # ── Feistel function f(R, K) ──

        def feistel(r_bits, subkey)
          # 1. Expand R from 32 to 48 bits
          er = permute(r_bits, E_TABLE)

          # 2. XOR with subkey
          xored = er.zip(subkey).map { |a, b| a ^ b }

          # 3. S-box substitution (8 × 6-bit groups → 8 × 4-bit groups = 32 bits)
          sout = 8.times.flat_map do |i|
            grp = xored[i * 6, 6]
            row = (grp[0] << 1) | grp[5]
            col = (grp[1] << 3) | (grp[2] << 2) | (grp[3] << 1) | grp[4]
            val = SBOX[i][row][col]
            [(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1]
          end

          # 4. P permutation
          permute(sout, P_TABLE)
        end

        # ── Single-block DES (ECB) operations ──

        def des_ecb_encrypt(block)
          bits = permute(to_bits(block), IP)
          l = bits[0, 32]
          r = bits[32, 32]

          16.times do |i|
            new_r = l.zip(feistel(r, @subkeys[i])).map { |a, b| a ^ b }
            l = r
            r = new_r
          end

          from_bits(permute(r + l, FP))
        end

        def des_ecb_decrypt(block)
          bits = permute(to_bits(block), IP)
          l = bits[0, 32]
          r = bits[32, 32]

          15.downto(0) do |i|
            new_r = l.zip(feistel(r, @subkeys[i])).map { |a, b| a ^ b }
            l = r
            r = new_r
          end

          from_bits(permute(r + l, FP))
        end
      end
    end
  end
end
