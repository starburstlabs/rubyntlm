# Pure-Ruby MD4 digest implementation (RFC 1320).
# Required because OpenSSL 3.x disables MD4 (legacy provider) by default,
# and Ruby 3.4 ships with openssl gem linked against OpenSSL 3.x.
#
# NTLM requires MD4 for computing the NT hash from a password.

module Net
  module NTLM
    module Crypto
      module MD4
        MASK = 0xffffffff

        module_function

        def digest(data)
          # Build a fresh binary (ASCII-8BIT) buffer to avoid encoding conflicts.
          # encode_utf16le returns strings whose encoding tag is UTF-8 even though
          # the bytes are UTF-16LE; using an explicit binary buffer ensures all
          # concatenation stays ASCII-8BIT regardless of the caller's encoding.
          msg = ::String.new(encoding: Encoding::BINARY)
          msg << data.b

          # Initialize state (little-endian constants)
          a = 0x67452301
          b = 0xefcdab89
          c = 0x98badcfe
          d = 0x10325476

          # Pad message: append 0x80, zeros, then 64-bit LE bit-length
          bit_len = msg.bytesize * 8
          msg << 0x80.chr(Encoding::BINARY)
          msg << 0x00.chr(Encoding::BINARY) while msg.bytesize % 64 != 56
          msg << [bit_len & MASK, bit_len >> 32].pack('VV')

          # Process each 512-bit (64-byte) block
          msg.unpack('V*').each_slice(16) do |x|
            aa, bb, cc, dd = a, b, c, d

            # Round 1 — F(b,c,d) = (b & c) | (~b & d), const = 0
            r1_shifts = [3, 7, 11, 19]
            16.times do |i|
              s = r1_shifts[i % 4]
              t = (a + f(b, c, d) + x[i]) & MASK
              a, b, c, d = d, left_rotate(t, s), b, c
            end

            # Round 2 — G(b,c,d) = (b & c) | (b & d) | (c & d), const = 0x5a827999
            r2_order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
            r2_shifts = [3, 5, 9, 13]
            16.times do |i|
              s = r2_shifts[i % 4]
              t = (a + g(b, c, d) + x[r2_order[i]] + 0x5a827999) & MASK
              a, b, c, d = d, left_rotate(t, s), b, c
            end

            # Round 3 — H(b,c,d) = b ^ c ^ d, const = 0x6ed9eba1
            r3_order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            r3_shifts = [3, 9, 11, 15]
            16.times do |i|
              s = r3_shifts[i % 4]
              t = (a + h(b, c, d) + x[r3_order[i]] + 0x6ed9eba1) & MASK
              a, b, c, d = d, left_rotate(t, s), b, c
            end

            a = (a + aa) & MASK
            b = (b + bb) & MASK
            c = (c + cc) & MASK
            d = (d + dd) & MASK
          end

          [a, b, c, d].pack('V4')
        end

        def f(b, c, d); (b & c) | (~b & d); end
        def g(b, c, d); (b & c) | (b & d) | (c & d); end
        def h(b, c, d); b ^ c ^ d; end

        def left_rotate(x, n)
          ((x << n) | (x >> (32 - n))) & MASK
        end
      end
    end
  end
end
