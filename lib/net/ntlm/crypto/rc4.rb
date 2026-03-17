# Pure-Ruby RC4 (ARCFOUR) stream cipher with an OpenSSL::Cipher-compatible interface.
# Required because OpenSSL 3.x disables RC4 by default.
#
# NTLM uses RC4 for session key exchange in the AUTHENTICATE message.

require 'securerandom'

module Net
  module NTLM
    module Crypto
      class RC4
        def initialize
          @s = (0..255).to_a
          @i = 0
          @j = 0
          @key = nil
        end

        # Sets the cipher key and initialises the KSA (Key Scheduling Algorithm).
        def key=(k)
          @key = k.b
          key_bytes = @key.bytes
          key_len   = key_bytes.length
          @s = (0..255).to_a
          j = 0
          256.times do |i|
            j = (j + @s[i] + key_bytes[i % key_len]) % 256
            @s[i], @s[j] = @s[j], @s[i]
          end
          @i = @j = 0
          self
        end

        # Generates a random 16-byte key, sets it, and returns the raw key bytes.
        # Matches the OpenSSL::Cipher#random_key interface.
        def random_key
          k = SecureRandom.random_bytes(16)
          self.key = k
          k
        end

        # No-op — RC4 is symmetric; encrypt/decrypt are the same operation.
        def encrypt; self; end
        def decrypt; self; end

        def update(data)
          data.b.bytes.map do |byte|
            @i = (@i + 1) % 256
            @j = (@j + @s[@i]) % 256
            @s[@i], @s[@j] = @s[@j], @s[@i]
            byte ^ @s[(@s[@i] + @s[@j]) % 256]
          end.pack('C*')
        end

        def final
          ''.b
        end
      end
    end
  end
end
