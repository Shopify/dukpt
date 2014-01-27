require 'java'
java_import java.lang.System
java_import javax.crypto.spec.SecretKeySpec
java_import javax.crypto.Cipher
java_import java.io.ByteArrayOutputStream

module DUKPT
  module Encryption

    MAX_DES_EDE_CBC_LENGTH = 8
    FLAWED_JRUBY_CIPHERS = %w[des-ede des-ede-cbc]

    alias_method(:original_openssl_encrypt, :openssl_encrypt)

    def openssl_encrypt(cipher_type, key, message, is_encrypt)
      if jruby? && jruby_flawed_cipher?(cipher_type)
        openssl_encrypt_jruby(cipher_type, key, message, is_encrypt)
      else
        original_openssl_encrypt(cipher_type, key, message, is_encrypt)
      end
    end

    def openssl_encrypt_jruby(cipher_type, key, message, is_encrypt)
      message = [message].pack('H*').to_java_bytes

      secret_key = build_key(key)

      cipher = get_cipher

      if is_encrypt
        cipher.init(Cipher::ENCRYPT_MODE, secret_key)
      elsif cipher_type == 'des-ede-cbc' && message.length > MAX_DES_EDE_CBC_LENGTH
        raise "des-ede-cbc decryption not supported in jruby for data longer than #{MAX_DES_EDE_CBC_LENGTH} bytes"
      else
        cipher.init(Cipher::DECRYPT_MODE, secret_key)
      end

      baos = ByteArrayOutputStream.new
      baos.write(cipher.update(message))
      baos.write(cipher.doFinal)

      cipher_result = String.from_java_bytes(baos.toByteArray)

      cipher_result.unpack('H*')[0]
    end

    def jruby?
      defined?(RUBY_ENGINE) && RUBY_ENGINE == 'jruby'
    end

    def jruby_flawed_cipher?(cipher_method)
      FLAWED_JRUBY_CIPHERS.include?(cipher_method)
    end

    def get_cipher
      Cipher.getInstance('DESede/ECB/NoPadding')
    end

    def build_key(raw_key)
      original_key = [raw_key].pack('H*').to_java_bytes

      key = Java::byte[24].new
      System.arraycopy(original_key, 0, key, 0, 16)
      System.arraycopy(original_key, 0, key, 16, 8)

      SecretKeySpec.new(key, 'DESede')
    end

  end
end