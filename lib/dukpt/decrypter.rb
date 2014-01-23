module DUKPT
  class Decrypter
    include Encryption

    attr_reader :bdk

    def initialize(bdk, mode=nil)
      @bdk = bdk
      self.cipher_mode = mode.nil? ? 'cbc' : mode
    end

    def decrypt_pin_key(cryptogram, ksn)
      ipek = derive_IPEK(bdk, ksn)
      pek = derive_PEK(ipek, ksn)
      decrypted_cryptogram = triple_des_decrypt(pek, cryptogram)
      [decrypted_cryptogram].pack('H*')
    end

    def decrypt_data_key(cryptogram, ksn, use_variant=true)
      ipek = derive_IPEK(bdk, ksn)
      dek = derive_DEK(ipek, ksn, use_variant)

      triple_des_decrypt(dek, cryptogram).upcase
    end

  end
end