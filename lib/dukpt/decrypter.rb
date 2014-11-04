module DUKPT
  class Decrypter
    include Encryption
    
    attr_reader :bdk

    def initialize(bdk, mode=nil)
      @bdk = bdk
      self.cipher_mode = mode.nil? ? 'cbc' : mode
    end

    def decrypt(cryptogram, ksn)
      ipek = derive_IPEK(bdk, ksn)
      pek = derive_PEK(ipek, ksn)
      decrypted_cryptogram = triple_des_decrypt(pek, cryptogram)
      [decrypted_cryptogram].pack('H*')
    end

    def decrypt_pin_block(cryptogram, ksn)
      decrypt(cryptogram, ksn)
    end

    def decrypt_data_block(cryptogram, ksn)
      ipek = derive_IPEK(bdk, ksn)
      dek = derive_DEK(ipek, ksn)
      decrypted_cryptogram = triple_des_decrypt(dek, cryptogram)
      [decrypted_cryptogram].pack('H*')
    end

  end
end