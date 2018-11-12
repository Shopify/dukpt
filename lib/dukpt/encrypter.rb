module DUKPT
  class Encrypter
    include Encryption
    
    attr_reader :bdk

    def initialize(bdk, mode=nil)
      @bdk = bdk
      self.cipher_mode = mode.nil? ? 'cbc' : mode
    end

    def encrypt(plaintext, ksn)
      encrypt_pin_block(plaintext, ksn)
    end

    def encrypt_pin_block(plaintext, ksn)
      ipek = derive_IPEK(bdk, ksn)
      pek = derive_PEK(ipek, ksn)
      triple_des_encrypt(pek, plaintext.unpack("H*").first).upcase
    end

    def encrypt_data_block(plaintext, ksn)
      ipek = derive_IPEK(bdk, ksn)
      dek = derive_DEK(ipek, ksn)
      triple_des_encrypt(dek, plaintext.unpack("H*").first).upcase
    end
  end
end