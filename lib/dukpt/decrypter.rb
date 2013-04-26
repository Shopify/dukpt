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
  end
end