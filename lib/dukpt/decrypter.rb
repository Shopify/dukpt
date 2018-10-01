module DUKPT
  class Decrypter
    include Encryption
    
    attr_reader :bdk

    def initialize(bdk, mode=nil)
      @bdk = bdk
      self.cipher_mode = mode.nil? ? 'cbc' : mode
    end

    def decrypt(cryptogram, ksn)
      decrypt_pin_block(cryptogram, ksn)
    end

    def decrypt_pin_block(cryptogram, ksn)
      ipek = derive_IPEK(bdk, ksn)
      pek = derive_PEK(ipek, ksn)
      decrypted_cryptogram = triple_des_decrypt(pek, cryptogram)
      [decrypted_cryptogram].pack('H*')
    end

    def decrypt_pin(cryptogram, ksn, pan)
      pan &&= pan.downcase.chomp('f')
      decrypted_block = decrypt_pin_block(cryptogram, ksn).unpack("H*").first
      block_format = decrypted_block[0]
      if block_format == "0"
        coded_pan = "0000"+pan[-13..-2]
        coded_pin = (decrypted_block.to_i(16) ^ coded_pan.to_i(16)).to_s(16).rjust(16, '0')
        pin_count = coded_pin[1].to_i
        coded_pin[2,pin_count]
      elsif block_format == "1"
        pin_count = decrypted_block[1]
        coded_pin[2,pin_count]
      end
    end

    def decrypt_data_block(cryptogram, ksn)
      ipek = derive_IPEK(bdk, ksn)
      dek = derive_DEK(ipek, ksn)
      decrypted_cryptogram = triple_des_decrypt(dek, cryptogram)
      [decrypted_cryptogram].pack('H*')
    end

  end
end