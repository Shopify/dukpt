module DUKPT
  class Encrypter
    include Encryption

    attr_reader :bdk

    def initialize(bdk, mode=nil)
      @bdk = bdk
      self.cipher_mode = mode.nil? ? 'cbc' : mode
    end

    def encrypt(message, ksn)
      ipek = derive_IPEK(bdk, ksn)
      pek = derive_PEK(ipek, ksn)
      cryptogram = triple_des_encrypt(pek, message)
      [cryptogram].pack('H*')
    end

    def encrypt_pin_block(pin_block, ksn)
      encrypt(pin_block, ksn)
    end

    def encrypt_pin(pin, pan, ksn)
      pan &&= pan.downcase.chomp('f')
      pin_field = "0#{pin.length}#{pin}".ljust(16, 'f')
      pan_field = "0000#{pan[-13..-2]}"
      pin_block = (pin_field.to_i(16) ^ pan_field.to_i(16)).to_s(16).rjust(16, '0')
      encrypt_pin_block(pin_block, ksn).unpack('H*').first
    end
  end
end
