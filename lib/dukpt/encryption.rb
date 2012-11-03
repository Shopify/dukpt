require 'openssl'

module DUKPT
  module Encryption
    REG3_MASK       = 0x1FFFFF
    SHIFT_REG_MASK  = 0x100000
    REG8_MASK       = 0xFFFFFFFFFFE00000
    LS16_MASK       = 0x0000000000000000FFFFFFFFFFFFFFFF
    MS16_MASK       = 0xFFFFFFFFFFFFFFFF0000000000000000
    KEY_MASK        = 0xC0C0C0C000000000C0C0C0C000000000
    PEK_MASK        = 0x00000000000000FF00000000000000FF
    KSN_MASK        = 0xFFFFFFFFFFFFFFE00000
    
    def derive_key(ipek, ksn)
      ksn_current = ksn.to_i(16)
      
      # Get 8 least significant bytes
      ksn_reg = ksn_current & LS16_MASK

      # Clear the 21 counter bits
      reg_8 = ksn_reg & REG8_MASK
      
      # Grab the 21 counter bits
      reg_3 = ksn_current & REG3_MASK
      shift_reg = SHIFT_REG_MASK
      
      #Initialize "curkey" to be the derived "ipek"
      curkey = ipek.to_i(16)
      
      while (shift_reg > 0)
      	if shift_reg & reg_3 > 0
      	  reg_8 = shift_reg | reg_8
      	  reg_8a = encrypt_register(curkey, reg_8)
      		curkey = curkey ^ KEY_MASK
      		reg_8b = encrypt_register(curkey, reg_8)      		
      		curkey = [reg_8b.to_s(16), reg_8a.to_s(16)].join.to_i(16)
      	end
      	shift_reg = shift_reg >> 1
      end
      curkey.to_s(16).rjust(32, "0")
    end

    def derive_PEK(ipek, ksn)
      key = derive_key(ipek, ksn)

      (key.to_i(16) ^ PEK_MASK).to_s(16)
    end
    
    def derive_IPEK(bdk, ksn)
    	ksn_cleared_count = (ksn.to_i(16) & KSN_MASK) >> 16
    	left_half_of_ipek = triple_des_encrypt(bdk, ksn_cleared_count.to_s(16)) 
    	xor_base_derivation_key = bdk.to_i(16) ^ KEY_MASK
    	right_half_of_ipek = triple_des_encrypt(xor_base_derivation_key.to_s(16), ksn_cleared_count.to_s(16))
    	ipek_derived = left_half_of_ipek + right_half_of_ipek
    end
    
    def triple_des_decrypt(key, message)
    	openssl_encrypt("des-ede-cbc", key, message, false)
    end
    
    def triple_des_encrypt(key, message)
    	openssl_encrypt("des-ede-cbc", key, message, true)
    end
    
    def des_encrypt(key, message)
    	openssl_encrypt("des-cbc", key, message, true)
    end
    
    private
    
    def encrypt_register(curkey, reg_8)
      left_key_half = curkey & MS16_MASK
  	  right_key_half = curkey & LS16_MASK
  		message = right_key_half ^ reg_8
  		ciphertext = des_encrypt(left_key_half.to_s(16), message.to_s(16)).to_i(16)
  		right_key_half ^ ciphertext
    end
    
    def openssl_encrypt(cipher_type, key, message, is_encrypt)
    	cipher = OpenSSL::Cipher::Cipher::new(cipher_type)
    	is_encrypt ? cipher.encrypt : cipher.decrypt
    	cipher.padding = 0
    	cipher.key = [key].pack('H*')
    	# No Initial Vector is used in the process.
    	cipher_result = ""
    	cipher_result << cipher.update([message].pack('H*'))
    	cipher_result << cipher.final
    	cipher_result.unpack('H*')[0]
    end
  end
end