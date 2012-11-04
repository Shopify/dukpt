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

    DEC_MASK        = 0x0000000000FF00000000000000FF0000
    
    def derive_key(ipek, ksn)
      ksn_current = ksn.to_i(16)
      
      # Get 8 least significant bytes
      ksn_reg = ksn_current & LS16_MASK

      # Clear the 21 counter bits
      ksn_reg = ksn_reg & REG8_MASK
      
      # Grab the 21 counter bits
      reg_3 = ksn_current & REG3_MASK
      shift_reg = SHIFT_REG_MASK
      
      #Initialize "curkey" to be the derived "ipek"
      curkey = ipek.to_i(16)
      while (shift_reg > 0)
      	if shift_reg & reg_3 > 0
      	  ksn_reg = shift_reg | ksn_reg          
          curkey = keygen(curkey, ksn_reg)
      	end
      	shift_reg = shift_reg >> 1
      end
      hex_string_from_val(curkey, 16)
    end

    def keygen(key, ksn)
      cr1 = ksn
      cr2 = encrypt_register(key, cr1)      
      
      key2 = key ^ KEY_MASK
      
      cr1 = encrypt_register(key2, cr1)

      [hex_string_from_val(cr1, 8), hex_string_from_val(cr2, 8)].join.to_i(16)      
    end

    def pek_from_key(key)
      hex_string_from_val((key.to_i(16) ^ PEK_MASK), 16)
    end

    def dec_from_key(key)
      key = key.to_i(16)

      key = key ^ DEC_MASK

      left = (key & MS16_MASK) >> 64
      right = (key & LS16_MASK)

      invariant_key_hex = hex_string_from_val(key, 16)

      left = triple_des_encrypt(invariant_key_hex, hex_string_from_val(left, 8))
      right = triple_des_encrypt(invariant_key_hex, hex_string_from_val(right, 8))

      left = hex_string_from_val(left.to_i(16), 8)
      right = hex_string_from_val(right.to_i(16), 8)

      [left, right].join
    end

    def derive_PEK(ipek, ksn)
      pek_from_key(derive_key(ipek, ksn))      
    end

    def derive_DEC(ipek, ksn)
      dec_from_key(derive_key(ipek, ksn))
    end

    def derive_IPEK(bdk, ksn)
    	ksn_cleared_count = (ksn.to_i(16) & KSN_MASK) >> 16
    	left_half_of_ipek = triple_des_encrypt(bdk, hex_string_from_val(ksn_cleared_count, 8)) 
    	xor_base_derivation_key = bdk.to_i(16) ^ KEY_MASK
    	right_half_of_ipek = triple_des_encrypt(hex_string_from_val(xor_base_derivation_key, 8), hex_string_from_val(ksn_cleared_count, 8))
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
    
    def hex_string_from_val val, bytes
      val.to_s(16).rjust(bytes * 2, "0")
    end
    def encrypt_register(curkey, reg_8)
      left_key_half = (curkey & MS16_MASK) >> 64
  	  right_key_half = curkey & LS16_MASK

  		message = right_key_half ^ reg_8
  		ciphertext = des_encrypt(hex_string_from_val(left_key_half, 8), hex_string_from_val(message, 8)).to_i(16)
  		result = right_key_half ^ ciphertext

      result
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