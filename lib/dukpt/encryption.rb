require 'openssl'

module DUKPT
  module Encryption
    REG3_MASK       = 0x000000000000000000000000001FFFFF
    SHIFT_REG_MASK  = 0x00000000000000000000000000100000
    REG8_MASK       = 0x0000000000000000FFFFFFFFFFE00000
    LS16_MASK       = 0x0000000000000000FFFFFFFFFFFFFFFF
    MS16_MASK       = 0xFFFFFFFFFFFFFFFF0000000000000000
    KEY_MASK        = 0xC0C0C0C000000000C0C0C0C000000000
    PEK_MASK        = 0x00000000000000FF00000000000000FF
    KSN_MASK        = 0x000000000000FFFFFFFFFFFFFFE00000
    DEK_MASK        = 0x0000000000FF00000000000000FF0000 # Used by IDTECH reader

    def cipher_mode=(cipher_type)
      if cipher_type == "ecb"
        @cipher_type_des = "des-ecb"
        @cipher_type_tdes = "des-ede"
      else
        @cipher_type_des = "des-cbc"
        @cipher_type_tdes = "des-ede-cbc"
      end
    end

    def derive_pek_from_ipek(ipek, ksn)
      #Initialize "curkey" to be the derived "ipek"
      initial_key = ipek.to_i(16)

      key_serial_number = ksn.to_i(16)
      serial_number = key_serial_number & REG8_MASK
      transaction_number = key_serial_number & REG3_MASK

      create_key(initial_key, serial_number, transaction_number)
    end

    def create_key(current_key, serial_number, transaction_number)
      shift_number = SHIFT_REG_MASK
      encrypted_serial_number = serial_number
      while (shift_number > 0)
        if shift_number & transaction_number > 0
          encrypted_serial_number = shift_number | encrypted_serial_number
          current_key = keygen(current_key, encrypted_serial_number)
        end
        shift_number = shift_number >> 1
      end
      hex_string_from_val(current_key, 16)
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

    def derive_dek_from_pek(key)
      key = key.to_i(16)

      key = key ^ DEK_MASK

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
      pek_from_key(derive_pek_from_ipek(ipek, ksn))
    end

    def derive_DEK(ipek, ksn)
      derive_dek_from_pek(derive_pek_from_ipek(ipek, ksn))
    end

    def derive_IPEK(bdk, ksn)
    	ksn_cleared_count = (ksn.to_i(16) & KSN_MASK) >> 16
    	left_half_of_ipek = triple_des_encrypt(bdk, hex_string_from_val(ksn_cleared_count, 8))
    	xor_base_derivation_key = bdk.to_i(16) ^ KEY_MASK
    	right_half_of_ipek = triple_des_encrypt(hex_string_from_val(xor_base_derivation_key, 8), hex_string_from_val(ksn_cleared_count, 8))
    	ipek_derived = left_half_of_ipek + right_half_of_ipek
    end

    def aes_decrypt(key, message)
      openssl_encrypt("aes-128-cbc", key, message, false)
    end

    def triple_des_decrypt(key, message)
    	openssl_encrypt(cipher_type_tdes, key, message, false)
    end

    def triple_des_encrypt(key, message)
    	openssl_encrypt(cipher_type_tdes, key, message, true)
    end

    def des_encrypt(key, message)
    	openssl_encrypt(cipher_type_des, key, message, true)
    end

    private

    def cipher_type_des
      @cipher_type_des || "des-cbc"
    end

    def cipher_type_tdes
      @cipher_type_tdes || "des-ede-cbc"
    end

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
      cipher = OpenSSL::Cipher.new(cipher_type)
    	is_encrypt ? cipher.encrypt : cipher.decrypt
    	cipher.padding = 0
    	cipher.key = [key].pack('H*')
    	cipher_result = ""
    	cipher_result << cipher.update([message].pack('H*'))
    	cipher_result << cipher.final
    	cipher_result.unpack('H*')[0]
    end
  end
end
