require 'test/unit'
require 'bundler/setup'
require 'dukpt'

class DUKPT::EncryptionTest < Test::Unit::TestCase
  include DUKPT::Encryption
  
  def test_least_signinficant_16_nibbles_mask
    expected = 0x00009876543210E00008
    actual   = 0xFFFF9876543210E00008 & LS16_MASK
    assert_equal expected, actual
  end
  
  def test_register_8_mask
    expected = 0x00009876543210e00000
    actual   = 0xFFFF9876543210E00008 & REG8_MASK
    assert_equal expected, actual
  end
  
  def test_register_3_mask
    expected = 0x1FFFFF
    actual   = 0xFFFFFFFFFFFFFFFFFFFF & REG3_MASK
    assert_equal expected, actual
  end
  
  def test_derive_ipek
    ksn = "FFFF9876543210E00008"
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ipek = derive_IPEK(bdk, ksn)
    assert_equal '6ac292faa1315b4d858ab3a3d7d5933a', ipek
  end
  
  def test_derive_pek
    ksn = "FFFF9876543210E00008"
    pek = derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '27f66d5244ff621eaa6f6120edeb427f', pek
  end
  
  def test_derive_key_3
    ksn = "FFFF9876543210E00003"
    key = derive_key('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '0DF3D9422ACA56E547676D07AD6BADFA', key.upcase
  end

  def test_derive_pek_counter_3
    ksn = "FFFF9876543210E00003"
    pek = derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '0DF3D9422ACA561A47676D07AD6BAD05', pek.upcase
  end

  def test_derive_pek_counter_7
    ksn = "FFFF9876543210E00007"
    pek = derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '0C8F780B7C8B492FAE84A9EB2A6CE69F', pek.upcase
  end

  def test_derive_pek_counter_F
    ksn = "FFFF9876543210E0000F"
    pek = derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '93DD5B956C4878B82E453AAEFD32A555', pek.upcase
  end

  def test_derive_pek_counter_10
    ksn = "FFFF9876543210E00010"
    pek = derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '59598DCBD9BD943F94165CE453585FA8', pek.upcase
  end

  def test_derive_pek_counter_13
    ksn = "FFFF9876543210E00013"
    pek = derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal 'C3DF489FDF11534BF03DE97C27DC4CD0', pek.upcase
  end

  def test_derive_pek_counter_EFF800
    ksn = "FFFF9876543210EFF800"
    pek = derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal 'F9CDFEBF4F5B1D61B3EC12454527E189', pek.upcase
  end

  def test_triple_des_decrypt
    ciphertext = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12"
    data_decrypted = triple_des_decrypt('27f66d5244ff621eaa6f6120edeb427f', ciphertext)
    assert_equal '2542353435323330303535313232373138395e484f47414e2f5041554c2020202020205e30383034333231303030303030303732353030303030303f00000000', data_decrypted
  end
  
  def test_triple_des_decrypt_with_ecb
    self.cipher_mode = "ecb"
    ciphertext = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12"
    data_decrypted = triple_des_decrypt('27f66d5244ff621eaa6f6120edeb427f', ciphertext)
    assert_equal '2542353435323330f2692820a5e12b9bbf110311e7d5453a0989597b8d3373e0718df68ec04a96ff0704673b0041cc2fe12da84c41b85772e98ed0f0d1ea1064', data_decrypted
  end

  def test_unpacking_decrypted_data
    data_decrypted = '2542353435323330303535313232373138395e484f47414e2f5041554c2020202020205e30383034333231303030303030303732353030303030303f00000000'
    expected = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\x00\x00\x00\x00"
    assert_equal expected, [data_decrypted].pack('H*')
  end
    
  def test_cipher_mode_ecb
    self.cipher_mode = "ecb"
    assert_equal cipher_type_des, "des-ecb"
    assert_equal cipher_type_tdes, "des-ede"
  end

  def test_dek_from_key 
    key = "27F66D5244FF62E1AA6F6120EDEB4280"
    dek = dek_from_key(key)
    assert_equal "C39B2778B058AC376FB18DC906F75CBA", dek.upcase
  end

  def test_derive_dek_counter_13
    ksn = "FFFF9876543210E00013"
    dek = derive_DEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '44893E3434ABDD6A817CE2841825E1FD', dek.upcase
  end

end