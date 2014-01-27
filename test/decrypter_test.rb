require 'bundler/setup'
require 'test/unit'
require 'dukpt'

class DUKPT::DecrypterTest < Test::Unit::TestCase

  def test_decrypt_pin_key
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "FFFF9876543210E00008"
    ciphertext = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12"
    plaintext = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\x00\x00\x00\x00"

    decrypter = DUKPT::Decrypter.new(bdk, "cbc")
    if defined?(RUBY_ENGINE) && RUBY_ENGINE == 'jruby'
      assert_raise RuntimeError do
        decrypter.decrypt_pin_key(ciphertext, ksn)
      end
    else
      assert_equal plaintext, decrypter.decrypt_pin_key(ciphertext, ksn)
    end
  end

  def test_decrypt_data_key
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "00000141300056200198"
    ciphertext = "5F4A3CD7A67B61506848E1E6AC9A3FE9029156EA47A2FF40"
    plaintext = "B6011985164138410D16061010000036808787FB00000000"

    decrypter = DUKPT::Decrypter.new(bdk, "ecb")
    assert_equal plaintext, decrypter.decrypt_data_key(ciphertext, ksn)
  end

end