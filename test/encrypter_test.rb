require 'bundler/setup'
require 'test/unit'
require 'dukpt'

class DUKPT::EncrypterTest < Test::Unit::TestCase  
  
  def test_encrypt_track_data
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "FFFF9876543210E00008"
    ciphertext = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12"
    plaintext = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\x00\x00\x00\x00"
    
    encrypter = DUKPT::Encrypter.new(bdk, "cbc")
    decrypter = DUKPT::Decrypter.new(bdk, "cbc")
    assert_equal ciphertext, encrypter.encrypt(plaintext, ksn)
  end
  
end