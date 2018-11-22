require 'bundler/setup'
require 'test/unit'
require 'dukpt'

class DUKPT::DecrypterTest < Test::Unit::TestCase

  def test_decrypt_track_data
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "FFFF9876543210E00008"
    ciphertext = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12"
    plaintext = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\x00\x00\x00\x00"

    decrypter = DUKPT::Decrypter.new(bdk, "cbc")
    assert_equal plaintext, decrypter.decrypt(ciphertext, ksn)
  end

  def test_decrypt_data_block
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "FFFF01040DA058E00001"
    ciphertext = "85A8A7F9390FD19EABC40B5D624190287D729923D9EDAFE9F24773388A9A1BEF"
    plaintext = ["5A08476173900101001057114761739001010010D15122011143878089000000"].pack("H*")

    decrypter = DUKPT::Decrypter.new(bdk, "cbc")
    assert_equal plaintext, decrypter.decrypt_data_block(ciphertext, ksn)
  end

  def test_decrypt_pin
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "F8765432108D12400014"
    ciphertext = "129C4FC2537BB63E"
    pan = "5413330089601109"
    plaintext_pin = "4315"

    decrypter = DUKPT::Decrypter.new(bdk)
    assert_equal plaintext_pin, decrypter.decrypt_pin(ciphertext, ksn, pan)
  end

  def test_decrypt_pin_with_padded_pan
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "F8765432108D12400011"
    ciphertext = "8C3169A2ABC1632F"
    pan = "6799998900000060919F"
    plaintext_pin = "4315"

    decrypter = DUKPT::Decrypter.new(bdk)
    assert_equal plaintext_pin, decrypter.decrypt_pin(ciphertext, ksn, pan)
  end

  def test_decrypt_pin_without_pan
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "F8765432108D12400011"
    ciphertext = "87b452c4b38a90337006b23960731b77"
    plaintext_pin = "4315"

    decrypter = DUKPT::Decrypter.new(bdk)
    assert_equal plaintext_pin, decrypter.decrypt_pin(ciphertext, ksn, nil)
  end
end
