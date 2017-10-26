require 'bundler/setup'
require 'test/unit'
require 'dukpt'

class DUKPT::EncrypterTest < Test::Unit::TestCase
  def test_encrypt_pin
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "F8765432108D12400014"
    plaintext_pin = "4315"
    ciphertext = "129C4FC2537BB63E"
    pan = "5413330089601109"

    encrypter = DUKPT::Encrypter.new(bdk)
    assert_equal ciphertext, encrypter.encrypt_pin(plaintext_pin, pan, ksn).upcase
  end

  def test_encrypt_pin_with_padded_pan
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "F8765432108D12400014"
    plaintext_pin = "4315"
    ciphertext = "129C4FC2537BB63E"
    pan = "5413330089601109F"

    encrypter = DUKPT::Encrypter.new(bdk)
    assert_equal ciphertext, encrypter.encrypt_pin(plaintext_pin, pan, ksn).upcase
  end
end
