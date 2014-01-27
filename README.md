# DUKPT

This library implements a decrypter for ciphertext originating from a device using a Derived Unique Key Per Transaction (DUKPT) scheme.

## Installation

Add this line to your application's Gemfile:

    gem 'dukpt'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install dukpt

## Usage

    # Instantiate a decrypter with your base derivation key (BDK)
    decrypter = DUKPT::Decrypter.new("0123456789ABCDEFFEDCBA9876543210")

    # You can specify whether you want to use "ecb" cipher mode if needed. The default is "cbc".
    decrypter = DUKPT::Decrypter.new("0123456789ABCDEFFEDCBA9876543210", "ecb")

### To decrypt with PIN Key Variant
    # Pass the ciphertext and the current Key Serial Number (KSN), as hex encoded strings, to the decryptor to get back the plaintext
    ksn = "FFFF9876543210E00008"
    ciphertext = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12"
  
    plaintext = decrypter.decrypt_pin_key(ciphertext, ksn) # => "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\x00\x00\x00\x00"

### To decrypt with Data Key
    # Pass the ciphertext and the current Key Serial Number (KSN), as hex encoded strings, to the decryptor to get back the plaintext.
    # If you want Data Key decryption just pass true as the last parameter, otherwise Data Key Variant decryption is used.
    ksn = "00000141300056200198"
    ciphertext = "5F4A3CD7A67B61506848E1E6AC9A3FE9029156EA47A2FF40"

    plaintext = decrypter.decrypt_data_key(ciphertext, ksn) # => "B6011985164138410D16061010000036808787FB00000000"

    # The card number is 6011985164138410

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
