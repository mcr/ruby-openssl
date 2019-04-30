# -*- coding: utf-8 -*-
require_relative 'utils'
require 'byebug'

if defined?(OpenSSL)

class OpenSSL::TestIES < OpenSSL::TestCase
  def setup
    test_key = File.read(File.expand_path(File.join(__FILE__, '..', 'test_key.pem')))
    @ec = OpenSSL::PKey::EC::IES.new(test_key, "placeholder")
  end

  def test_ec_has_private_and_public_keys
    assert @ec.private_key?
    assert @ec.public_key?
  end

  def test_encrypt_then_decrypt_get_the_source_text
    source = 'いろはにほへと ちるぬるを わかよたれそ つねならむ うゐのおくやま けふこえて あさきゆめみし ゑひもせすん'
    cryptogram = @ec.public_encrypt(source)
    result = @ec.private_decrypt(cryptogram)
    assert_equal source, result.force_encoding('UTF-8')
  end

  def test_encrypt_only
    source = 'This is a simple test'
    cryptogram = @ec.public_encrypt(source)
    assert cryptogram
  end
end

end
