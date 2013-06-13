#!/usr/bin/ruby
require 'openssl'
require 'digest/sha1'
require 'cgi'

#nice way to get quick encryption into a project


#cipher for docstoc auth request
#this is used to obtain a ticket when sending files
class String
  def encrypt(options = {})
    Docstoc::Cipher.new(options).encrypt(self)
  end

  def decrypt(options = {})
    Docstoc::Cipher.new(options).decrypt(self)
  end
end

module Docstoc
=begin
  class String
    def encrypt(options = {})
      Cipher.new(options).encrypt(self)
    end

    def decrypt(options = {})
      Cipher.new(options).decrypt(self)
    end
  end
=end

  class Cipher
    CONF = File.join(RAILS_ROOT, 'lib/pdf_uploads/docstoc/conf.yml')
    def initialize(options = {})

      creds = YAML::load(File.read(CONF))[:cipher]
      @options = {
        :algorithm => 'aes-128-cbc',
        :method    => 'encrypt',
        :key       => creds[:auth_key],
        :iv        => creds[:iv]
      }
      @options.update(options)

      @convert = lambda {|c, string|
        c.key = @options[:key]
        c.iv  = @options[:iv]
        res = c.update(string)
        res << c.final
        res
      }
    end

    def encrypt(string)
      c = OpenSSL::Cipher::Cipher.new(@options[:algorithm])
      c.encrypt
      [@convert.call(c, string)].pack("*m")
    end

    def decrypt(base64_string)
      #must ask for key or this whole project
      #is pointless

      string = base64_string.unpack("*m")[0]
      c = OpenSSL::Cipher::Cipher.new(@options[:algorithm])
      c.decrypt
      @convert.call(c, string)
    end

    def self.get_post_creds
      ['testuser'.encrypt, 'testpass'.encrypt]
    end

    def self.test_inverse
      ['testuser'.encrypt.decrypt, 'testpass'.encrypt.decrypt]
    end

    def self.test_size(size, options = {})
      large_string = (0..size).map {('a'..'z').map[rand(27)] }.join('')
      large_string == large_string.encrypt(options).decrypt(options)
    end

    def self.test_algo_switch
      %w(128 192 256).map {|bits|
        self.test_size(10000, :algorithm => "aes-#{bits}-cbc", :key => rand(1<<bits.to_i).to_s(base=16))
      }
    end

    def self.test_file_encryption
      File.new(__FILE__).read.encrypt
    end
  end
end
