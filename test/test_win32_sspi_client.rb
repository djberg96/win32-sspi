########################################################################
# Tests for the Win32::SSPI::Client class.
########################################################################
require 'test-unit'
require 'win32/sspi/client'
require 'win32/sspi/server'

class TC_Win32_SSPI_Client < Test::Unit::TestCase
  def setup
    @client = Win32::SSPI::Client.new
    @server = Win32::SSPI::Server.new
    @type1 = nil
    @type3 = nil
  end

  test "username basic functionality" do
    assert_respond_to(@client, :username)
    assert_nothing_raised{ @client.username }
    assert_kind_of(String, @client.username)
  end

  test "username defaults to current user" do
    assert_equal(ENV['USERNAME'], @client.username)
  end

  test "domain basic functionality" do
    assert_respond_to(@client, :domain)
    assert_nothing_raised{ @client.domain }
    assert_kind_of(String, @client.domain)
  end

  test "domain defaults to current domain" do
    assert_equal(ENV['USERDOMAIN'], @client.domain)
  end

  test "password basic functionality" do
    assert_respond_to(@client, :password)
    assert_nothing_raised{ @client.password }
  end

  test "password is nil by default" do
    assert_nil(@client.password)
  end

  test "auth_type basic functionality" do
    assert_respond_to(@client, :auth_type)
    assert_nothing_raised{ @client.auth_type }
    assert_kind_of(String, @client.auth_type)
  end

  test "auth_type defaults to NTLM" do
    assert_equal('NTLM', @client.auth_type)
  end

  test "type_1_message basic functionality" do
    assert_respond_to(@client, :type_1_message)
    assert_nothing_raised{ @client.type_1_message }
  end

  test "type_1_message is initially nil" do
    assert_nil(@client.type_1_message)
  end

  test "type_3_message basic functionality" do
    assert_respond_to(@client, :type_3_message)
    assert_nothing_raised{ @client.type_3_message }
  end

  test "type_3_message is initially nil" do
    assert_nil(@client.type_3_message)
  end

  test "initial_token basic functionality" do
    assert_respond_to(@client, :initial_token)
  end

  test "initial_token method accepts an argument" do
    assert_nothing_raised{ @client.initial_token(true) }
  end

  test "initial_token generates and returns an expected token" do
    assert_nothing_raised{ @type1 = @client.initial_token }
    assert_kind_of(String, @type1)
    assert_true(@type1.size > 10)
  end

  test "the type_1_message accessor is set after initial_token is called" do
    @client.initial_token
    assert_not_nil(@client.type_1_message)
  end

  test "complete_authentication basic functionality" do
    assert_respond_to(@client, :complete_authentication)
  end

  test "complete_authentication accepts a type 2 message and returns a type 3 message" do
    assert_nothing_raised{ @type2 = @server.initial_token(@client.initial_token) }
    assert_nothing_raised{ @type3 = @client.complete_authentication(@type2) }
    assert_kind_of(String, @type3)
    assert_true(@type3.size > 10)
  end

  test "complete_authentication raises an error if a bogus token is passed" do
    assert_raise(Errno::EINVAL){ @client.complete_authentication('foo') }
  end

  def teardown
    @client = nil
    @server = nil
    @type1  = nil
    @type3  = nil
  end
end
