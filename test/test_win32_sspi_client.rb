########################################################################
# Tests for the Win32::SSPI::Client class.
########################################################################
require 'test-unit'
require 'win32/sspi/client'

class TC_Win32_SSPI_Client < Test::Unit::TestCase
  def setup
    @client = Win32::SSPI::Client.new
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

  def teardown
    @client = nil
  end
end
