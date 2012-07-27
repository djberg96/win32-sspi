########################################################################
# Tests for the Win32::SSPI::Server class.
########################################################################
require 'test-unit'
require 'win32/sspi/client'
require 'win32/sspi/server'

class TC_Win32_SSPI_Server < Test::Unit::TestCase
  def setup
    @client = Win32::SSPI::Client.new
    @server = Win32::SSPI::Server.new
    @type1 = nil
    @type2 = nil
  end

  test "auth_type basic functionality" do
    assert_respond_to(@server, :auth_type)
    assert_nothing_raised{ @server.auth_type }
    assert_kind_of(String, @server.auth_type)
  end

  test "auth_type defaults to NTLM" do
    assert_equal('NTLM', @server.auth_type)
  end

  test "type_1_message basic functionality" do
    assert_respond_to(@server, :type_1_message)
    assert_nothing_raised{ @server.type_1_message }
  end

  test "type_1_message is initially nil" do
    assert_nil(@server.type_1_message)
  end

  test "type_2_message basic functionality" do
    assert_respond_to(@server, :type_2_message)
    assert_nothing_raised{ @server.type_2_message }
  end

  test "type_2_message is initially nil" do
    assert_nil(@server.type_2_message)
  end

  test "username basic functionality" do
    assert_respond_to(@server, :username)
    assert_nothing_raised{ @server.username }
  end

  test "username is initially nil" do
    assert_nil(@server.username)
  end

  test "domain basic functionality" do
    assert_respond_to(@server, :domain)
    assert_nothing_raised{ @server.domain }
  end

  test "domain is initially nil" do
    assert_nil(@server.domain)
  end

  test "initial_token basic functionality" do
    assert_respond_to(@server, :initial_token)
  end

  test "initial_token accepts a type 1 message and returns a type 2 message" do
    @type1 = @client.initial_token
    assert_nothing_raised{ @type2 = @server.initial_token(@type1) }
    assert_kind_of(String, @type2)
    assert_true(@type2.size > 10)
  end

  test "the type_1_message accessor is set after initial_token is called" do
    @type1 = @client.initial_token
    @server.initial_token(@type1)
    assert_not_nil(@server.type_1_message)
    assert_kind_of(String, @server.type_1_message)
  end

  test "the type_2_message accessor is set after initial_token is called" do
    @type1 = @client.initial_token
    @server.initial_token(@type1)
    assert_not_nil(@server.type_2_message)
    assert_kind_of(String, @server.type_2_message)
  end

  test "complete_authentication basic functionality" do
    assert_respond_to(@server, :complete_authentication)
  end

  test "complete_authentication accepts a type 3 message and returns a status" do
    @type1 = @client.initial_token
    @type2 = @server.initial_token(@type1)
    @type3 = @client.complete_authentication(@type2)
    result = nil

    assert_nothing_raised{ result = @server.complete_authentication(@type3) }
    assert_kind_of(Numeric, result)
  end

  test "complete_authentication raises an error if a bogus token is passed" do
    assert_raise(Errno::EINVAL){ @server.complete_authentication('foo') }
  end

  def teardown
    @client = nil
    @server = nil
    @type1  = nil
    @type2  = nil
  end
end
