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
  end

  test "username defaults to current user" do
    assert_equal(ENV['USERNAME'], @client.username)
  end

  test "domain basic functionality" do
    assert_respond_to(@client, :domain)
    assert_nothing_raised{ @client.domain }
  end

  test "domain defaults to current domain" do
    assert_equal(ENV['USERDOMAIN'], @client.domain)
  end

  def teardown
    @client = nil
  end
end
