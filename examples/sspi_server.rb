# Attempting to setup an example authenticating server
require 'win32/pipe'
require 'win32/sspi/server'

Win32::Pipe::Server.new('sspi') do |pipe|
  pipe.connect
  type_1_msg = pipe.read.first
  puts "Got Type 1 message: #{type_1_msg.inspect}"
  puts "=" * 50

  sspi_server = Win32::SSPI::Server.new(type_1_msg)
  type_2_msg = sspi_server.get_initial_token
  pipe.write(type_2_msg)

  type_3_msg = pipe.read.first
  puts "Got Type 3 message: #{type_3_msg.inspect}"
  puts "=" * 50

  sspi_server.complete_authentication(type_3_msg)
  puts "User: " + sspi_server.username
  puts "Domain: " + sspi_server.domain
  puts "Completed"
end
