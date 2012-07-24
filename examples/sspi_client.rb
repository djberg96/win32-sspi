require 'win32/pipe'
require 'win32/sspi/client'

Win32::Pipe::Client.new('sspi') do |pipe|
  client = Win32::SSPI::Client.new

  type_1_message = client.get_initial_token
  p type_1_message
  pipe.write(type_1_message)

  puts "=" * 50

  type_2_message = pipe.read.first
  p type_2_message

  puts "=" * 50

  type_3_message = client.complete_authentication(type_2_message)
  p type_3_message
  pipe.write(type_3_message)
end
