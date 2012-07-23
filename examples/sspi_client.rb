require 'win32/pipe'
require 'win32/sspi/client'

Win32::Pipe::Client.new('sspi') do |pipe|
  sspi = Win32::SSPI::Client.new
  type_1_message = sspi.get_initial_token
  p type_1_message

  pipe.write(type_1_message)
  type_2_message = pipe.read.first
  p type_2_message
end
