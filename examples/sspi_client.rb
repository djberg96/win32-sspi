require 'win32/pipe'
require 'win32/sspi/client'

Win32::Pipe::Client.new('sspi') do |pipe|
  client = Win32::SSPI::Client.new

  type_1_message = client.initial_token
  puts "Generated type 1 message: #{type_1_message.inspect}"
  pipe.write(client.type_1_message)

  puts "=" * 50

  type_2_message = pipe.read.first
  puts "Received type 2 message from server: #{type_2_message.inspect}"

  puts "=" * 50

  type_3_message = client.complete_authentication(type_2_message)
  puts "Generated type 3 message: #{type_3_message.inspect}"
  pipe.write(client.type_3_message)
end
