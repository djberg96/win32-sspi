require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'structs')
require File.join(File.dirname(__FILE__), 'windows', 'functions')

module Win32
  module SSPI
    class Server
      include Windows::Constants
      include Windows::Structs
      include Windows::Functions

      attr_reader :auth_type

      def initialize(auth_type = 'NTLM')
        @auth_type = auth_type

        cred_handle = CredHandle.new
        time_struct = TimeStamp.new

        status = AcquireCredentialsHandle(
          nil,
          auth_type,
          SECPKG_CRED_INBOUND,
          nil,
          nil,
          nil,
          nil,
          cred_handle,
          time_struct
        )

        if status != SEC_E_OK
          raise SystemCallError.new('AcquireCredentialsHandle', FFI.errno)
        end

        begin
        ensure
          if FreeCredentialsHandle(cred_handle) != SEC_E_OK
            raise SystemCallError.new('FreeCredentialsHandle', FFI.errno)
          end
        end
      end
    end
  end
end

if $0 == __FILE__
  server = Win32::SSPI::Server.new
  p server
end
