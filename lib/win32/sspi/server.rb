require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'structs')
require File.join(File.dirname(__FILE__), 'windows', 'functions')

module Win32
  module SSPI
    class Server
      include Windows::Constants
      include Windows::Structs
      include Windows::Functions

      attr_reader :input
      attr_reader :auth_type

      def initialize(input, auth_type = 'NTLM')
        @input = input
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
          context = CtxtHandle.new
          expirty = TimeStamp.new

          sec_buf = SecBuffer.new
          sec_buf[:BufferType] = SECBUFFER_TOKEN
          sec_buf[:cbBuffer] = TOKENBUFSIZE
          sec_buf[:pvBuffer] = FFI::MemoryPointer.new(:char, TOKENBUFSIZE)

          output = SecBufferDesc.new
          output[:ulVersion] = SECBUFFER_VERSION
          output[:cBuffers] = 1
          output[:pBuffers] = sec_buf

          context_attr = FFI::MemoryPointer.new(:ulong)

          status = AcceptSecurityContext(
            cred_handle,
            nil,
            input,
            ASC_REQ_DELEGATE, # Just imitating mod_auth_sspi here
            SECURITY_NATIVE_DREP,
            context,
            output,
            context_attr,
            expiry
          )

          if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE)
            if CompleteAuthToken(context, output) != SEC_E_OK
              raise SystemCallError.new('CompleteAuthToken', FFI.errno)
            end
          end

          if status != SEC_E_OK
            raise SystemCallError.new('AcceptSecurityContext', FFI.errno)
          end
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
