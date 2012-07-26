require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'structs')
require File.join(File.dirname(__FILE__), 'windows', 'functions')

module Win32
  module SSPI
    class Server
      include Windows::Constants
      include Windows::Structs
      include Windows::Functions
      extend Windows::Functions

      attr_reader :input
      attr_reader :auth_type
      attr_reader :token

      # Here the input is the type 1 message received from the client
      def initialize(input, auth_type = 'NTLM')
        @input = input
        @auth_type = auth_type
        @token = nil
        @context = CtxtHandle.new
        @credentials = CredHandle.new
      end

      def get_initial_token
        time_struct = TimeStamp.new

        status = AcquireCredentialsHandle(
          nil,
          @auth_type,
          SECPKG_CRED_INBOUND,
          nil,
          nil,
          nil,
          nil,
          @credentials,
          time_struct
        )

        if status != SEC_E_OK
          raise SystemCallError.new('AcquireCredentialsHandle', FFI.errno)
        end

        expiry  = TimeStamp.new
        outbuf  = SecBuffer.new.init
        inbuf   = SecBuffer.new.init(@input)

        outbuf_sec = SecBufferDesc.new.init(outbuf)
        inbuf_sec  = SecBufferDesc.new.init(inbuf)

        context_attr = FFI::MemoryPointer.new(:ulong)

        status = AcceptSecurityContext(
          @credentials,
          nil,
          inbuf_sec,
          ASC_REQ_DELEGATE, # Just imitating mod_auth_sspi here
          SECURITY_NATIVE_DREP,
          @context,
          outbuf_sec,
          context_attr,
          expiry
        )

        if status != SEC_E_OK
          if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE
            if CompleteAuthToken(@context, output) != SEC_E_OK
              raise SystemCallError.new('CompleteAuthToken', FFI.errno)
            end
          else
            unless status == SEC_I_CONTINUE_NEEDED
              raise SystemCallError.new('AcceptSecurityContext', FFI.errno)
            end
          end
        end

        bsize = outbuf[:cbBuffer]
        @token = outbuf[:pvBuffer].read_string_length(bsize)

        @token
      end

      # Here the token is the type 3 message received from the client
      def complete_authentication(token)
        inbuf = SecBuffer.new.init(token)
        inbuf_sec = SecBufferDesc.new.init(inbuf)

        context_attr = FFI::MemoryPointer.new(:ulong)

        status = AcceptSecurityContext(
          @credentials,
          @context,
          inbuf_sec,
          ASC_REQ_DELEGATE,
          SECURITY_NATIVE_DREP,
          @context,
          nil,
          context_attr,
          nil
        )

        if status != SEC_E_OK
          raise SystemCallError.new('AcceptSecurityContext', FFI.errno)
        end

        if @credentials && FreeCredentialsHandle(@credentials) != SEC_E_OK
          raise SystemCallError.new('FreeCredentialsHandle', FFI.errno)
        end
      end

      def self.security_packages
        num = FFI::MemoryPointer.new(:ulong)
        spi = FFI::MemoryPointer.new(SecPkgInfo, 20) # Should be plenty
        arr = []

        result = EnumerateSecurityPackages(num, spi)

        if result != SEC_E_OK
          raise SystemCallError.new('EnumerateSecurityPackages', FFI.errno)
        else
          begin
            num = num.read_long

            ptr = spi[0].read_pointer

            num.times{
              s = SecPkgInfo.new(ptr)
              arr << s[:Name]
              ptr += SecPkgInfo.size
            }
          ensure
            FreeContextBuffer(ptr)
          end
        end

        arr
      end
    end
  end
end

if $0 == __FILE__
  #server = Win32::SSPI::Server.new
  #p server
  p Win32::SSPI::Server.security_packages
end
