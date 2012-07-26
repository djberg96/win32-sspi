require 'base64'

require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'structs')
require File.join(File.dirname(__FILE__), 'windows', 'functions')

module Win32
  module SSPI
    class Client
      include Windows::Constants
      include Windows::Structs
      include Windows::Functions

      attr_reader :username
      attr_reader :domain
      attr_reader :auth_type
      attr_reader :context
      attr_reader :credentials

      # For analysis of type 1 messages. Not sure if this is useful yet.
      class MessageType1
        attr_reader :workstation
        attr_reader :domain
        attr_reader :signature

        # Breakdown based on http://davenport.sourceforge.net/ntlm.html
        def initialize(token)
          @signature = token[0,8].strip
          @type1_indicator = token[8,4]
          @flags = token[12,4]
          @domain_security_buffer = token[16,8]
          @worstation_security_buffer = token[24,8]
          @os_version_structure = token[32,8]
          @workstation = token[40,12]
          @domain = token[52..-1]
        end
      end

      def initialize(username = nil, domain = nil, password = nil, auth_type = 'NTLM')
        @username  = username || ENV['USERNAME'].dup
        @domain    = domain   || ENV['USERDOMAIN'].dup
        @password  = password
        @auth_type = auth_type
        @token     = nil
        @context   = CtxtHandle.new
        @credentials = CredHandle.new
        @context_attributes = FFI::MemoryPointer.new(:ulong)
      end

      def token(encoded = false)
        if encoded
          Base64.encode64(@token).delete("\n")
        else
          @token
        end
      end

      # Generate the type 1 message
      def get_initial_token(local = true, encode = false)
        time_struct = TimeStamp.new
        auth_struct = nil

        # If local is true, obtain handle to credentials of the logged in user.
        #
        # FIXME: Causes the client to choke in the complete_authentication method.
        unless local
          if @username || @domain || @password
            auth_struct = SEC_WINNT_AUTH_IDENTITY.new
            auth_struct[:Flags] = SEC_WINNT_AUTH_IDENTITY_ANSI

            if @username
              auth_struct[:User] = FFI::MemoryPointer.from_string(@username.dup)
              auth_struct[:UserLength] = @username.size
            end

            if @domain
              auth_struct[:Domain] = FFI::MemoryPointer.from_string(@domain.dup)
              auth_struct[:DomainLength] = @domain.size
            end

            if @password
              auth_struct[:Password] = FFI::MemoryPointer.from_string(@password.dup)
              auth_struct[:PasswordLength] = @password.size
            end
          end
        end

        status = AcquireCredentialsHandle(
          nil,
          @auth_type,
          SECPKG_CRED_OUTBOUND,
          nil,
          auth_struct,
          nil,
          nil,
          @credentials,
          time_struct
        )

        if status != SEC_E_OK
          raise SystemCallError.new('AcquireCredentialsHandle', FFI.errno)
        end

        rflags = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION
        expiry = TimeStamp.new

        sec_buf = SecBuffer.new.init
        buffer  = SecBufferDesc.new.init(sec_buf)

        status = InitializeSecurityContext(
          @credentials,
          nil,
          nil,
          rflags,
          0,
          SECURITY_NETWORK_DREP,
          nil,
          0,
          @context,
          buffer,
          @context_attributes,
          expiry
        )

        if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED
          raise SystemCallError.new('InitializeSecurityContext', FFI.errno)
        else
          bsize = sec_buf[:cbBuffer]
          @token = sec_buf[:pvBuffer].read_string_length(bsize)
        end

        @token
      end

      # Here the token is a type 2 message received from the server and,
      # assuming all goes well, returns a type 3 message.
      #
      def complete_authentication(token)
        rflags = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION

        expiry = TimeStamp.new

        sec_buf_in = SecBuffer.new.init(token)
        buf_in = SecBufferDesc.new.init(sec_buf_in)

        sec_buf_out = SecBuffer.new.init
        buf_out = SecBufferDesc.new.init(sec_buf_out)

        status = InitializeSecurityContext(
          @credentials,
          @context,
          nil,
          rflags,
          0,
          SECURITY_NETWORK_DREP,
          buf_in,
          0,
          @context,
          buf_out,
          @context_attributes,
          expiry
        )

        if status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK
          raise SystemCallError.new('InitializeSecurityContext', FFI.errno)
        end

        bsize = sec_buf_out[:cbBuffer]
        token = sec_buf_out[:pvBuffer].read_string_length(bsize)

        ptr = SecPkgContext_Names.new

        status = QueryContextAttributes(@context, SECPKG_ATTR_NAMES, ptr)

        if status != SEC_E_OK
          raise SytemCallError.new('QueryContextAttributes', FFI.errno)
        end

        user_string = ptr[:sUserName].read_string

        if user_string.include?("\\")
          @domain, @username = user_string.split("\\")
        end

        if @context && DeleteSecurityContext(@context) != SEC_E_OK
          raise SystemCallError.new('DeleteSecurityContext', FFI.errno)
        end

        if @credentials && FreeCredentialsHandle(@credentials) != SEC_E_OK
          raise SystemCallError.new('FreeCredentialsHandle', FFI.errno)
        end

        @context = nil
        @credentials = nil
        @context_attributes = nil

        token
      end
    end # Client
  end # SSPI
end # Win32

# Eventually delete this
if $0 == __FILE__
  #sspi = Win32::SSPI::Client.new(nil, nil, 'NTLM')
  sspi = Win32::SSPI::Client.new
  sspi.get_initial_token
  #p sspi.context
  #token = sspi.token
  #p token
  #p token
  #m = Win32::SSPI::MessageType1.new(token)
  #p m.domain
  #p m.workstation
  #p m.signature

  # According to http://davenport.sourceforge.net/ntlm.html
  #p token[0,8]   # NTLMSSP Sig
  #p token[8,4]   # Type 1 indicator
  #p token[12,4]  # Flags
  #p token[16,8]  # Supplied Domain buffer
  #p token[24,8]  # Supplied Workstation buffer
  #p token[32,-1] # OS Version structure
  #p token[40,12]  # Supplied Workstation data
  #p token[52..-1] # Supplied domain data
end
