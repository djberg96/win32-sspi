require 'ffi'
require 'base64'

module Win32
  class SSPI
    extend FFI::Library
    ffi_lib :secur32

    attach_function :AcquireCredentialsHandle, :AcquireCredentialsHandleA,
      [:string, :string, :ulong, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer],
      :ulong

    attach_function :InitializeSecurityContext, :InitializeSecurityContextA,
      [:pointer, :pointer, :string, :ulong, :ulong, :ulong, :pointer, :ulong, :pointer, :pointer, :pointer, :pointer],
      :ulong

    attach_function :FreeCredentialsHandle, [:pointer], :ulong
    attach_function :DeleteSecurityContext, [:pointer], :ulong

    class SEC_WINNT_AUTH_IDENTITY < FFI::Struct
      layout(
        :User, :pointer,
        :UserLength, :ulong,
        :Domain, :pointer,
        :DomainLength, :ulong,
        :Password, :pointer,
        :PasswordLength, :ulong,
        :Flags, :ulong
      )
    end

    class SecHandle < FFI::Struct
      layout(:dwLower, :pointer, :dwUpper, :pointer)
    end

    CredHandle = SecHandle
    CtxtHandle = SecHandle

    class TimeStamp < FFI::Struct
      layout(:dwLowDateTime, :ulong, :dwHighDateTime, :ulong)
    end

    class SecBuffer < FFI::Struct
      layout(
        :cbBuffer, :ulong,
        :BufferType, :ulong,
        :pvBuffer, :pointer
      )
    end

    class SecBufferDesc < FFI::Struct
      layout(
        :ulVersion, :ulong,
        :cBuffers, :ulong,
        :pBuffers, :pointer,
      )
    end

    ISC_REQ_CONFIDENTIALITY         = 0x00000010
    ISC_REQ_REPLAY_DETECT           = 0x00000004
    ISC_REQ_CONNECTION              = 0x00000800
    SEC_E_OK                        = 0x00000000
    SEC_I_CONTINUE_NEEDED           = 0x00090312
    SECURITY_NETWORK_DREP           = 0x00000000
    SEC_WINNT_AUTH_IDENTITY_ANSI    = 1
    SEC_WINNT_AUTH_IDENTITY_UNICODE = 2
    SECPKG_CRED_OUTBOUND            = 2
    SECBUFFER_TOKEN                 = 2
    SECBUFFER_VERSION               = 0
    TOKENBUFSIZE                    = 1024

    attr_reader :username
    attr_reader :domain
    attr_reader :auth_type

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

    def initialize(username = nil, domain = nil, auth_type = 'Negotiate')
      @username  = username || ENV['USERNAME'].dup
      @domain    = domain   || ENV['USERDOMAIN'].dup
      @auth_type = auth_type
      @token     = nil
    end

    def token(encoded = false)
      if encoded
        Base64.encode64(@token).delete("\n")
      else
        @token
      end
    end

    def get_initial_token(local = true, encode = false)
      cred_struct = CredHandle.new
      time_struct = TimeStamp.new
      auth_struct = nil

      # If local is true, obtain handle to credentials of the logged in user.
      unless local
        if @username || @domain
          auth_struct = SEC_WINNT_AUTH_IDENTITY.new
          auth_struct[:Flags] = SEC_WINNT_AUTH_IDENTITY_UNICODE

          if @username
            username = @username.concat(0.chr).encode('UTF-16LE')
            auth_struct[:User] = FFI::MemoryPointer.from_string(username)
            auth_struct[:UserLength] = username.size
          end

          if @domain
            domain = @domain.concat(0.chr).encode('UTF-16LE')
            auth_struct[:Domain] = FFI::MemoryPointer.from_string(domain)
            auth_struct[:DomainLength] = domain.size
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
        cred_struct,
        time_struct
      )

      if status != SEC_E_OK
        raise SystemCallError.new('AcquireCredentialsHandle', FFI.errno)
      end

      begin
        rflags = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION
        expiry = TimeStamp.new

        context_struct = CtxtHandle.new
        context_attrib = FFI::MemoryPointer.new(:ulong)

        sec_buf = SecBuffer.new
        sec_buf[:BufferType] = SECBUFFER_TOKEN
        sec_buf[:cbBuffer] = TOKENBUFSIZE
        sec_buf[:pvBuffer] = FFI::MemoryPointer.new(:char, TOKENBUFSIZE)

        buffer = SecBufferDesc.new
        buffer[:ulVersion] = SECBUFFER_VERSION
        buffer[:cBuffers] = 1
        buffer[:pBuffers] = sec_buf

        status = InitializeSecurityContext(
          cred_struct,
          nil,
          nil,
          rflags,
          0,
          SECURITY_NETWORK_DREP,
          nil,
          0,
          context_struct,
          buffer,
          context_attrib,
          expiry
        )

        if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED
          raise SystemCallError.new('InitializeSecurityContext', FFI.errno)
        else
          bsize = sec_buf[:cbBuffer]
          @token = sec_buf[:pvBuffer].read_string_length(bsize)


          if DeleteSecurityContext(context_struct) != SEC_E_OK
            raise SystemCallError.new('DeleteSecurityContext', FFI.errno)
          end
        end
      ensure
        if FreeCredentialsHandle(cred_struct) != SEC_E_OK
          raise SystemCallError.new('FreeCredentialsHandle', FFI.errno)
        end
      end
    end
  end
end

# Eventually delete this
if $0 == __FILE__
  sspi = Win32::SSPI.new(nil, nil, 'NTLM')
  sspi.get_initial_token
  token = sspi.token
  #p token
  m = Win32::SSPI::MessageType1.new(token)
  p m.domain
  p m.workstation
  p m.signature

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
