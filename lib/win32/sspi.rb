require 'ffi'

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

    ISC_REQ_CONFIDENTIALITY       = 0x00000010
    ISC_REQ_REPLAY_DETECT         = 0x00000004
    ISC_REQ_CONNECTION            = 0x00000800
    SEC_E_OK                      = 0x00000000
    SEC_I_CONTINUE_NEEDED         = 0x00090312
    SECURITY_NETWORK_DREP         = 0x00000000
    SEC_WINNT_AUTH_IDENTITY_ANSI  = 1
    SECPKG_CRED_OUTBOUND          = 2
    SECBUFFER_TOKEN               = 2
    SECBUFFER_VERSION             = 0
    TOKENBUFSIZE                  = 1024

    attr_reader :username
    attr_reader :domain
    attr_reader :auth_type
    attr_reader :token

    def initialize(username = nil, domain = nil, auth_type = 'Negotiate')
      @username  = username
      @domain    = domain
      @auth_type = auth_type
      @token     = nil
    end

    def get_initial_token(encode = false)
      auth_struct = SEC_WINNT_AUTH_IDENTITY.new
      cred_struct = CredHandle.new
      time_struct = TimeStamp.new

      auth_struct[:Flags] = SEC_WINNT_AUTH_IDENTITY_ANSI

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
