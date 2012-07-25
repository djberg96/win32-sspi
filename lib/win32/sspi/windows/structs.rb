require 'ffi'

module Windows
  module Structs
    extend FFI::Library

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

      def initialize(token = nil, mem = nil)
        super(mem)

        self[:BufferType] = 2 # SECBUFFER_TOKEN

        if token
          self[:cbBuffer] = token.size
          self[:pvBuffer] = FFI::MemoryPointer.from_string(token)
        else
          self[:cbBuffer] = 1024 # Our TOKENBUFSIZE
          self[:pvBuffer] = FFI::MemoryPointer.new(:char, 1024)
        end
      end
    end

    class SecBufferDesc < FFI::Struct
      layout(
        :ulVersion, :ulong,
        :cBuffers, :ulong,
        :pBuffers, :pointer,
      )

      def initialize(sec_buffer = nil, mem = nil)
        super(mem)
        self[:ulVersion] = 0 # SECBUFFER_VERSION
        self[:cBuffers]  = 1
        self[:pBuffers]  = sec_buffer
      end
    end

    class SecPkgInfo < FFI::Struct
      layout(
        :fCapabilities, :ulong,
        :wVersion, :ushort,
        :wRPCID, :ushort,
        :cbMaxToken, :ulong,
        :Name, :string,
        :Comment, :string
      )
    end

    class SecPkgContext_Names < FFI::Struct
      layout(:sUserName, :pointer)
    end
  end
end
