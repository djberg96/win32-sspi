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

      # NOTE: Experimental for now, may remove this marshalling stuff later

      def marshal_dump
        [self[:dwLower].read_ulong, self[:dwUpper].read_ulong]
      end

      def marshal_load(values)
        lptr = FFI::MemoryPointer.new(:ulong)
        hptr = FFI::MemoryPointer.new(:ulong)
        lptr.write_ulong(values[0])
        hptr.write_ulong(values[1])
      end
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

      def init(token = nil)
        self[:BufferType] = 2 # SECBUFFER_TOKEN

        if token
          self[:cbBuffer] = token.size
          self[:pvBuffer] = FFI::MemoryPointer.from_string(token)
        else
          self[:cbBuffer] = 4096 # Our TOKENBUFSIZE
          self[:pvBuffer] = FFI::MemoryPointer.new(:char, 1024)
        end

        self
      end
    end

    class SecBufferDesc < FFI::Struct
      layout(
        :ulVersion, :ulong,
        :cBuffers, :ulong,
        :pBuffers, :pointer,
      )

      def init(sec_buffer)
        self[:ulVersion] = 0 # SECBUFFER_VERSION
        self[:cBuffers]  = 1
        self[:pBuffers]  = sec_buffer
        self
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
