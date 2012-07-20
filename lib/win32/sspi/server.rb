require 'ffi'

module Win32
  class SSPI::Server
    extend FFI::Library
    ffi_lib :secur32

    # TODO: Move FFI functions to a common declaration file.
    attach_function :AcquireCredentialsHandle, :AcquireCredentialsHandleA,
      [:string, :string, :ulong, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer],
      :ulong

    attach_function :AcceptSecurityContext,
      [:pointer, :pointer, :pointer, :ulong, :ulong, :pointer, :pointer, :pointer, :pointer],
      :ulong

    attach_function :FreeCredentialsHandle, [:pointer], :ulong

    def initialize(auth_type = 'NTLM')
       status = AcquireCredentialsHandle(
        nil,
        auth_type,
        SECPKG_CRED_INBOUND,
        nil,
        nil,
        nil,
        nil,
        cred_struct,
        time_struct
      )
    end
  end
end
