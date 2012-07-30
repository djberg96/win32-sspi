require File.join(File.dirname(__FILE__), 'constants')

class String
  # Determine if a string is base64 encoded. Use this to automatically
  # decode tokens if already encoded.
  #
  def base64?
    unpack("m").pack("m").delete("\n") == delete("\n")
  end
end

# This maps SECURITY_STATUS results into a value that SystemCallError understands
class SecurityStatus
  include Windows::Constants
  
  def initialize(errno)
    @new_errno = 0
    
    case errno
      when SEC_E_INSUFFICIENT_MEMORY
        @new_errno = 12 # ENOMEM
      when SEC_E_INTERNAL_ERROR
        @new_errno = 35 # Unknown
      when SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_UNSUPPORTED_FUNCTION, SEC_E_WRONG_PRINCIPAL
        @new_errno = 22 # EINVAL
      when SEC_E_LOGON_DENIED
        @new_errno = 1 # EPERM
      when SEC_E_NO_AUTHENTICATING_AUTHORITY, SEC_E_NO_CREDENTIALS, SEC_E_TARGET_UNKNOWN
        @new_errno = 3 # ESRCH
      else
        @new_errno = 35 # Unknown
    end
  end
  
  def to_i
    @new_errno
  end
  
  def to_int
    @new_errno
  end
end
