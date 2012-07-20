module Windows
  module Constants
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
  end
end
