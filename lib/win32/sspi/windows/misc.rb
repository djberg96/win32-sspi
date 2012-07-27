class String
  # Determine if a string is base64 encoded. Use this to automatically
  # decode tokens if already encoded.
  #
  def base64?
    unpack("m").pack("m").delete("\n") == delete("\n")
  end
end
