# TLS termination, FFI surface. Implementation: native/o11y_tls.c (mbedTLS,
# the same static build used by the OTLP exporter's TLS client).
#
# Each port picks a config with a fixed ALPN:
#   TLS.otls_accept(fd, 0)  ... OTLP/HTTPS (ALPN http/1.1)
#   TLS.otls_accept(fd, 1)  ... OTLP/grpcs (ALPN h2)
# For h2-over-TLS the I/O switch happens inside o11y_h2.c via otls_is(fd),
# invisible to Ruby. The HTTP/1.1 side uses otls_read_line / otls_recv_some,
# which mirror the sp_net rl_* semantics (drain the line buffer first).

module TLS
  ffi_cflags "-I../../deps/mbedtls/include"
  ffi_cflags "-L../../deps/mbedtls/library"
  ffi_cflags "native/o11y_tls.c"
  ffi_lib "mbedtls"
  ffi_lib "mbedx509"
  ffi_lib "mbedcrypto"
  ffi_func :otls_init,        [:str, :str], :int   # (cert_path, key_path); -2/-3 = cert/key parse failure
  ffi_func :otls_accept,      [:int, :int], :int   # (fd, mode 0=http/1.1 1=h2); -2 = handshake failure
  ffi_func :otls_alpn,        [:int], :str
  ffi_func :otls_is,          [:int], :int
  ffi_func :otls_read_line,   [:int], :str
  ffi_func :otls_recv_some,   [:int, :int], :binstr
  ffi_func :otls_write_bytes, [:int, :str, :int], :int
  ffi_func :otls_close,       [:int], :void
end
