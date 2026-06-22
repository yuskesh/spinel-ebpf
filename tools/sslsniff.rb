# sslsniff — dump TLS plaintext (bcc sslsniff equivalent).
#
# Uprobes SSL_write in libssl: the 2nd argument is the *plaintext* buffer the
# app hands to OpenSSL before encryption, so we stream it straight out. Set the
# target lib via SPNL_UPROBE_BINARY (system-wide when SPNL_UPROBE_PID unset):
#
#   export SPNL_UPROBE_BINARY=/usr/lib/aarch64-linux-gnu/libssl.so.3
#   bin/spinel-ebpf compile tools/sslsniff.rb --build -o build/sslsniff
#   sudo -E ./build/sslsniff/sslsniff &
#   curl -sk https://localhost:4433/        # GET line + response appear in plaintext
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def uprobe__SSL_write(ssl, buf, num)
  spnl_emit_str(buf)
end

puts "[sslsniff] dumping SSL_write plaintext (set SPNL_UPROBE_BINARY=libssl):"
Stream.spnl_stream(0)
