# `:binstr` FFI return mode — binary-safe recv.
#
# `:str` builds the Ruby String up to the first NUL (C-string); `:binstr` builds
# it from exactly `sp_net_bin_len` bytes, so binary payloads with embedded NULs
# survive — the basis for binary protocols (WebSocket frames, binary uploads).
# spinel also sets TCP_NODELAY on accepted fds automatically.
#
# Uses the spinel-ebpf-owned sp_net_rl_recv_some (a read_line-aware, :binstr-safe
# recv) since sp_net_recv_some is a fixed-signature builtin.
#
# build: bin/spinel-ebpf compile examples/observability/binstr_echo.rb --native-only --build -o build
# run:   ./build/binstr_echo &   then send a body with NUL bytes to 127.0.0.1:9300
#   -> replies "len=<exact byte count>" (with :str it would truncate at the NUL)
module Net
  ffi_func :sp_net_listen,        [:int, :int], :int
  ffi_func :sp_net_accept,        [:int],       :int     # TCP_NODELAY set automatically
  ffi_func :sp_net_rl_recv_some,  [:int, :int], :binstr  # binary-safe (NUL-safe) read
  ffi_func :sp_net_write_str,     [:int, :str], :int
  ffi_func :sp_net_rl_close,      [:int],       :int
end

port = (ENV["SPINEL_HTTP_PORT"] || "9300").to_i
fd = Net.sp_net_listen(port, 0)
if fd < 0
  puts "listen failed"
  exit(1)
end
puts "binstr_echo on 127.0.0.1:" + port.to_s

client = Net.sp_net_accept(fd)
body = Net.sp_net_rl_recv_some(client, 65000)
n = body.bytesize
Net.sp_net_write_str(client, "len=" + n.to_s + "\n")
Net.sp_net_rl_close(client)
