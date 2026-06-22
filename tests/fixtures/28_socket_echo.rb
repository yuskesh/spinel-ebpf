# TCP socket FFI smoke test.
#
# Binds 127.0.0.1:8080, accepts a single connection, echoes one line back,
# and exits. Pair with `echo hi | nc 127.0.0.1 8080` in another shell.
#
# This exercises every helper added to spinel for the HTTP server milestone:
#   - sp_net_listen / sp_net_accept     (socket + bind + listen + accept)
#   - sp_net_read_line                  (line-buffered read)
#   - sp_net_write_str                  (retry-until-done write)
#   - sp_net_close                      (cleanup)
#
# A second fixture (an HTTP server example) will reuse the
# same module bindings to handle HTTP requests instead of bare echo.

module Net
  ffi_func :sp_net_listen,     [:int, :int],    :int
  ffi_func :sp_net_accept,     [:int],          :int
  ffi_func :sp_net_read_line,  [:int],          :str
  ffi_func :sp_net_write_str,  [:int, :str],    :int
  ffi_func :sp_net_close,      [:int],          :int
end

server = Net.sp_net_listen(8080, 0)
if server < 0
  puts "[echo] tcp_listen failed"
  exit(1)
end
puts "[echo] listening on 127.0.0.1:8080"

client = Net.sp_net_accept(server)
if client < 0
  puts "[echo] accept failed"
  Net.sp_net_close(server)
  exit(1)
end
puts "[echo] accepted client"

line = Net.sp_net_read_line(client)
puts "[echo] got: #{line}"
Net.sp_net_write_str(client, "echo: ")
Net.sp_net_write_str(client, line)
Net.sp_net_write_str(client, "\n")

Net.sp_net_close(client)
Net.sp_net_close(server)
puts "[echo] done"
