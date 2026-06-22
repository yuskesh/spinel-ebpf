# examples/http_server/sendfile_demo/serve_deck_term.rb
#
# Dogfooding++ : the spinel-ebpf HTTP server serves its own presentation
# deck AND an in-browser terminal into the container.
#
#   GET  /            -> deck.html        (sendfile, text/html)
#   GET  /terminal    -> terminal.html    (sendfile, text/html) — browser shell UI
#   POST /api/exec    -> sp_net_shell_capture(<request body>) — RAW SHELL (root in
#                        container). LAN-only by user's choice. RCE by design.
#   GET  /health      -> "OK\n"
#
# Run: SPINEL_HTTP_PORT=8080 SPINEL_STATIC_FILE=/tmp/deck.html \
#      SPINEL_TERMINAL_FILE=/tmp/terminal.html ./serve_deck_term

require_relative "http_parser"

module Net
  ffi_func :sp_net_listen,        [:int, :int],    :int
  ffi_func :sp_net_accept,        [:int],          :int
  ffi_func :sp_net_read_line,     [:int],          :str
  ffi_func :sp_net_write_str,     [:int, :str],    :int
  ffi_func :sp_net_rl_close,         [:int],          :int
  ffi_func :sp_net_file_size,     [:str],          :int
  ffi_func :sp_net_sendfile,      [:int, :str],    :int
  ffi_func :sp_net_rl_recv_some,     [:int, :int],    :str
  ffi_func :sp_net_shell_capture, [:str, :int],    :str
end

def build_response(ctype, status, body)
  "HTTP/1.0 " + status + "\r\n" +
  "Content-Type: " + ctype + "\r\n" +
  "Content-Length: " + body.length.to_s + "\r\n" +
  "Connection: close\r\n" +
  "\r\n" +
  body
end

def serve_html(client, path)
  sz = Net.sp_net_file_size(path)
  if sz < 0
    Net.sp_net_write_str(client, build_response("text/plain", "404 Not Found", "Not Found\n"))
    return
  end
  header = "HTTP/1.0 200 OK\r\n" +
           "Content-Type: text/html; charset=utf-8\r\n" +
           "Content-Length: " + sz.to_s + "\r\n" +
           "Connection: close\r\n" +
           "\r\n"
  Net.sp_net_write_str(client, header)
  Net.sp_net_sendfile(client, path)
end

def drain_headers(fd)
  loop do
    line = Net.sp_net_read_line(fd)
    break if line.length == 0
  end
end

# ---- main ----

port      = (ENV["SPINEL_HTTP_PORT"]    || "8080").to_i
deck      = ENV["SPINEL_STATIC_FILE"]   || "/tmp/deck.html"
term_file = ENV["SPINEL_TERMINAL_FILE"] || "/tmp/terminal.html"

listen_fd = Net.sp_net_listen(port, 0)
if listen_fd < 0
  puts "[deck] tcp_listen(" + port.to_s + ") failed"
  exit(1)
end
puts "[deck] serving deck + /terminal (RAW /api/exec) on 0.0.0.0:" + port.to_s

loop do
  client = Net.sp_net_accept(listen_fd)
  if client < 0
    puts "[deck] accept failed"
    break
  end

  line = Net.sp_net_read_line(client)
  req  = parse_request_line(line)
  drain_headers(client)

  if req.valid == 1 && req.verb == "POST" && req.path == "/api/exec"
    cmd = Net.sp_net_rl_recv_some(client, 65000)         # request body = the command
    out = Net.sp_net_shell_capture(cmd, 65000)        # RAW shell, root in container
    Net.sp_net_write_str(client, build_response("text/plain; charset=utf-8", "200 OK", out))
  elsif req.valid == 1 && req.verb == "GET" && req.path == "/terminal"
    serve_html(client, term_file)
  elsif req.valid == 1 && req.verb == "GET" && req.path == "/health"
    Net.sp_net_write_str(client, build_response("text/plain", "200 OK", "OK\n"))
  elsif req.valid == 1 && req.verb == "GET"
    serve_html(client, deck)
  else
    Net.sp_net_write_str(client, build_response("text/plain", "405 Method Not Allowed", "Method Not Allowed\n"))
  end
  Net.sp_net_rl_close(client)
end

Net.sp_net_rl_close(listen_fd)
