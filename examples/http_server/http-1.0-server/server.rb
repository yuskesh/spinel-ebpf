# examples/http_server/http-1.0-server/server.rb
#
# Single-process HTTP/1.0 server. Single-process accept loop. Combines the
# TCP socket FFI and the request-line parser into a server that responds to
# GET / and GET /health with 200, returns 404 for unknown paths, 405 for
# non-GET methods, and 400 for malformed request lines. Each connection is
# one request + Connection: close (HTTP/1.0 default), no keepalive — the
# multi-process SO_REUSEPORT server revisits this when worker processes come
# in.
#
# Run: SPINEL_HTTP_PORT=8080 ./server   (port falls back to 8080 if unset)
# Stop: Ctrl+C (SIGINT) or kill.

require_relative "http_parser"

module Net
  ffi_func :sp_net_listen,     [:int, :int],    :int
  ffi_func :sp_net_accept,     [:int],          :int
  ffi_func :sp_net_read_line,  [:int],          :str
  ffi_func :sp_net_write_str,  [:int, :str],    :int
  ffi_func :sp_net_rl_close,      [:int],          :int
end

# Build the full HTTP/1.0 response (status line + minimal headers + body)
# as a single string so we issue one TCP write per request. Content-Length
# is mandatory for the client to know the body length without keepalive
# ambiguity; Connection: close signals end-of-stream.
def build_response(status, body)
  "HTTP/1.0 " + status + "\r\n" +
  "Content-Type: text/plain\r\n" +
  "Content-Length: " + body.length.to_s + "\r\n" +
  "Connection: close\r\n" +
  "\r\n" +
  body
end

# Route based on the parsed request. Returns a 2-element response built
# via build_response.
def route(req)
  if req.valid == 0
    return build_response("400 Bad Request",        "Bad Request\n")
  end
  if req.verb != "GET"
    return build_response("405 Method Not Allowed", "Method Not Allowed\n")
  end
  if req.path == "/"
    return build_response("200 OK",                 "hello\n")
  end
  if req.path == "/health"
    return build_response("200 OK",                 "OK\n")
  end
  build_response("404 Not Found",                   "Not Found\n")
end

# Drain header lines from the client until an empty line. Per HTTP/1.0 the
# empty line terminates the request preamble. For GET there's no body to
# follow, so we can respond immediately after.
def drain_headers(fd)
  loop do
    line = Net.sp_net_read_line(fd)
    break if line.length == 0
  end
end

# ---- main ----

port = (ENV["SPINEL_HTTP_PORT"] || "8080").to_i
listen_fd = Net.sp_net_listen(port, 0)
if listen_fd < 0
  puts "[server] tcp_listen(" + port.to_s + ") failed"
  exit(1)
end
puts "[server] spinel HTTP/1.0 on 127.0.0.1:" + port.to_s

loop do
  client = Net.sp_net_accept(listen_fd)
  if client < 0
    puts "[server] accept failed"
    break
  end

  line = Net.sp_net_read_line(client)
  req  = parse_request_line(line)
  drain_headers(client)

  response = route(req)
  Net.sp_net_write_str(client, response)
  Net.sp_net_rl_close(client)
end

Net.sp_net_rl_close(listen_fd)
