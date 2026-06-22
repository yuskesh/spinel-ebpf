# examples/http_server/sendfile_demo/server.rb
#
# sendfile(2) zero-copy static-file serving. Same single-process HTTP/1.0
# accept loop as the basic HTTP/1.0 server, with one extra route:
#
#   GET /static  -> the file named by $SPINEL_STATIC_FILE, streamed to the
#                   socket with sendfile(2). The body bytes go from the
#                   file page cache straight to the socket WITHOUT passing
#                   through a userspace buffer (nginx's `sendfile on`).
#   GET /        -> "hello\n" via the ordinary write(2) path (control, so
#                   strace shows write for / and sendfile for /static).
#   GET /health  -> "OK\n"
#
# HTTP framing (status line, headers, Content-Length) stays in Ruby; only
# the body byte transfer is pushed into the kernel. That is the whole
# point — "HTTP written in Ruby" keeps holding while we take the zero-copy win.
#
# Run: SPINEL_HTTP_PORT=8080 SPINEL_STATIC_FILE=/work/static.bin ./server
# Stop: Ctrl+C (SIGINT) or kill.

require_relative "http_parser"

module Net
  ffi_func :sp_net_listen,     [:int, :int],    :int
  ffi_func :sp_net_accept,     [:int],          :int
  ffi_func :sp_net_read_line,  [:int],          :str
  ffi_func :sp_net_write_str,  [:int, :str],    :int
  ffi_func :sp_net_rl_close,      [:int],          :int
  ffi_func :sp_net_file_size,  [:str],          :int
  ffi_func :sp_net_sendfile,   [:int, :str],    :int
end

# Plain string response (status line + minimal headers + body) for the
# non-static routes. One TCP write per request, Connection: close.
def build_response(status, body)
  "HTTP/1.0 " + status + "\r\n" +
  "Content-Type: text/plain\r\n" +
  "Content-Length: " + body.length.to_s + "\r\n" +
  "Connection: close\r\n" +
  "\r\n" +
  body
end

# Non-static routing, identical to the basic HTTP/1.0 server
# (400/405/200//200/health/404).
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

# Serve `path` over the connection with sendfile(2). We stat the file
# first so the Content-Length header is correct, write the header block
# with the ordinary write path, then hand the body to the kernel. If the
# file is missing / not a regular file, fall back to a 404.
def serve_static(client, path)
  sz = Net.sp_net_file_size(path)
  if sz < 0
    Net.sp_net_write_str(client, build_response("404 Not Found", "Not Found\n"))
    return
  end
  header = "HTTP/1.0 200 OK\r\n" +
           "Content-Type: application/octet-stream\r\n" +
           "Content-Length: " + sz.to_s + "\r\n" +
           "Connection: close\r\n" +
           "\r\n"
  Net.sp_net_write_str(client, header)   # header: ordinary write
  Net.sp_net_sendfile(client, path)      # body: kernel zero-copy
end

def drain_headers(fd)
  loop do
    line = Net.sp_net_read_line(fd)
    break if line.length == 0
  end
end

# ---- main ----

port        = (ENV["SPINEL_HTTP_PORT"]   || "8080").to_i
static_file = ENV["SPINEL_STATIC_FILE"]  || "/work/static.bin"

listen_fd = Net.sp_net_listen(port, 0)
if listen_fd < 0
  puts "[server] tcp_listen(" + port.to_s + ") failed"
  exit(1)
end
puts "[server] sendfile HTTP/1.0 on 127.0.0.1:" + port.to_s + " static=" + static_file

loop do
  client = Net.sp_net_accept(listen_fd)
  if client < 0
    puts "[server] accept failed"
    break
  end

  line = Net.sp_net_read_line(client)
  req  = parse_request_line(line)
  drain_headers(client)

  if req.valid == 1 && req.verb == "GET" && req.path == "/static"
    serve_static(client, static_file)
  else
    Net.sp_net_write_str(client, route(req))
  end
  Net.sp_net_rl_close(client)
end

Net.sp_net_rl_close(listen_fd)
