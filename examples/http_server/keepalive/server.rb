# examples/http_server/keepalive/server.rb
#
# HTTP/1.1 keepalive (persistent connections) on top of the SO_REUSEPORT
# server. This exists to measure the spinel HTTP server's REAL-network
# capacity fairly against nginx: the HTTP/1.0 servers use Connection: close
# (one request per connection), which over a real network is bound by RTT +
# connection-per-request churn (the server sits idle at ~1k RPS regardless of
# cores). nginx with keepalive saturates the box; spinel could not even be
# compared until it learned keepalive. This variant adds that.
#
# Pure userspace (no eBPF): drops the L7 path counter and the sk_reuseport
# BPF program so it builds --native-only (no libbpf) and isolates the
# keepalive question. Still multi-worker via fork + SO_REUSEPORT.
#
# Build:  spinel-ebpf compile examples/http_server/keepalive/server.rb --build --native-only -o build/keepalive
# Run:    SPINEL_HTTP_WORKERS=6 SPINEL_HTTP_PORT=8080 ./build/keepalive/server

require_relative "../http-1.0-server/http_parser"

module Net
  ffi_func :sp_net_listen,    [:int, :int], :int
  ffi_func :sp_net_accept,    [:int],       :int
  ffi_func :sp_net_read_line, [:int],       :str
  ffi_func :sp_net_write_str, [:int, :str], :int
  ffi_func :sp_net_rl_close,     [:int],       :int
  ffi_func :sp_net_fork,      [],           :int
  ffi_func :sp_net_getpid,    [],           :int
end

# HTTP/1.1 response with Content-Length and NO "Connection: close" — HTTP/1.1
# defaults to persistent, so the client (wrk default, browsers) reuses the socket.
def build_response(status, body)
  "HTTP/1.1 " + status + "\r\n" +
  "Content-Type: text/plain\r\n" +
  "Content-Length: " + body.length.to_s + "\r\n" +
  "\r\n" +
  body
end

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

# Read request headers up to (and including) the blank line that ends them.
def drain_headers(fd)
  loop do
    line = Net.sp_net_read_line(fd)
    break if line.length == 0
  end
end

def worker_loop(port, my_idx)
  listen_fd = Net.sp_net_listen(port, 1)
  if listen_fd < 0
    puts "[worker " + Net.sp_net_getpid.to_s + "] listen failed"
    exit(1)
  end
  puts "[worker " + my_idx.to_s + " pid=" + Net.sp_net_getpid.to_s + "] keepalive ready on port " + port.to_s

  loop do
    client = Net.sp_net_accept(listen_fd)
    if client < 0
      break
    end
    # Keepalive: serve successive requests on the SAME connection. The first
    # read_line of an empty string means the client closed (EOF) -> done with
    # this connection. sp_net_read_line's per-fd buffer persists across these
    # reads and is reset by sp_net_rl_close().
    loop do
      line = Net.sp_net_read_line(client)
      break if line.length == 0
      req = parse_request_line(line)
      drain_headers(client)
      Net.sp_net_write_str(client, route(req))
    end
    Net.sp_net_rl_close(client)
  end

  Net.sp_net_rl_close(listen_fd)
end

# ---- main ----

port    = (ENV["SPINEL_HTTP_PORT"]    || "8080").to_i
workers = (ENV["SPINEL_HTTP_WORKERS"] || "4").to_i
if workers < 1
  workers = 1
end

puts "[main " + Net.sp_net_getpid.to_s + "] keepalive server starting " + workers.to_s + " worker(s) on port " + port.to_s

my_idx = 0
i = 1
while i < workers
  pid = Net.sp_net_fork
  if pid < 0
    puts "[main] fork failed"
    exit(1)
  end
  if pid == 0
    my_idx = i
    break
  end
  i = i + 1
end

worker_loop(port, my_idx)
