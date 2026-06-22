# examples/http_server/epoll/server.rb
#
# Event-driven spinel HTTP/1.1 server (epoll), the answer to the blocking
# model's limits. The blocking keepalive server serves ONE connection per
# worker — its keepalive inner loop occupies the worker, so N workers handle
# only N concurrent connections; matching nginx needed 4-8x oversubscribed
# workers and still peaked roughly 21% lower.
#
# Here each worker runs an epoll event loop and multiplexes MANY connections
# (like nginx): epoll_wait returns the next ready fd; if it's the listen socket we
# accept a new client and add it; otherwise we read its (keepalive) request and
# respond, leaving it registered for the next one. One worker per core now
# saturates the box.
#
# Benchmark-grade simplification: epoll signals "readable", and small GET requests
# arrive complete in one packet, so we read the request with the (blocking, but
# data-is-present) buffered read_line. A production server would use non-blocking
# reads + per-fd buffering for partial/pipelined requests; here wrk sends one
# complete request per readable event, fully consumed before we switch fds.
#
# Pure userspace (no eBPF) -> builds --native-only.
#   spinel-ebpf compile examples/http_server/epoll/server.rb --build --native-only -o build/epoll
#   SPINEL_HTTP_WORKERS=6 SPINEL_HTTP_PORT=8080 ./build/epoll/server

require_relative "../http-1.0-server/http_parser"

module Net
  ffi_func :sp_net_listen,         [:int, :int], :int
  ffi_func :sp_net_accept,         [:int],       :int
  ffi_func :sp_net_read_line,      [:int],       :str
  ffi_func :sp_net_write_str,      [:int, :str], :int
  ffi_func :sp_net_rl_close,          [:int],       :int
  ffi_func :sp_net_fork,           [],           :int
  ffi_func :sp_net_getpid,         [],           :int
  ffi_func :sp_net_epoll_create,   [],           :int
  ffi_func :sp_net_epoll_add,      [:int, :int], :int
  ffi_func :sp_net_epoll_del,      [:int, :int], :int
  ffi_func :sp_net_epoll_wait_one, [:int],       :int
end

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
  ep = Net.sp_net_epoll_create
  if ep < 0
    puts "[worker " + Net.sp_net_getpid.to_s + "] epoll_create failed"
    exit(1)
  end
  Net.sp_net_epoll_add(ep, listen_fd)
  puts "[worker " + my_idx.to_s + " pid=" + Net.sp_net_getpid.to_s + "] event-driven (epoll) ready on port " + port.to_s

  loop do
    fd = Net.sp_net_epoll_wait_one(ep)
    if fd < 0
      break                                  # error / shutdown
    elsif fd == listen_fd
      # Level-triggered: accept one; epoll re-fires while more are pending.
      client = Net.sp_net_accept(listen_fd)
      if client >= 0
        Net.sp_net_epoll_add(ep, client)
      end
    else
      line = Net.sp_net_read_line(fd)
      if line.length == 0
        Net.sp_net_epoll_del(ep, fd)         # EOF / peer closed
        Net.sp_net_rl_close(fd)
      else
        req = parse_request_line(line)
        drain_headers(fd)
        Net.sp_net_write_str(fd, route(req))
        # leave fd in epoll for the next keepalive request
      end
    end
  end

  Net.sp_net_rl_close(listen_fd)
end

# ---- main ----

port    = (ENV["SPINEL_HTTP_PORT"]    || "8080").to_i
workers = (ENV["SPINEL_HTTP_WORKERS"] || "4").to_i
if workers < 1
  workers = 1
end

puts "[main " + Net.sp_net_getpid.to_s + "] epoll event-driven server starting " + workers.to_s + " worker(s) on port " + port.to_s

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
