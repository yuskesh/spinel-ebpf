# examples/http_server/l7-path-counter/server.rb
#
# HTTP/1.0 server augmented with an L7 per-path counter that lives entirely
# in a BPF map. Every served request invokes `record_path_hit(path_key)`,
# which is partition-tagged :ebpf and so (with --ebpf-dispatch) routes
# through bpf_prog_test_run() into the `bpf_path_counts` HASH map. From
# userspace, the metric is observable via
#   bpftool map dump name bpf_path_counts
# and can be scraped by a future spnl_runtime exporter.
#
# Build:
#   spinel-ebpf compile examples/http_server/l7-path-counter/server.rb \
#       -o build/l7_server --build --ebpf-dispatch
# Run:
#   ./build/l7_server/server &
#   curl http://127.0.0.1:8080/
#   bpftool map dump name bpf_path_counts

require_relative "../http-1.0-server/http_parser"

module Net
  ffi_func :sp_net_listen,     [:int, :int],    :int
  ffi_func :sp_net_accept,     [:int],          :int
  ffi_func :sp_net_read_line,  [:int],          :str
  ffi_func :sp_net_write_str,  [:int, :str],    :int
  ffi_func :sp_net_rl_close,      [:int],          :int
end

# Keep the L7 keys small and stable so userspace bpftool dumps stay readable.
KEY_ROOT   = 1
KEY_HEALTH = 2
KEY_OTHER  = 3

# Lives in a :ebpf method so spinel-ebpf transparent dispatch routes
# this call through bpf_prog_test_run -> SEC("syscall") -> spnl_path_counter_inc
# -> bpf_map_update_elem (atomic add). Userspace observes via bpf_path_counts.
def record_path_hit(key)
  path_counter_inc(key)
  0
end

# Native-side: pick the BPF map key for the path. String compare keeps this
# method on the :native side of the partition (BPF can't easily hash strings;
# we hash up front and pass an int across the dispatch boundary).
def path_key(path)
  if path == "/"
    KEY_ROOT
  elsif path == "/health"
    KEY_HEALTH
  else
    KEY_OTHER
  end
end

def build_response(status, body)
  "HTTP/1.0 " + status + "\r\n" +
  "Content-Type: text/plain\r\n" +
  "Content-Length: " + body.length.to_s + "\r\n" +
  "Connection: close\r\n" +
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

# ---- main ----

port = (ENV["SPINEL_HTTP_PORT"] || "8080").to_i
listen_fd = Net.sp_net_listen(port, 0)
if listen_fd < 0
  puts "[server] tcp_listen(" + port.to_s + ") failed"
  exit(1)
end
puts "[server] spinel HTTP/1.0 + L7 BPF counter on 127.0.0.1:" + port.to_s

loop do
  client = Net.sp_net_accept(listen_fd)
  if client < 0
    puts "[server] accept failed"
    break
  end

  line = Net.sp_net_read_line(client)
  req  = parse_request_line(line)
  drain_headers(client)

  record_path_hit(path_key(req.path))   # L7 metric via BPF map (transparent dispatch)

  Net.sp_net_write_str(client, route(req))
  Net.sp_net_rl_close(client)
end

Net.sp_net_rl_close(listen_fd)
