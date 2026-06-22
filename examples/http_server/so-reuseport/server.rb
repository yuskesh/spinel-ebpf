# examples/http_server/so-reuseport/server.rb
#
# Multi-process spinel HTTP/1.0 server. Each worker creates its own listen
# socket with SO_REUSEPORT bound to the same port; the kernel's default
# 5-tuple hash spreads incoming SYNs across the reuseport group. An optional
# SO_ATTACH_REUSEPORT_EBPF program adds consistent-hash worker pinning (see
# below).
#
# Inherits everything from the L7 path-counter server (HTTP/1.0 routing, L7
# BPF counter via transparent dispatch). Adds a parent that forks N workers,
# plus each worker's pid tagged onto the log so connections can be attributed.
#
# Build:
#   spinel-ebpf compile examples/http_server/so-reuseport/server.rb \
#       -o build/reuseport_server --build --ebpf-dispatch
# Run:
#   SPINEL_HTTP_WORKERS=4 ./build/reuseport_server/server
#   # in another shell: curl http://127.0.0.1:8080/ ; ab -c 100 -n 10000 ...

require_relative "../http-1.0-server/http_parser"

module Net
  ffi_func :sp_net_listen,                [:int, :int],    :int
  ffi_func :sp_net_accept,                [:int],          :int
  ffi_func :sp_net_read_line,             [:int],          :str
  ffi_func :sp_net_write_str,             [:int, :str],    :int
  ffi_func :sp_net_rl_close,                 [:int],          :int
  ffi_func :sp_net_fork,                  [],              :int
  ffi_func :sp_net_getpid,                [],              :int
end

# SO_REUSEPORT BPF helpers — register a worker's socket in the SOCKARRAY
# and attach the sk_reuseport__select program to the reuseport group.
module ReuseportBpf
  ffi_func :sp_bpf_reuseport_register, [:int, :int], :int
  ffi_func :sp_bpf_reuseport_attach,   [:int, :str], :int
end

# SK_REUSEPORT BPF program. The kernel passes ctx with a 5-tuple hash;
# we map that to a worker index modulo SPINEL_HTTP_WORKERS (compile-time
# constant) and call bpf_sk_select_reuseport via the worker_select builtin.
# `SK_PASS` confirms the selection (or lets the kernel fall back if the
# slot is empty).
SK_PASS  = 0
WORKERS  = 4   # keep in sync with the SPINEL_HTTP_WORKERS env default. The
               # :ebpf method below uses a literal 4 because the BPF codegen
               # doesn't yet resolve user-defined ConstantReadNode (KNOWN_CONSTANTS
               # only covers kernel enums); plumbing const values through the IR
               # is future work.

# Consistent-hash worker selection. The kernel-computed 5-tuple hash
# (sk_reuseport_md->hash) drives a modulo into bpf_worker_socks; the selected
# socket is the worker that will see the accept(). Returning SK_PASS lets
# the kernel use that selection (or fall back to default 5-tuple if the slot
# happens to be empty during the initial registration race).
def sk_reuseport__select
  idx = reuseport_hash % 4
  worker_select(idx)
  SK_PASS
end

KEY_ROOT   = 1
KEY_HEALTH = 2
KEY_OTHER  = 3

def record_path_hit(key)
  path_counter_inc(key)
  0
end

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

# Each worker (including the original parent process) opens its OWN listen
# socket with SO_REUSEPORT, registers it in the bpf_worker_socks SOCKARRAY
# at its `my_idx` slot, and serves accept loops until killed. Worker 0 also
# attaches the sk_reuseport__select BPF program to the reuseport group —
# subsequent SYNs are then dispatched by hash(5-tuple) % WORKERS instead
# of the kernel default 5-tuple distribution.
def worker_loop(port, my_idx)
  listen_fd = Net.sp_net_listen(port, 1)
  if listen_fd < 0
    puts "[worker " + Net.sp_net_getpid.to_s + "] listen failed"
    exit(1)
  end
  ReuseportBpf.sp_bpf_reuseport_register(listen_fd, my_idx)
  # Opt-in BPF worker selection. Set SPINEL_HTTP_BPF_SELECT=1 to attach the
  # sk_reuseport__select program; default keeps the kernel's plain 5-tuple
  # distribution.
  if my_idx == 0 && (ENV["SPINEL_HTTP_BPF_SELECT"] || "0") != "0"
    rc = ReuseportBpf.sp_bpf_reuseport_attach(listen_fd, "sk_reuseport__select")
    if rc < 0
      puts "[worker 0] reuseport_attach failed rc=" + rc.to_s
    else
      puts "[worker 0] reuseport BPF prog attached on listen fd " + listen_fd.to_s
    end
  end
  puts "[worker " + my_idx.to_s + " pid=" + Net.sp_net_getpid.to_s + "] ready on 127.0.0.1:" + port.to_s

  loop do
    client = Net.sp_net_accept(listen_fd)
    if client < 0
      puts "[worker " + Net.sp_net_getpid.to_s + "] accept failed"
      break
    end
    line = Net.sp_net_read_line(client)
    req  = parse_request_line(line)
    drain_headers(client)
    record_path_hit(path_key(req.path))
    Net.sp_net_write_str(client, route(req))
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

puts "[main " + Net.sp_net_getpid.to_s + "] SO_REUSEPORT server starting " + workers.to_s + " worker(s) on port " + port.to_s

# Fork workers-1 children; parent process also serves as a worker so we end
# up with `workers` accept loops total. fork returns 0 in the child; the
# child immediately breaks out of the fork loop with its idx (i), and the
# parent stays as idx=0.
my_idx = 0
i = 1
while i < workers
  pid = Net.sp_net_fork
  if pid < 0
    puts "[main] fork failed"
    exit(1)
  end
  if pid == 0
    my_idx = i  # child: this is its idx in the worker sockarray
    break
  end
  i = i + 1
end

worker_loop(port, my_idx)
