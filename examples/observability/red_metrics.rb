# RED metrics collected via eBPF and exposed on a Prometheus /metrics endpoint.
#
# Kernel side (eBPF): measure do_sys_openat2 latency with kprobe/kretprobe and
#   push it into the ringbuf via spnl_emit_pair(svc, latency_ns).
# Userspace (Ruby): aggregate RED with on_emit_pair. The consumer's ringbuf epoll
#   fd is placed on the same epoll as the listen fd and drained whenever an event
#   arrives (no waiting for a scrape, so no overflow).
#   Graceful shutdown works because sp_net_epoll_wait_one returns -1 on SIGINT/TERM.
#
# build: bin/spinel-ebpf compile examples/observability/red_metrics.rb --build -o build
# run:   SPINEL_HTTP_PORT=9100 ./build/red_metrics &
#        curl -s localhost:9100/metrics
use_plugin :ebpf

module Net
  ffi_func :sp_net_listen,         [:int, :int], :int
  ffi_func :sp_net_accept,         [:int],       :int
  ffi_func :sp_net_read_line,      [:int],       :str
  ffi_func :sp_net_write_str,      [:int, :str], :int
  ffi_func :sp_net_rl_close,       [:int],       :int
  ffi_func :sp_net_epoll_create,   [],           :int
  ffi_func :sp_net_epoll_add,      [:int, :int], :int
  ffi_func :sp_net_epoll_wait_one, [:int],       :int
  ffi_func :sp_net_install_term_handlers, [],    :int   # SIGINT/TERM -> shutdown flag
end

module Consumer
  ffi_func :spnl_consumer_epoll_fd, [], :int   # ringbuf epoll fd to multiplex
end

@count  = 0
@sum_ns = 0
@max_ns = 0

# --- kernel: openat latency -> ringbuf (svc=0, dur_ns) ---
def kprobe__do_sys_openat2
  latency_start
end

def kretprobe__do_sys_openat2(ret)
  spnl_emit_pair(0, latency_end)
end

# --- userspace: RED aggregation (per event, full Ruby) ---
on_emit_pair do |svc, dur_ns|
  @count  = @count + 1
  @sum_ns = @sum_ns + dur_ns
  @max_ns = dur_ns if dur_ns > @max_ns
end

def metrics_body
  "# HELP spnl_openat_total openat calls observed via eBPF.\n" +
  "# TYPE spnl_openat_total counter\n" +
  "spnl_openat_total " + @count.to_s + "\n" +
  "# HELP spnl_openat_latency_ns_sum sum of openat latencies (ns).\n" +
  "# TYPE spnl_openat_latency_ns_sum counter\n" +
  "spnl_openat_latency_ns_sum " + @sum_ns.to_s + "\n" +
  "spnl_openat_latency_ns_max " + @max_ns.to_s + "\n"
end

port = (ENV["SPINEL_HTTP_PORT"] || "9100").to_i
listen_fd = Net.sp_net_listen(port, 0)
if listen_fd < 0
  puts "[red] listen failed"
  exit(1)
end

Net.sp_net_install_term_handlers          # SIGINT/TERM -> graceful loop exit
ep  = Net.sp_net_epoll_create
Net.sp_net_epoll_add(ep, listen_fd)
rfd = Consumer.spnl_consumer_epoll_fd
Net.sp_net_epoll_add(ep, rfd)
puts "[red] /metrics on 127.0.0.1:" + port.to_s + " (epoll mux listen=" + listen_fd.to_s + " ring=" + rfd.to_s + ")"

loop do
  fd = Net.sp_net_epoll_wait_one(ep)
  break if fd < 0                       # SIGINT/TERM -> graceful shutdown
  if fd == rfd
    consume_events(0)                   # drain ready ringbuf records -> RED (continuous)
  else
    client = Net.sp_net_accept(listen_fd)
    if client >= 0
      Net.sp_net_read_line(client)      # request line (this demo serves /metrics for any path)
      loop do
        line = Net.sp_net_read_line(client)
        break if line.length == 0
      end
      body = metrics_body
      resp = "HTTP/1.0 200 OK\r\n" +
             "Content-Type: text/plain; version=0.0.4\r\n" +
             "Content-Length: " + body.length.to_s + "\r\n" +
             "Connection: close\r\n\r\n" + body
      Net.sp_net_write_str(client, resp)
      Net.sp_net_rl_close(client)
    end
  end
end
puts "[red] shutdown"
