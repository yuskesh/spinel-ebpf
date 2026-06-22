# Real-latency histogram of do_sys_openat2 in ns.
#
# kprobe stamps the per-tid entry time via latency_start (writes
# bpf_lat_starts[tid] = ktime_ns). kretprobe reads + deletes it via
# latency_end which returns the ns delta, then hist_observe bins it.
#
# The per-tid map handles concurrent openat across threads without race
# (sys_enter and sys_exit alternate within a single thread).
#
# Build:
#   bin/spinel-ebpf compile examples/observability/openat_latency_hist.rb \
#                   -o build/openat_lat --build
#
# Run:
#   ./build/openat_lat/openat_latency_hist &
#   # exercise (varied I/O patterns):
#   for i in $(seq 1 1000); do cat /etc/hostname > /dev/null; done
#   # tail latencies:
#   bpftool map dump name bpf_hist
#   # bcc-style ASCII art via the host runtime:
#   # (call spnl_runtime_print_log2_hist from your host code)
#
# The slot distribution shows nanosecond-scale latencies:
#   slot 6  =        64..127 ns
#   slot 7  =       128..255 ns
#   slot 8  =       256..511 ns
#   slot 9  =       512..1023 ns
#   slot 10 =      1024..2047 ns (≈1µs)
#   slot 20 = 1048576..2097151 ns (≈1ms)

def kprobe__do_sys_openat2(dfd, filename)
  latency_start
end

def kretprobe__do_sys_openat2(ret)
  hist_observe(latency_end)
end

puts "openat_latency_hist loaded — exercise with file opens then dump bpf_hist"
sleep 3600
