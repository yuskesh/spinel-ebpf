# funclatency — latency histogram of a kernel function (bcc funclatency equivalent).
#
# Times do_sys_openat2 (the openat/openat2 syscall path) and prints a log2
# histogram of the call latency in nanoseconds, bcc-style. Change the two method
# names to time any other function with a matching kprobe/kretprobe.
#
#   bin/spinel-ebpf compile tools/funclatency.rb --build -o build/funclatency
#   ./build/funclatency/funclatency &     # samples for 5s, then prints
#   for i in $(seq 1 2000); do cat /etc/hostname >/dev/null; done
module Hist
  ffi_func :spnl_dump_log2_hist, [:str, :str], :int
end

def kprobe__do_sys_openat2(dfd)
  latency_start
end

def kretprobe__do_sys_openat2(ret)
  hist_observe(latency_end)
end

puts "[funclatency] timing do_sys_openat2 for 5s..."
sleep 5
Hist.spnl_dump_log2_hist("bpf_hist", "do_sys_openat2 latency (ns)")
