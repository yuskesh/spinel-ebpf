# Per-PID log2 latency histogram for do_sys_openat2.
#
# Like openat_latency_hist but keyed by PID — each process has its
# own 64-bucket log2 distribution stored in bpf_hist_keyed (HASH of
# `struct spnl_hist_struct { __u64 buckets[64]; }`).
#
# Inspect:
#   bpftool map dump name bpf_hist_keyed
#     (each key is a PID; value is a 64-element __u64 array)

def kprobe__do_sys_openat2(dfd, filename)
  latency_start
end

def kretprobe__do_sys_openat2(ret)
  hist_observe_by(pid, latency_end)
end

puts "openat_per_pid_hist loaded — exercise then dump bpf_hist_keyed"
sleep 3600
