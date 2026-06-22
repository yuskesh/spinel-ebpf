# ktime + latency + histogram integration fixture.
# kprobe stamps entry, kretprobe computes per-tid delta + bins it.

def kprobe__do_sys_openat2(dfd, filename)
  latency_start
end

def kretprobe__do_sys_openat2(ret)
  hist_observe(latency_end)
end
