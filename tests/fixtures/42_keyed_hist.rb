# hist_observe_by(key, value) per-key log2 hist fixture.
# Bins openat latency by PID (per-process latency hist).

def kprobe__do_sys_openat2(dfd, filename)
  latency_start
end

def kretprobe__do_sys_openat2(ret)
  hist_observe_by(pid, latency_end)
end
