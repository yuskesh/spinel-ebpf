# hist_observe_linear(slot) caller-bucketed hist fixture.
# Bins openat latency in microseconds (linear, slot = us value).

def kprobe__do_sys_openat2(dfd, filename)
  latency_start
end

def kretprobe__do_sys_openat2(ret)
  hist_observe_linear(latency_end >> 10)
end
