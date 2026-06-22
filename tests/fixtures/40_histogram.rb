# log2 histogram smoke fixture.
# A kprobe handler observing the arg as a log2-bucketed sample.
# Combined with a kretprobe to measure latency would be more realistic
# but this is enough to exercise the codegen.

def kprobe__do_sys_openat2(dfd, filename)
  hist_observe(dfd)
end
