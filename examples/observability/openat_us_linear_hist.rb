# Linear (caller-bucketed) histogram for do_sys_openat2 latency,
# binned in 1-microsecond slots.
#
# `hist_observe_linear(slot)` writes to bpf_hist_lin[slot] — caller is
# responsible for computing the slot index (here: ns / 1000 = us).
# 256 slots, OOB values clamp to slot 255 (i.e. all ≥256 µs lump together).
#
# Inspect:
#   bpftool map dump name bpf_hist_lin

def kprobe__do_sys_openat2(dfd, filename)
  latency_start
end

def kretprobe__do_sys_openat2(ret)
  # Slot ≈ µs (latency_end is ns, >> 10 ≈ /1024, close enough for log-ish
  # bucketing). Use unsigned division builtin once we have one; for now
  # ARSH on positive values is exact.
  hist_observe_linear(latency_end >> 10)
end

puts "openat_us_linear_hist loaded — exercise then dump bpf_hist_lin"
sleep 3600
