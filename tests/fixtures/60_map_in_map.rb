# map-in-map (ARRAY_OF_MAPS). Buckets openat() into 4 inner ARRAY maps by
# tid%4; libbpf auto-populates the outer map with the inner maps at load time,
# so no host-side wiring is needed.
def kprobe__do_sys_openat2(dfd)
  g = tid() % 4
  mim_inc(g, 0)
end
