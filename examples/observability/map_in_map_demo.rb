# map-in-map (ARRAY_OF_MAPS). Buckets openat() into 4 inner maps by tid%4.
# libbpf auto-populates the outer with the inner maps at load time.
# Dump bpf_mim_inner0..3 to see the per-bucket counts.
def kprobe__do_sys_openat2(dfd)
  g = tid() % 4
  mim_inc(g, 0)
end
puts "map-in-map openat buckets attached"
sleep 3600
