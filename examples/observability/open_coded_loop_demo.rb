# Open-coded iterator. When `n.times` has n as a compile-time
# integer literal, the codegen lowers the loop to a `bpf_iter_num_*`
# kfunc sequence INLINE in the calling function — no callback, no
# capture struct, no BPF-to-BPF call.
#
# This counts kprobe firings of openat and uses a 3-iteration inline
# loop to emit three multiples of the counter on each fire.
#
# Build:
#   spinel-ebpf compile examples/observability/open_coded_loop_demo.rb \
#       -o build/open_coded_loop_demo --build
# Run:
#   ./build/open_coded_loop_demo/open_coded_loop_demo &
#   ls /etc/  # triggers openat
#   bpftool map dump name open_coded_loop_top_total

@total = 0

def kprobe__do_sys_openat2
  3.times do |i|
    @total = @total + i
    spnl_emit(@total)
  end
end

puts "open-coded loop demo: 3.times runs inline (no bpf_loop callback)"
sleep 3600
