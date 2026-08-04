# cpumap_redirect(cpu) -- the third member of the bpf_redirect_map family.
#
# xsk_redirect / dev_redirect survived the port to the C codegen (they are pinned
# by 64_xsk_dev_redirect.rb); cpumap_redirect did not, and nothing said so
# because no fixture called it. The three are the same shape -- one map, one
# index -- so the hole was invisible to a text-diff gate and visible only to
# someone who tried to use it.
#
# The CPUMAP entry holds `struct bpf_cpumap_val { __u32 qsize; __u32 prog_id; }`;
# userspace fills the slots (bpftool / libbpf) and the kernel enqueues the frame
# on the target CPU's NAPI ring. bpf_redirect_map returns XDP_REDIRECT on success
# and the flags argument (0 = XDP_ABORTED) when the slot is empty.
XDP_ABORTED  = 0
XDP_DROP     = 1
XDP_PASS     = 2
XDP_TX       = 3
XDP_REDIRECT = 4

@rx = 0

def xdp__fanout
  @rx = @rx + 1
  cpumap_redirect(pkt_l4_sport % 4)
end
