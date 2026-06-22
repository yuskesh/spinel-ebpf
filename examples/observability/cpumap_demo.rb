# CPUMAP + bpf_redirect_map for XDP per-CPU fanout.
#
# Redirects every packet to CPU 0 via `spnl_cpumap[0]`. On multi-queue
# NICs this lets the entry XDP run on the queue's IRQ CPU but heavy
# packet processing happens on a dedicated CPU's NAPI ring. Apple
# container's virtio-net is queue=1 so the fanout has nothing to fan to,
# but the BPF program loads and verifies — the same code will scale on a
# multi-queue host (real NIC or vhost-net with `queues=N`).
#
# Build:
#   spinel-ebpf compile examples/observability/cpumap_demo.rb \
#       -o build/cpumap_demo --build
# Populate slot 0 with qsize=192 and run:
#   bpftool map update name spnl_cpumap key 0 0 0 0 \
#       value c0 0 0 0 0 0 0 0
#   # = bpf_cpumap_val { .qsize = 192, .bpf_prog.fd = 0 }
#   SPNL_XDP_IFACE=lo ./build/cpumap_demo/cpumap_demo &
#   ping -c 5 127.0.0.1

@redirected = 0
@passed     = 0

def xdp__fanout
  # Try to push to CPU 0. cpumap_redirect returns XDP::REDIRECT on
  # success, XDP::ABORTED or similar on failure. We just use the
  # result as the return value of the XDP program.
  r = cpumap_redirect(0)
  if r == XDP::REDIRECT
    @redirected = @redirected + 1
    r
  else
    @passed = @passed + 1
    XDP::PASS
  end
end

puts "CPUMAP demo loaded. Populate spnl_cpumap slot 0 (qsize=192) to enable redirect."
sleep 3600
