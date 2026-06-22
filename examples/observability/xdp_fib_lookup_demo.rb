# Kernel FIB (routing table) lookup from XDP.
#
# This is the first spinel-ebpf builtin that needs a *typed local*: fib_lookup
# emits a `struct bpf_fib_lookup` stack local, fills it, and hands &local to the
# bpf_fib_lookup helper — which the verifier tracks as PTR_TO_STACK across the
# call. (The earlier kfield/kptr pattern only round-tripped a pointer *value*
# through an __s64 slot; it never passed a typed local to a helper.)
#
# fib_lookup(dst_ip) returns the egress ifindex for a routable IPv4 destination
# (host byte order, like pkt_ip4_dst), or -1 when there is no route.
#
# Build:
#   spinel-ebpf compile examples/observability/xdp_fib_lookup_demo.rb \
#       -o build/xdp_fib --build
# Run:
#   SPNL_XDP_IFACE=lo ./build/xdp_fib/xdp_fib_lookup_demo &
#   ping -c 5 -q 127.0.0.1

@rx       = 0
@routed   = 0
@noroute  = 0
@last_oif = 0

def xdp__main
  @rx = @rx + 1
  dst = pkt_ip4_dst
  if dst != 0
    oif = fib_lookup(dst)
    if oif >= 0
      @routed = @routed + 1
      @last_oif = oif
    else
      @noroute = @noroute + 1
    end
  end
  XDP_PASS
end

puts "xdp_fib_lookup_demo loaded (SPNL_XDP_IFACE=lo)"
sleep 3600
