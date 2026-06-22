# IPv6 route lookup from TC. fib_lookup6(dst_hi, dst_lo) is the IPv6
# counterpart of fib_lookup: it fills the network-order ipv6_dst[4] from
# the host-order high/low 64 bits and asks the kernel FIB for the egress ifindex.
# Here we look up ::1 (loopback): hi=0, lo=1.
#
# Build: spinel-ebpf compile examples/observability/tc_fib6.rb -o build/f6 --build
@oif = 0

def tc__ingress__r6
  @oif = fib_lookup6(0, 1)    # route to ::1
  TC_ACT_OK
end

puts "tc_fib6 loaded"
sleep 3600
