# pkt_dynptr_byte_at — verifier-safe byte access into an XDP frame.
#
# This counts how many packets have byte 0x45 at offset 14 (the IPv4
# version/IHL byte of a standard 20-byte IP header). Equivalent to "count
# IPv4 packets" but the access goes through bpf_dynptr_slice so the verifier
# bounds-checks it without any manual `data + N > data_end` in the codegen
# (or the Ruby).
#
# Build:
#   spinel-ebpf compile examples/observability/xdp_dynptr_demo.rb \
#       -o build/xdp_dynptr_demo --build
# Run:
#   SPNL_XDP_IFACE=lo ./build/xdp_dynptr_demo/xdp_dynptr_demo &
#   ping -c 5 -q 127.0.0.1
#   bpftool map dump name xdp_dynptr_dem_top_ipv4_pkts

@ipv4_pkts = 0
@other_pkts = 0

def xdp__dynptr_demo
  # IPv4 header at offset 14 (after 14-byte Ethernet). The very first byte
  # is `version:4 | ihl:4` — for a vanilla IPv4 header that's 0x45.
  b = pkt.byte_at(14)
  if b == 0x45
    @ipv4_pkts = @ipv4_pkts + 1
  else
    @other_pkts = @other_pkts + 1
  end
  XDP::PASS
end

puts "dynptr demo attached"
sleep 3600
