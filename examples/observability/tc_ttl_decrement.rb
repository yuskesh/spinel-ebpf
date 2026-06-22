# TC-egress IPv4 TTL decrement + checksum fix — the router fast-path,
# written in Ruby. This is the second family of typed-local-to-helper builtins
# (after fib_lookup): skb_load_byte / skb_store_byte each emit a typed __u8
# stack local and hand &local to bpf_skb_{load,store}_bytes, and l3_csum_replace
# incrementally repairs the IP header checksum.
#
# IPv4-over-Ethernet offsets: TTL byte = 14 (eth) + 8 = 22, IP checksum = 14 + 10 = 24.
#
# Verified with BPF_PROG_TEST_RUN because the build container's loopback doesn't
# deliver packets to XDP/TC hooks.
#
# Build:
#   spinel-ebpf compile examples/observability/tc_ttl_decrement.rb -o build/ttl --build
@seen        = 0
@decremented = 0

def tc__egress__ttl
  @seen = @seen + 1
  ttl = skb_load_byte(22)
  if ttl > 1
    new_ttl = ttl - 1
    l3_csum_replace(24, ttl << 8, new_ttl << 8)
    skb_store_byte(22, new_ttl)
    @decremented = @decremented + 1
  end
  TC_ACT_OK
end

puts "tc_ttl_decrement loaded (SPNL_TCX_IFACE=lo)"
sleep 3600
