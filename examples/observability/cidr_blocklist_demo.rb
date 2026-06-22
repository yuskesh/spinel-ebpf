# CIDR blocklist via LPM_TRIE.
#
# Blocks the whole 127.0.0.0/8 loopback subnet, demonstrating longest-prefix
# matching: a packet from 127.0.0.1 matches the /8 entry and is dropped by the
# TC ingress filter. This is the CIDR generalisation of the exact-IP HASH blocklist.
#
# Run:  SPNL_TCX_IFACE=lo ./cidr_blocklist_demo &
#       curl --max-time 2 http://127.0.0.1   # blocked while /8 is in the trie
#       bpftool map dump name <truncated cidr_blocklist_demo @blocked_hits map>
TC_ACT_OK   = 0
TC_ACT_SHOT = 2

@blocked_hits = 0
@passed_hits  = 0

def tc__ingress__cidr_filter
  if cidr_blocklist_match(pkt_ip4_src) == 1
    @blocked_hits = @blocked_hits + 1
    TC_ACT_SHOT
  else
    @passed_hits = @passed_hits + 1
    TC_ACT_OK
  end
end

module CidrBlocklist
  ffi_func :sp_bpf_cidr_blocklist_add, [:uint32, :uint32], :int
  ffi_func :sp_bpf_cidr_blocklist_del, [:uint32, :uint32], :int
end

CidrBlocklist.sp_bpf_cidr_blocklist_add(0x7f000000, 8)   # 127.0.0.0/8
puts "127.0.0.0/8 blocked via LPM_TRIE; TC ingress active"
sleep 3600
