# CIDR blocklist (LPM_TRIE) TC ingress filter. Drops sources matching any
# blocked prefix; userspace inserts prefixes via the CidrBlocklist FFI and the
# kernel does longest-prefix matching — the CIDR generalisation of the
# exact-IP HASH blocklist.
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
