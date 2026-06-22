# Dynamic blocklist.
#
# A TC ingress filter consults a BPF HASH map (`bpf_blocklist`) — userspace can
# add/remove IPs to control which sources get TC_ACT_SHOT in real time. This
# building block (HASH map populated by host, queried in kernel) is the
# pattern used by Cilium / Cloudflare for DDoS edge rules.
#
# Demo timeline:
#   t=0   start, blocklist empty                  → curl 127.0.0.1 ok
#   t=4   sp_bpf_blocklist_add(0x7f000001)        → curl blocked
#   t=8   sp_bpf_blocklist_del(0x7f000001)        → curl ok again
#   t=12  exit (destructor releases TC link)

TC_ACT_OK    = 0
TC_ACT_SHOT  = 2
LOCALHOST_BE = 0x7f000001    # 127.0.0.1 in host order (matches pkt_ip4_src)

@blocked_hits = 0
@passed_hits  = 0

def tc__ingress__blocklist_filter
  if blocklist_match(pkt_ip4_src) == 1
    @blocked_hits = @blocked_hits + 1
    TC_ACT_SHOT
  else
    @passed_hits = @passed_hits + 1
    TC_ACT_OK
  end
end

module Blocklist
  ffi_func :sp_bpf_blocklist_add, [:uint32], :int
  ffi_func :sp_bpf_blocklist_del, [:uint32], :int
end

puts "[demo] t=0  TC filter attached, blocklist empty (curl ok)"
sleep 4
puts "[demo] t=4  adding 127.0.0.1 to blocklist (curl will be blocked)"
Blocklist.sp_bpf_blocklist_add(LOCALHOST_BE)
sleep 4
puts "[demo] t=8  removing 127.0.0.1 from blocklist (curl ok again)"
Blocklist.sp_bpf_blocklist_del(LOCALHOST_BE)
sleep 4
puts "[demo] t=12 exiting; TC link released at destructor"
