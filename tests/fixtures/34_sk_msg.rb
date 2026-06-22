# Minimum sk_msg / sk_skb demo.
#
# Two attach families:
#   - sk_msg__<name>            -> SEC("sk_msg"),               ctx = struct sk_msg_md *
#   - sk_skb__verdict__<name>   -> SEC("sk_skb/stream_verdict"), ctx = struct __sk_buff *
#   - sk_skb__parser__<name>    -> SEC("sk_skb/stream_parser"),  ctx = struct __sk_buff *
#
# Bodies must return SK_PASS / SK_DROP (kernel enum: SK_DROP=0, SK_PASS=1).
# Attach for these program types requires bpf_prog_attach() against a
# BPF_MAP_TYPE_SOCKMAP/SOCKHASH map fd — deferred to the fast-path response
# demo that wires everything together. This fixture only validates
# that the codegen pattern produces verifier-loadable programs.

SK_PASS = 1
SK_DROP = 0

@msg_count = 0
@skb_count = 0

def sk_msg__pass_all
  @msg_count = @msg_count + 1
  SK_PASS
end

def sk_skb__verdict__pass_all
  @skb_count = @skb_count + 1
  SK_PASS
end

puts "[demo] sk_msg + sk_skb programs loaded (attach happens separately)"
sleep 5
