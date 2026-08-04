# Negative fixture: a TCP-slice builtin outside XDP.
#
# The seven builtins rewrite and RESIZE the raw frame through `struct xdp_md`
# (bpf_xdp_adjust_tail). A TC classifier holds an skb; neither the resize nor the
# raw pointers exist there, and the two syncookie ones bottom out in kfuncs whose
# first parameter is an XDP packet pointer.
#
# Without the gate this is a clang error two layers down about a `struct
# __sk_buff` having no `data_end` of the right type, or an unresolved kfunc --
# neither of which names the hook the author chose.
#
# tc__ingress__ rather than a kprobe on purpose: it is the context most likely to
# be tried, because pkt.* readers DO work there.
TC_ACT_OK = 0

def tc__ingress__filter
  if payload_starts("GET /health ")
    TC_ACT_OK
  else
    TC_ACT_OK
  end
end
