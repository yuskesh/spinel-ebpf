# `xdp__tcp_slice__<name>` -- the pure-XDP TCP slice (the BUNDLE form).
#
# The body is a MARKER. The codegen recognises the name and replaces the whole
# method with the generated state machine (bpf_conntab + counters + csum/swap/
# build helpers + spnl_tcp_slice_main), leaving only a thin SEC("xdp") entry.
# Whatever is written below is discarded.
#
# This file was the NEGATIVE fixture (144_tcp_slice_withdrawn) while the attach
# kind stood withdrawn: the same source, refused. Reusing it rather than adding a
# new number means this golden can be compared straight against the retired Ruby
# generator's own output for the same input.
def xdp__tcp_slice__health
  XDP_PASS
end
