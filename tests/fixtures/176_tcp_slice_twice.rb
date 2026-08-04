# Negative fixture: two pure-XDP TCP slices in one unit.
#
# The generated machine has FIXED symbol names (bpf_conntab, bpf_ts_counters,
# spnl_tcp_slice_main, ...) and is hardcoded to port 8080 and "GET /health ", so
# a second `xdp__tcp_slice__` would be the same program under a second name --
# two SEC("xdp") entries the loader attaches to the same interface, the second
# of which replaces the first.
#
# Refused rather than emitted, because the emitted C would not even compile
# (duplicate definitions) and that message names a C identifier, not the second
# `def`. The same shape as "two USER_RINGBUF callbacks".
def xdp__tcp_slice__health
  XDP_PASS
end

def xdp__tcp_slice__ping
  XDP_PASS
end
