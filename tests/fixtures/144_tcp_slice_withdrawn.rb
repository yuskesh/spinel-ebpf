# Negative fixture: `xdp__tcp_slice__<name>` is a WITHDRAWN attach kind.
#
# The body is a marker: the codegen was supposed to recognise the name and
# generate the whole pure-XDP TCP state machine. It does not -- and because the
# name starts with the IMPLEMENTED prefix `xdp__`, a prefix scan of the codegen
# answers "present". That is the false negative: the marker body became the
# entire program, wrapped in SEC("syscall").
def xdp__tcp_slice__health
  XDP_PASS
end
