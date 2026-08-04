# Negative fixture: `xdp_tail__<name>` is a WITHDRAWN attach kind.
#
# It used to compile with exit 0 into a plain SEC("syscall") wrapper -- not an
# XDP program, not a tail-call target, attached to nothing. The codegen must
# refuse it: the PROG_ARRAY it would be jumped through, and `tail_call_to` (the
# jump), did not survive the port to the C codegen, and the builtin has since
# been withdrawn. A silent no-op is the failure mode this project forbids.
@hits = 0

def xdp_tail__tcp_handler
  @hits = @hits + 1
  XDP_PASS
end
