# Negative fixture: a literal slot outside the declared range.
#
# The unit declares ONE `def xdp_tail__<name>`, so the loader
# (_spnl_prog_array_populate) populates exactly slot 0. `tail_call_to(3)` names a
# slot that will never hold anything.
#
# This is refused because of HOW bpf_tail_call fails: it does not return an
# error, it does not abort the program, it simply does not jump -- the caller
# keeps running at the next instruction. So an out-of-range slot produces a probe
# that loads, attaches, fires, and always takes the fallback path, and there is
# no runtime signal that distinguishes that from a fallback the author intended.
# The literal case is decidable at compile time (the target count is known before
# any body is lowered), so it is decided there.
#
XDP_PASS = 2

@hits = 0

def xdp_tail__only_target
  @hits = @hits + 1
  XDP_PASS
end

def xdp__dispatcher
  tail_call_to(3)
  XDP_PASS
end
