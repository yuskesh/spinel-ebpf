# Negative fixture: tail_call_to from a kprobe.
#
# A tail call transfers control to another program of the CALLER'S OWN TYPE, and
# `spnl_prog_array` only ever holds this unit's `def xdp_tail__<name>` -- XDP
# programs. From a kprobe the jump can never land: the slots hold the wrong
# program type, so the verifier would reject the transfer at run time by simply
# not taking it, i.e. the probe would keep running and nothing would say why.
#
# Refused by the context gate, at the layer that still knows the author wrote
# `def kprobe__...`, rather than left to a downstream message about an undeclared
# `ctx` -- which is literally what happens without the gate, since a kprobe inner
# has no ctx parameter at all.
@hits = 0

def kprobe__do_sys_openat2
  @hits = @hits + 1
  tail_call_to(0)
  0
end
