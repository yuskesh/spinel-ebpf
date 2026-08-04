# Negative fixture: payload_starts with something that is not a string literal.
#
# The prefix is UNROLLED into one compare per byte at compile time -- that is
# what makes the matcher verifier-cheap (no loop, no bounded read). Anything that
# is not a literal has no bytes at compile time, so there is nothing to unroll.
#
# Refused with the reason rather than accepted-and-degraded: the alternatives
# were to compare zero bytes (a matcher that is always true) or to emit a bounded
# loop (a different, much more expensive thing than what was asked for). Both are
# the "loads and does the wrong thing quietly" class this generator forbids.
#
# The argument here is an integer rather than a string-valued local because a
# string local dies EARLIER, in the generic lowering ("node type not yet ported:
# StringNode") -- a true message about a different subject. A negative fixture
# has to reach the check it is about, so this one hands over something the
# lowering is perfectly happy to carry.
#
# tcp_reply_data's payload literal is refused the same way and for the same
# reason: its length fixes every size in the generated header.
XDP_PASS = 2
XDP_DROP = 1

def xdp__slice(prefix_code)
  if payload_starts(prefix_code)
    XDP_DROP
  else
    XDP_PASS
  end
end
