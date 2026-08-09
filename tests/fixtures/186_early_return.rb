# an earlier experiment: early `return` in statement position.
#
# The shape an author writes first when the probe is a DECISION rather than a
# measurement. Until an earlier experiment this died with `node type not yet ported (Stage 1):
# ReturnNode` -- a prism class name and no way forward -- even though the
# machinery was already there: the handler body lowers into an `_inner` whose
# return type is the method's, and the wrapper propagates it.
#
# Both arms are here on purpose: the early return AND a value after the `if`, so
# the golden shows the two exits of the same function.
def kprobe__do_sys_openat2(a)
  if a > 100
    return 1
  end
  if a > 10
    @big += 1
    return 2
  end
  @small += 1
  0
end
