# Negative: ns_id with a key that is not a namespace.
#
# The key selects a kernel struct member at compile time, so it is a symbol
# literal and the accepted set is closed. A typo has to be loud: `ns_id(:mount)`
# silently returning 0 would read as "this task is in no mount namespace", which
# is not a thing, and would then compare unequal to every host check.
def kprobe__do_sys_openat2
  @n = ns_id(:mount)
end
