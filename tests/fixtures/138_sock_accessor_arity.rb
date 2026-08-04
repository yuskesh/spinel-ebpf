# Negative: a sock_* accessor called with no pointer.
#
# These are flat calls that take the `struct sock *` explicitly -- the argument
# is not optional and there is no implicit receiver, so dropping it has to fail
# loudly rather than pick some `sk` out of scope.
def kprobe__tcp_sendmsg(sk)
  @dport = sock_dport
end
