# sock_*(sk) -- read a `struct sock *` by name, in host byte order.
#
# kfield can already reach every one of these fields, and reading skc_dport with
# it is an established pattern. What kfield cannot do is know which fields need a
# byte swap, because struct sock_common mixes byte orders WITHIN ONE STRUCT:
#
#   skc_dport  __be16   network order   -> the accessor swaps
#   skc_num    __u16    host order      -> the accessor does not
#
# Measured on one connection to 127.0.0.1:8123: the raw reads are dport=47903 /
# sport=60404, and the uniformly-swapped reads are 8123 / 62699. All four look
# like port numbers, so either uniform rule the author might write is silently
# wrong for one of the two ports. That is why the conversion lives in the
# accessor and every value below is host order.
#
# The pointer is UNTRUSTED here (a kprobe argument), so these go through
# BPF_CORE_READ. The direct deref that tcp_sock_* uses for the trusted
# struct_ops sk does not even load in this context.
@conns = 0
@v6 = 0

# tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
def kprobe__tcp_sendmsg(sk)
  # A port RANGE is just Ruby, because the value is already host order.
  if sock_protocol(sk) == IPPROTO_TCP && sock_state(sk) == TCP_STATE_ESTABLISHED
    if sock_dport(sk) >= 8100 && sock_dport(sk) <= 8199
      @conns = @conns + 1
      spnl_emit4(sock_dport(sk), sock_sport(sk), sock_daddr(sk), sock_family(sk))
      if sock_family(sk) == AF_INET6
        @v6 = @v6 + 1
        spnl_emit_pair(sock_daddr6_hi(sk), sock_daddr6_lo(sk))
      end
    end
  end
end
