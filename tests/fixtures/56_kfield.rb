# arbitrary kernel struct field access via kfield / kptr (BPF_CORE_READ).
#
# Reads scalar fields of a `struct sock *` kprobe argument. Works on an
# untrusted kprobe pointer because BPF_CORE_READ lowers to
# bpf_probe_read_kernel + CO-RE relocation (BTF-driven), unlike the existing
# tcp_sock direct-deref accessor which only works in trusted struct_ops context.
@calls = 0
@sndbuf = 0
@rcvbuf = 0

# tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
def kprobe__tcp_sendmsg(sk)
  @calls = @calls + 1
  # (A) explicit kfield builtin
  @sndbuf = kfield(sk, "sock", "sk_sndbuf")
  # (B) kptr typed handle + dot-accessor sugar over kfield
  s = kptr(sk, "sock")
  @rcvbuf = s.sk_rcvbuf
end
