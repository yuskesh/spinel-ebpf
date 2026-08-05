# Read arbitrary kernel struct fields from a kprobe.
#
# `tcp_sendmsg(struct sock *sk, ...)` gives an untrusted `sk` pointer. kfield /
# kptr lower to BPF_CORE_READ (bpf_probe_read_kernel + CO-RE, BTF-driven), so
# reading sk->sk_sndbuf / sk->sk_rcvbuf is verifier-safe — a direct deref would
# be rejected outside trusted (struct_ops / fentry / lsm) contexts.
#
# Run it, make any TCP connection (e.g. `curl deb.debian.org`), then observe the
# last values read straight from the kernel:
#   # The kernel keeps only the first 15 characters of a map name, so these
#   # two both appear as `u_kfield_demo_t` and cannot be told apart by name.
#   # Look them up by id instead:
#   bpftool map show | grep u_kfield_demo_t
#   bpftool map dump id <the id printed above>
@calls = 0
@last_sndbuf = 0
@last_rcvbuf = 0

def kprobe__tcp_sendmsg(sk)
  @calls = @calls + 1
  # (A) explicit kfield builtin
  @last_sndbuf = kfield(sk, "sock", "sk_sndbuf")
  # (B) kptr typed handle + dot-accessor sugar
  s = kptr(sk, "sock")
  @last_rcvbuf = s.sk_rcvbuf
end

puts "kfield_demo loaded — kprobe tcp_sendmsg reading sk_sndbuf/sk_rcvbuf"
sleep 3600
