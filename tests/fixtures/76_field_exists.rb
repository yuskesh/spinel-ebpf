# field_exists -> bpf_core_field_exists, a
# load-time CO-RE check of whether a struct field is present in the running
# kernel's BTF (1) or not (0).
@snd = 0
def kprobe__tcp_sendmsg(sk)
  @snd = field_exists(sk, "sock", "sk_sndbuf")
  0
end
