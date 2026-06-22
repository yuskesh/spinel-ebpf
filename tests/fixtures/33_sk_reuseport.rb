# Minimum SO_REUSEPORT BPF demo.
#
# `sk_reuseport__<name>` lowers to `SEC("sk_reuseport") int <name>(struct
# sk_reuseport_md *ctx)`. Body must return SK_PASS (use the default kernel
# selection, i.e. the first socket in the reuseport group) or SK_DROP.
#
# Attach is application-specific: setsockopt(listen_fd, SOL_SOCKET,
#   SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd))
# after creating the listen socket. That wiring happens in the multi-worker
# spinel HTTP server. This fixture only validates that the codegen pattern
# produces a verifier-loadable program — libbpf's auto-attach harmlessly
# skips SK_REUSEPORT programs.

SK_PASS = 0

@pass_count = 0

def sk_reuseport__pass_all
  @pass_count = @pass_count + 1
  SK_PASS
end

puts "[demo] sk_reuseport program loaded (attach happens separately)"
sleep 5
