# fentry/fexit attach demo.
#
# Counts inbound TCP packets at the `tcp_v4_rcv` kernel function. fentry
# fires on function entry (before any work); fexit fires on return and gets
# the function's return value as a trailing argument.
#
# fentry / fexit are BPF-trampoline-based — direct call (~50 ns) versus the
# trap-based kprobe (~1 μs). Wire format identical to the kprobe pattern.
#
# Build:
#   spinel-ebpf compile examples/observability/tcp_rcv_fentry.rb \
#       -o build/tcp_rcv_fentry --build
# Run:
#   ./build/tcp_rcv_fentry/tcp_rcv_fentry &
#   # generate some TCP traffic on the host, then:
#   bpftool map dump name tcp_rcv_fentry_top_  # the top-level ivar maps
#
# strace -e bpf the loader: zero data-plane syscalls during measurement,
# the same observability story kprobes provide.

@rx_entry = 0
@rx_exit_ok = 0
@rx_exit_err = 0

def fentry__tcp_v4_rcv(skb)
  @rx_entry = @rx_entry + 1
  spnl_emit(@rx_entry)
end

def fexit__tcp_v4_rcv(skb, ret)
  if ret == 0
    @rx_exit_ok = @rx_exit_ok + 1
  else
    @rx_exit_err = @rx_exit_err + 1
  end
end

puts "fentry/fexit attached to tcp_v4_rcv"
sleep 3600
