# Reactor DSL "everything-included" demo. A single module handles 6 kinds of
# event source at once, aggregates counters / state into shared ivars, and runs
# a periodic dump with bpf_timer. A kernel-side observability suite that reads
# like a Sinatra app.
#
# Layout:
#   - on :xdp                          - NIC ingress packet (+ user_ringbuf drain)
#   - on :sock_ops                     - cgroup-scoped TCP state transitions
#   - on :kprobe, "do_sys_openat2"     - file open syscall
#   - on :tracepoint, "sched", "..."   - context switch
#   - on :user_cmd do |cmd|            - libbpf push from userspace
#   - on :timer, every: 1.seconds      - kernel-side periodic
#
# Build:
#   spinel-ebpf compile examples/observability/full_observability_demo.rb \
#       -o build/full_observability --build
#
# Run:
#   mount -t tracefs nodev /sys/kernel/tracing            # once, if needed
#   SPNL_XDP_IFACE=lo SPNL_CGROUP_PATH=/sys/fs/cgroup \
#     ./build/full_observability/full_observability_demo &
#
#   # Fire each event source:
#   ping -c 5 -q 127.0.0.1                # -> xdp + sock_ops + kprobe + sched
#   ls /etc /tmp /usr >/dev/null          # -> kprobe (open)
#   /tmp/push_one $(bpftool map list | awk '/bpf_user_cmds/{sub(":","",$1);print $1}') 42
#                                          # -> user_cmd
#   sleep 3                                # -> timer (~3 ticks)
#
#   # Check all counters:
#   for n in rx_total tcp_connects open_count ctx_switches \
#            cmds_received last_cmd ticks; do
#     printf "%-15s = " "$n"
#     bpftool map dump name "full_observabili_top_$n" \
#       | grep -oE 'value":\s*[0-9]+' | head -1
#   done

@rx_total      = 0
@tcp_connects  = 0
@open_count    = 0
@ctx_switches  = 0
@cmds_received = 0
@last_cmd      = 0
@ticks         = 0

module FullObservability
  include BPF::EventLoop

  # NOTE: write `on :user_cmd` above `on :xdp`. The XDP handler needs the
  # callback name when it calls user_ringbuf_drain, so in the partition's
  # enumeration order (= source order) the callback must be defined first.
  # A future codegen improvement (pre-scan) would make the order arbitrary.

  # -- source 1: userspace control channel (libbpf user_ringbuf push)
  on :user_cmd do |cmd|
    @cmds_received = @cmds_received + 1
    @last_cmd = cmd
  end

  # -- source 2: NIC packet (XDP hook)
  # side effect: drain user_ringbuf to pump on :user_cmd
  on :xdp do
    @rx_total = @rx_total + 1
    user_ringbuf_drain
    XDP::PASS
  end

  # -- source 3: TCP state transitions (cgroup-scoped SOCK_OPS)
  on :sock_ops do
    if sock_ops_op == BPF::SockOps::TCP_CONNECT_CB
      @tcp_connects = @tcp_connects + 1
    end
  end

  # -- source 4: kprobe — file open syscall
  on :kprobe, "do_sys_openat2" do
    @open_count = @open_count + 1
  end

  # -- source 5: tracepoint — context switch
  on :tracepoint, "sched", "sched_switch" do
    @ctx_switches = @ctx_switches + 1
  end

  # -- source 6: time axis (bpf_timer, kernel-side periodic)
  on :timer, every: 1.seconds do
    @ticks = @ticks + 1
  end
end

puts "FullObservability loaded — 6 event sources active in 1 module"
puts " trigger each source then `bpftool map dump name full_observabili_top_*`"
sleep 3600
