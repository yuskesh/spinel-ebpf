# Negative fixture: `on :timer` with no `every:`.
#
# The interval is folded into bpf_timer_start at compile time, so a timer without
# one has nothing to arm. The audit measured what silence costs here: before the
# kind was ported, the whole block vanished from the emitted C and the probe
# still exited 0. Refusing is the same claim in the other direction -- a timer
# that cannot fire must not compile.
@ticks = 0

module NoInterval
  include BPF::EventLoop

  on :timer do
    @ticks = @ticks + 1
  end
end
