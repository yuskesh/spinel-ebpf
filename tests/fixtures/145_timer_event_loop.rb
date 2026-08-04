# `on :timer, every: N.<unit>` -- a bpf_timer-backed periodic callback.
#
# This was the NEGATIVE fixture (145_timer_withdrawn) while the kind stood
# withdrawn. Same source, different verdict, and that is the point: the audit
# measured this compiling with exit 0 into a program whose HANDLER BODY never
# reached the emitted C (the C reactor table had no :timer, and an unknown kind
# is skipped), while the advertised SEC ("syscall") was the same string a silent
# degradation produces. The timer map, the arming program and the re-arming
# callback have since been ported, so the golden beside this fixture now
# contains the body.
#
# The shape is deliberately the one the feature originally shipped with, so the
# golden can be compared against the retired Ruby generator's own output for
# this source.
@ticks = 0

module Heartbeat
  include BPF::EventLoop

  on :timer, every: 1.seconds do
    @ticks = @ticks + 1
  end
end
