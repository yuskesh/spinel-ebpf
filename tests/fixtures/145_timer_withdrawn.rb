# Negative fixture: `on :timer, every: N` is a WITHDRAWN attach kind.
#
# The worst shape measured in the attach-kind audit. The C reactor table has no
# :timer entry and an unknown kind is skipped, so the handler did not merely
# attach to nothing -- the body never reached the emitted C at all, and the
# advertised SEC ("syscall") happened to be the same string a silent degradation
# produces, so even a SEC-comparison audit would have called it fine.
@ticks = 0

module Heartbeat
  include BPF::EventLoop

  on :timer, every: 1.seconds do
    @ticks = @ticks + 1
  end
end
