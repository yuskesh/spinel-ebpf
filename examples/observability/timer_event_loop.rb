# NOT BUILDABLE WITH THE CURRENT CODE GENERATOR.
#
# This example uses `on :timer`, which did not survive the move from the
# original Ruby code generator to the C one. Compiling it now stops with a
# message that names the missing piece and points at the alternative, rather
# than emitting a program that loads and never fires -- which is what used to
# happen, silently.
#
# The file is kept because it records how the feature was expressed. Restoring
# it means porting the generator side, not editing this file.
#
# `on :timer, every: N.<unit> do ... end` — bpf_timer-backed
# periodic callback inside BPF::EventLoop. The handler fires once per
# interval (here 1 second) and re-arms itself.
#
# Build:
#   spinel-ebpf compile examples/observability/timer_event_loop.rb \
#       -o build/timer_event_loop --build
# Run:
#   ./build/timer_event_loop/timer_event_loop &
#   sleep 5
#   bpftool map dump name timer_event_loop_top_ticks
#   # Expect ~5 ticks

@ticks = 0

module Heartbeat
  include BPF::EventLoop

  on :timer, every: 1.seconds do
    @ticks = @ticks + 1
  end
end

puts "Heartbeat timer loaded (every 1 second)"
sleep 3600
