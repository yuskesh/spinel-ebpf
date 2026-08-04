# A timer sharing a module with an ordinary handler.
#
# Fixture 145 pins the timer alone, in the shape the feature originally shipped
# with. This one pins the part 145 cannot show: a timer is emitted by a
# SHORT-CIRCUIT in the per-method loop, so it has to leave every other method's
# inner+wrapper untouched and the section order intact. `@opens` is written by
# the kprobe and read by the timer, which is the reactor DSL's whole premise (one
# module, several event sources, shared instance variables) and the shape
# examples/observability/full_observability_demo.rb uses.
@opens = 0
@ticks = 0
@last  = 0

module Sampler
  include BPF::EventLoop

  on :kprobe, "do_sys_openat2" do
    @opens = @opens + 1
  end

  # Every 500 ms: publish the count the kprobe has been accumulating and reset it,
  # i.e. the kernel-side "periodic aggregation" the timer exists for.
  on :timer, every: 500.milliseconds do
    @last  = @opens
    @opens = 0
    @ticks = @ticks + 1
  end
end
