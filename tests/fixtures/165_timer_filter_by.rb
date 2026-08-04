# Negative fixture: `filter_by` in a unit that also has a timer.
#
# The common filter refuses a unit whose handlers it cannot all cover, because
# filtering some and leaving the rest open produces a probe that LOOKS narrowed
# and is not. A bpf_timer callback is not process context -- SPNL_FILTER_PID
# would be compared against whichever task the softirq landed on -- so the timer
# is one of the handlers it cannot cover, and the declaration is refused whole.
filter_by :pid

@opens = 0
@ticks = 0

module Mixed
  include BPF::EventLoop

  on :kprobe, "do_sys_openat2" do
    @opens = @opens + 1
  end

  on :timer, every: 1.seconds do
    @ticks = @ticks + 1
  end
end
