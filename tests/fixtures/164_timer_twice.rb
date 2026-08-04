# Negative fixture: two `on :timer` handlers in one unit.
#
# The callback name is fixed (spnl_timer_cb_main), so a second timer would emit a
# second function with that name -- clang would say "redefinition" and name a
# symbol the author never wrote. Refused here instead, at the layer that still
# knows there are two `on :timer` blocks.
@a = 0
@b = 0

module TwoTimers
  include BPF::EventLoop

  on :timer, every: 1.seconds do
    @a = @a + 1
  end

  on :timer, every: 2.seconds do
    @b = @b + 1
  end
end
