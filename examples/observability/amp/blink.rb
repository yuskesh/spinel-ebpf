# Minimal amp-m7 probe. On each tick the runtime calls on_tick;
# @ticks is a static-memory counter, spnl_emit publishes it to the ring.
def on_tick
  @ticks += 1
  spnl_emit(@ticks)
end
