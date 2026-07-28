# amp-m7 real-hardware demo probe. Distinct arithmetic (@ticks * 7) so the
# ring values (7, 14, 21, ...) are unmistakably from the Ruby-authored bytecode
# running on the M7, not a hand-written counter.
def on_tick
  @ticks += 1
  spnl_emit(@ticks * 7)
end
