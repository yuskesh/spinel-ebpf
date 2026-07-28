# Hot-swap target: single @ticks (×1) so the swapped-in ring values (1,2,3)
# are unmistakably different from hb_hw's ×7 (7,14,21) — proving a live probe swap
# with no firmware restart.
def on_tick
  @ticks += 1
  spnl_emit(@ticks)
end
