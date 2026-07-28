# ktime_ns amp helper (NETC PHC, gPTP-synced). Emit the PHC time as data.
def timer_100
  @last = ktime_ns
  spnl_emit(@last)
end
