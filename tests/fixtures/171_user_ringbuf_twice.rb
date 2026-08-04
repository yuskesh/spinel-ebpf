# Negative fixture: two USER_RINGBUF callbacks in one unit.
#
# There is one `bpf_user_cmds` ring per unit and `user_ringbuf_drain` names its
# callback by symbol, so the second callback would be emitted and never called.
# The same call made for a second `on :timer`: refused at the layer that still
# knows there are two definitions, rather than letting one silently win.
@a = 0
@b = 0

def user_ringbuf__first(value)
  @a = @a + value
end

def user_ringbuf__second(value)
  @b = @b + value
end

def xdp__pump
  user_ringbuf_drain
  XDP_PASS
end
