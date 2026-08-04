# Negative fixture: a USER_RINGBUF callback nobody drains.
#
# A callback is not attached to anything. It runs only when some other handler
# calls `user_ringbuf_drain`, so as written the host can push commands forever
# and this body never runs -- and the emitted C would not even keep the
# function, since it is `static` with no caller.
#
# This is where it differs from a lone tail-call target, which IS a program and
# which the loader does register into the PROG_ARRAY. Refused at the layer that
# still knows what the author wrote.
@cmds = 0

def user_ringbuf__cmd_handler(value)
  @cmds = @cmds + value
end
