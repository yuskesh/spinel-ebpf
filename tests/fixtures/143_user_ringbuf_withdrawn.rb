# Negative fixture: `user_ringbuf__<name>` is a WITHDRAWN attach kind.
#
# It was supposed to become a SEC-less callback that bpf_user_ringbuf_drain
# invokes. The USER_RINGBUF map, the callback emission and `user_ringbuf_drain`
# all went missing in the port to the C codegen, so this used to compile into a
# plain SEC("syscall") program that nothing drained.
@cmds = 0

def user_ringbuf__cmd_handler(value)
  @cmds = @cmds + value
  0
end
