# BPF_ITER over kernel tasks. The program is invoked once per task; here
# it just counts them into a global ivar. Driven from userspace at load time
# (glue.c creates the iterator and reads it).
@ntasks = 0
def iter__task__count
  @ntasks = @ntasks + 1
end
