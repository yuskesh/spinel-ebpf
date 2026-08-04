# iter_task() -- the builtin half of the BPF_ITER capability.
#
# 62_iter_task.rb only exercises the ATTACH (`def iter__task__<n>`), so when the
# builtin was dropped in the port to the C codegen nothing noticed: the fixture
# kept passing while `iter_task()` died with "CallNode not yet ported". Counting
# tasks is not what iter/task is for -- reading fields off each one is. This
# fixture pins the part that makes the capability true.
#
# iter_task() yields the task_struct* the iterator was invoked for (as __s64);
# kfield() then reads fields off it with BPF_CORE_READ. The inner is ctx-prefixed
# so ctx->task is in scope; there is no other attach point that has one, which is
# why the builtin is gated to iter__task__.
@ntasks = 0
@pid_sum = 0

def iter__task__scan
  t = iter_task
  @ntasks = @ntasks + 1
  @pid_sum = @pid_sum + kfield(t, "task_struct", "pid")
  0
end
