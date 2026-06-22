# BPF_ITER over kernel tasks. Counts every task (one prog call per task) into
# @ntasks at load time. bcc BPF_ITER / `bpftool iter` equivalent.
@ntasks = 0
def iter__task__count
  @ntasks = @ntasks + 1
end
puts "iter/task counted all tasks at load"
sleep 3600
