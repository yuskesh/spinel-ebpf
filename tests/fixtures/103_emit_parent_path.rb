# emit_parent_path -- the CURRENT process's parent executable path via bpf_d_path.
#
# Parent chain via direct deref (t->real_parent->mm->exe_file->f_path) so it stays a
# trusted pointer for bpf_d_path (BPF_CORE_READ scalarizes it). Same kernel gate
# as emit_path: only measured-OK bpf_d_path hooks. Rides the str ringbuf.
@opens = 0

def lsm__file_open(file, ret)
  @opens = @opens + 1
  emit_path(file)        # file.path
  emit_comm              # process.executable.name
  emit_parent_path       # process.parent.executable.path
  0
end
