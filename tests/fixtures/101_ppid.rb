# ppid -- the calling process's parent tgid.
#
# Scalar read via BPF_CORE_READ(bpf_get_current_task_btf(), real_parent, tgid).
# Returns the INIT-namespace pid (like all BPF pids); a container's /proc pids
# differ. An expression, so it can drive `if`.
@from_init = 0

def fmod_ret__security_file_open(file, ret)
  if ppid == 1
    @from_init = @from_init + 1
  end
  ret
end
