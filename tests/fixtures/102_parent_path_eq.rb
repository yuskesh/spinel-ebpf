# parent_path_eq -- deny a file access based on the PARENT's executable path.
#
# Tetragon's matchParentBinaries + Override equivalent, in Ruby. The parent exe
# path is read via a direct-deref chain (t->real_parent->mm->exe_file->f_path) so
# it stays a trusted pointer for bpf_d_path (BPF_CORE_READ would scalarize it).
@denied = 0

def fmod_ret__security_file_open(file, ret)
  if parent_path_eq("/usr/bin/spnlbad") && path_eq(file, "/etc/spnl_parent_file")
    @denied = @denied + 1
    -1
  else
    ret
  end
end
