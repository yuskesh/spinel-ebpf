# kfield_str_eq(ptr, "struct", "field"..., "literal") -- does a kernel struct's
# STRING field equal a compile-time literal?
#
# The expression form (it drives `if`), sibling of kfield_str's emit form and of
# path_eq. Different axis from path_eq: this compares a structural FIELD, so it
# reaches strings bpf_d_path cannot produce -- a kprobe can never call bpf_d_path
# yet can read file->f_path.dentry->d_name.name here.
#
# The LAST string argument is the value to compare; everything before it is the
# field path. Forgetting it does not silently shift the meaning: the chain then
# stops on `struct dentry *` and the compile-time shape check refuses it.
#
# Buffer sizing is NOT path_eq's (measured): bpf_probe_read_kernel_str truncates
# silently, so an exactly-sized buffer would make "spnl" match "spnl_target.txt".
# One spare byte makes the end of the value observable.
@hits = 0

# vfs_read(struct file *file, ...) -- observation, no verdict to return.
def kprobe__vfs_read(file)
  if kfield_str_eq(file, "file", "f_path.dentry", "d_name.name", "spnl_target.txt")
    @hits = @hits + 1
  end
end

# The same predicate on a hook that HAS a verdict: deny by file NAME, wherever it
# lives, which is the axis a full-path selector cannot express in one literal.
def fmod_ret__security_file_open(file, ret)
  if kfield_str_eq(file, "file", "f_path.dentry", "d_name.name", "spnl_secret.txt")
    -1
  else
    ret
  end
end
