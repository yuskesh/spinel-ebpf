# NEGATIVE fixture: kfield_str_eq written WITHOUT its compare literal.
#
# Every argument of kfield_str_eq is a string, so leaving the literal out does not
# look wrong: the last FIELD is promoted to it and the field path silently loses
# its last hop. What is left is a chain that ends on `struct dentry *` -- still a
# pointer, so a naive "is it a pointer?" test would accept it and read the dentry
# itself as a string.
#
# This fixture exists to keep that from ever compiling. It HAS a golden (the
# codegen emits C for it, and that C is worth reviewing) but its committed
# compile status is `clang_fail`: the SPNL_KSTR_CHECK at the call site refuses it
# and names this Ruby line in the message. If it ever turns `ok`, the shape check
# has been weakened and the silent failure is back.
@hits = 0

def kprobe__vfs_read(file)
  if kfield_str_eq(file, "file", "f_path.dentry", "d_name.name")
    @hits = @hits + 1
  end
end
