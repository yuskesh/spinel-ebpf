# emit_kfield_str(ptr, "struct", "field"...) -- a kernel struct's STRING field.
#
# kfield reads a field as a scalar. This is its string sibling: same accessor
# convention (comma = pointer hop, dot = embedded member), the per-unit string
# ringbuf as the destination (same channel as emit_comm / emit_path / emit_argv).
#
# The two chains below end on the two DIFFERENT shapes a string field can have,
# and the source looks identical for both -- the codegen asks the C type system
# which one it is, because reading a pointer field "as bytes" yields the eight
# bytes of the pointer and the verifier does not object:
#
#   d_name.name   const unsigned char *   the field POINTS AT the characters
#   s_id          char[32]                the field IS the characters
#
# The second one is also three hops deep (file -> dentry -> super_block), which
# is the case kfield already handled for scalars.
#
# No hook gate: unlike bpf_d_path, bpf_probe_read_kernel_str loaded in every
# program type measured -- so this works in a kprobe, where bpf_d_path is
# structurally impossible and the full path is out of reach.
@reads = 0

# vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
def kprobe__vfs_read(file)
  @reads = @reads + 1
  emit_kfield_str(file, "file", "f_path.dentry", "d_name.name")    # pointer shape
  emit_kfield_str(file, "file", "f_path.dentry", "d_sb", "s_id")   # array shape, 3 hops
end
