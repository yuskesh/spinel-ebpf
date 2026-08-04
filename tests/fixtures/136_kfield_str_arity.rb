# NEGATIVE fixture: kfield_str_eq with no field path at all.
#
# (ptr, "struct", "literal") leaves nothing between the struct name and the value
# to compare, so there is no field to read. The codegen refuses it at compile time
# with the shape spelled out -- including the part that is genuinely easy to get
# wrong, that the LAST string is the literal and not a field.
#
# Refused by the codegen, so this fixture has no golden (tests/golden/codegen_reject.tsv).
def kprobe__vfs_read(file)
  if kfield_str_eq(file, "file", "spnl_target.txt")
    0
  end
end
