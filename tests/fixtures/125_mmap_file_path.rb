# lsm/mmap_file -- see the file behind an executable mapping, by path.
#
# This hook's argument is `file__nullable` in BTF (an anonymous mmap has
# file == NULL). The NULL guard is not defensiveness, it is REQUIRED TO LOAD: the
# unguarded version is rejected by the verifier with "R1 pointer arithmetic on
# trusted_ptr_or_null_ prohibited, null-check it first". That was measured as a
# direct A/B against the same probe with the guard, which loads and falls back to
# "path unknown = no match".
@denied = 0

def lsm__mmap_file(file, reqprot, prot, flags)
  emit_path(file)
  if path_starts_with(file, "/tmp/")
    @denied = @denied + 1
    -1
  else
    0
  end
end
