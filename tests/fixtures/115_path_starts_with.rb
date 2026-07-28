# path_starts_with(file, "/literal/prefix/") -- PREFIX path match, the
# sibling of the exact-match path_eq.
#
# A path under the prefix can be up to PATH_MAX long (prefix + arbitrary suffix),
# so the compare reads into a per-CPU 4096B scratch map, not a stack buffer: a
# small buffer would -ENAMETOOLONG on long paths and MISS them = a
# deny/audit bypass. The literal length/bytes are known at compile time, so the
# byte compare is fully unrolled with a length-first short-circuit.
#
# path_starts_with is an expression (drives `if`), gated to the 3 bpf_d_path hooks.
@denied = 0
@allowed = 0

def fmod_ret__security_file_open(file, ret)
  if path_starts_with(file, "/etc/spnl_e332/")
    @denied = @denied + 1
    -1
  else
    @allowed = @allowed + 1
    ret
  end
end
