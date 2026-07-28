# path_eq(file, "/literal/path") -- exact full-path match, equivalent to
# Tetragon's matchBinaries selector.
#
# This takes direct advantage of AOT compilation: the literal's length and bytes
# are known at compile time, so it lowers to an exactly-sized stack buffer plus
# an unrolled byte comparison. A runtime-configured agent cannot recompile its
# policy and therefore needs a string map (bucketed into size classes) plus an
# LPM trie; spinel-ebpf can bake the literal straight into the program.
#
# Sizing the buffer to exactly the literal length is not a limitation but the
# correct semantics: if the real path is longer than the literal, bpf_d_path
# returns -ENAMETOOLONG, which is precisely a non-match.
#
# path_eq is an expression, so it can drive an `if` (emit_path is a statement).
@denied = 0
@allowed = 0

def fmod_ret__security_file_open(file, ret)
  if path_eq(file, "/etc/spnl_e287_secret")
    @denied = @denied + 1
    -1
  else
    @allowed = @allowed + 1
    ret
  end
end
