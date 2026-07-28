# path_contains(file, "/literal/substr/") -- SUBSTRING path match, the third
# sibling of path_eq (exact) and path_starts_with (prefix).
#
# A substring can appear at ANY offset up to PATH_MAX, so the compare is a
# sliding-window search over the whole path via bpf_loop (reading into a per-CPU
# 4096B scratch map, shared with path_starts_with): a crafted long path with the
# substring near the end must NOT bypass the deny (no-bypass). The literal
# length/bytes are known at compile time, so each window's byte compare is fully
# unrolled inside the callback; a CONSTANT 4096 loop bound stays verifier-bounded
# and the callback breaks early at the real path end (i+N > plen) or on a match.
#
# path_contains is an expression (drives `if`), gated to the 3 bpf_d_path hooks.
@denied = 0
@allowed = 0

def fmod_ret__security_file_open(file, ret)
  if path_contains(file, "/.ssh/")
    @denied = @denied + 1
    -1
  else
    @allowed = @allowed + 1
    ret
  end
end
