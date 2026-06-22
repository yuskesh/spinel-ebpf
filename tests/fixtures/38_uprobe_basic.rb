# uprobe / uretprobe attach smoke fixture.
# Binary path comes from SPNL_UPROBE_BINARY env var at attach time.
# Args use kprobe-style PT_REGS_PARM<N>.

@calls = 0
@returns = 0
@last_ret = 0

def uprobe__readline(prompt)
  @calls += 1
end

def uretprobe__readline(ret)
  @returns += 1
  @last_ret = ret
end
