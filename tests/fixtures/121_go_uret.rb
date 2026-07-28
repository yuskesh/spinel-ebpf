# go_uret -- Go return-probe. uretprobe corrupts Go's movable stack, so the handler
# is a plain SEC("uprobe") that glue.c attaches at every RET offset of the function (arm64
# `ret` = 0xd65f03c0 scan). At a RET, PARM1 (=R0) is the function's return value.
module GoUretFix
  include BPF::EventLoop

  on :go_uret, "/opt/app/goclient:crypto/tls.(*Conn).Read" do |ret|
    spnl_emit(ret)
  end
end
