# Verification: reactor block params for uprobe.
# Does `on :uprobe, ... do |arg0| ... end` bind arg0 to PT_REGS_PARM1?

module ReactorBlockParams
  include BPF::EventLoop

  on :uprobe, "/usr/bin/bash:readline" do |prompt|
    @sum = @sum + prompt
  end
end

@sum = 0
