# Verification: reactor block params for USDT.

module ReactorUsdtParams
  include BPF::EventLoop

  on :usdt, "/usr/lib/aarch64-linux-gnu/libstdc++.so.6", "libstdcxx", "throw" do |obj, tinfo, dest|
    @last_obj = obj
    @count = @count + 1
  end
end

@last_obj = 0
@count = 0
