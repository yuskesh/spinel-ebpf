# Named emit — distinguish emit sites by name.
#
# `emit :NAME, value` (producer) lowers to spnl_emit_pair(<name tag>, value), and
# `on_emit :NAME do |v|` (consumer) routes the pair ringbuf by tag to the matching
# handler. This lets you distinguish multiple emit sites of the same kind (pair)
# by name (an alternative to numeric per-site tags; answers the "which probe did
# this value come from?" question).
#
# Constraints (current minimal form): write `emit :NAME, <single value>` as a
# statement (on its own line). One value per event. Named emit and raw
# on_emit_pair cannot be mixed (both use the pair ringbuf).
#
# build:    bin/spinel-ebpf compile examples/observability/named_demo.rb --build --ebpf-dispatch -o build
# run:      ./build/named_demo     # -> 6 (http) then 300 (tcp)
# describe: bin/spinel-ebpf describe examples/observability/named_demo.rb
@http = 0
@tcp  = 0

def produce(n)
  n.times do |i|
    emit :http_open, (i + 1)     # 1,2,3 -> :http_open
  end
  n.times do |i|
    emit :tcp_send, 100          # 100 x n -> :tcp_send
  end
end

on_emit :http_open do |v|
  @http = @http + v
end

on_emit :tcp_send do |v|
  @tcp = @tcp + v
end

produce(3)
consume_events(200)
puts @http     # 1+2+3 = 6
puts @tcp      # 100*3 = 300
