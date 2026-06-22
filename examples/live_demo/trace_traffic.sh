#!/bin/sh
# Live demo: visualize the traffic of the server that is serving this terminal,
# using eBPF. Shows a visualization program written in Ruby being compiled,
# built, and run on the spot.
cd /work
echo "# eBPF visualization program written in Ruby:"
echo "------------------------------------------------------------"
cat examples/live_demo/ws_traffic.rb
echo "------------------------------------------------------------"
echo ""
echo "\$ ruby bin/spinel-ebpf compile examples/live_demo/ws_traffic.rb -o /tmp/wstraf --build"
ruby bin/spinel-ebpf compile examples/live_demo/ws_traffic.rb -o /tmp/wstraf --build 2>/dev/null
echo ""
echo "\$ /tmp/wstraf/ws_traffic        # run it -> typing in the terminal above streams the sent bytes"
echo ""
exec /tmp/wstraf/ws_traffic
