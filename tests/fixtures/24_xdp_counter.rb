# Minimum XDP demonstration.
#
# `xdp__<name>` method names attach as SEC("xdp"). Body must return one of
# XDP_PASS / XDP_DROP / XDP_TX / XDP_REDIRECT (codegen recognises the
# constants via KNOWN_CONSTANTS). Top-level ivars persist across packets via
# the per-unit BPF HASH map.
#
# Definitions of XDP_* are kept here so the file is also valid CRuby, but
# the codegen substitutes the literal integers (see KNOWN_CONSTANTS).

XDP_ABORTED  = 0
XDP_DROP     = 1
XDP_PASS     = 2
XDP_TX       = 3
XDP_REDIRECT = 4

@rx_pkts = 0

def xdp__main
  @rx_pkts = @rx_pkts + 1
  XDP_PASS
end

# Native main: keep the binary alive so the attached XDP program keeps running.
# Counter lives in a BPF map; dump it from another shell while we're sleeping:
#   bpftool map dump name u_24_xdp_co_top_rx_pkts
puts "[demo] XDP attached. sleeping 10s; inspect counter via bpftool."
sleep 10
puts "[demo] exiting; XDP detaches at destructor."
