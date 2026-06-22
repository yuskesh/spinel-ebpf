# socket_filter / flow_dissector / sk_lookup minimal programs. Each just
# returns a constant verdict so it loads + verifies (attach is application- or
# netns-specific and out of scope here).
def socket_filter__keep
  65535
end
def flow_dissector__ok
  0
end
def sk_lookup__pass
  1
end
