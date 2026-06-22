# full DNAT — IP + port rewrite with proto-aware L4 csum offset.
# skb_load_u16 / skb_store_u16 (port) + l4_csum_replace (no pseudo-header).
@n = 0

def tc__ingress__dnat
  proto = skb_load_byte(23)
  dst = skb_load_u32(30)
  if dst == 167772162
    np = 167772259
    if proto == 6
      l4 = 50
    else
      l4 = 40
    end
    l3_csum_replace_ip(24, dst, np)
    l4_csum_replace_ip(l4, dst, np)
    skb_store_u32(30, np)
    dp = skb_load_u16(36)
    l4_csum_replace(l4, dp, 8080)
    skb_store_u16(36, 8080)
    @n = @n + 1
  end
  TC_ACT_OK
end
