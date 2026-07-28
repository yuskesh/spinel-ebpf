# amp-m7 trigger DSL (convention over method name).
# timer_1000 -> runtime calls every 1000 ms; irq_74 -> on NVIC IRQ 74 (TPM4).
def timer_1000
  @ticks += 1
  spnl_emit(@ticks)
end

def irq_74
  @irqs += 1
  spnl_emit(@irqs)
end
