# hard/soft IRQ handler time (bcc hardirqs/softirqs). Declares the
# irq/vec field (exercises the tracepoint struct extraction + softirq override);
# cpu_id() keys the per-CPU latency (one handler per CPU at a time). The shipped
# tools omit the field and key purely by cpu_id; this fixture covers the field
# path too.
def tracepoint__irq__irq_handler_entry(irq)
  lat_start(cpu_id + irq)
  0
end

def tracepoint__irq__irq_handler_exit(irq, ret)
  d = lat_end(cpu_id + irq)
  if d > 0
    hist_observe(d)
  end
  0
end

def tracepoint__irq__softirq_entry(vec)
  lat_start(cpu_id + vec)
  0
end

def tracepoint__irq__softirq_exit(vec)
  d = lat_end(cpu_id + vec)
  if d > 0
    hist_observe(d)
  end
  0
end
