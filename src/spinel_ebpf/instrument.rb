# frozen_string_literal: true
#
# `--instrument` auto-instrumentation — symbol-map driven.
#
# spinel is the compiler, so it knows every method and the exact C symbol it
# lowers to. Upstream `--emit-symbol-map` dumps that mapping as JSON
# ({c, ruby, kind, file, line}); we use it as the AUTHORITATIVE source instead of
# assuming `sp_<name>` (which breaks for operator/mangled names and misses
# class/instance methods). For each instrumented method this module:
#
#   1. takes its real C symbol from the symbol map (top-level + class methods),
#   2. injects __attribute__((noinline)) on that symbol so it survives `cc -O2`
#      (non-recursive leaves are otherwise inlined away and lose their symbol),
#   3. generates an agent that puts a uprobe/uretprobe on the symbol and records
#      per-method rate + log2 latency in the kernel keyed-hist.
#
# Records flow through as Hashes: { ruby:, c:, kind:, file:, line:, idx: }.
require "json"
require_relative "codegen_bpf"

module SpinelEbpf
  module Instrument
    module_function

    # Parse upstream `--emit-symbol-map` JSON into records. `line` is an Integer
    # or nil; `file` is basenamed for use as a metric label.
    def parse_symbol_map(json)
      data = JSON.parse(json)
      (data["symbols"] || []).map do |s|
        { ruby: s["ruby"], c: s["c"], kind: s["kind"],
          file: s["file"] ? File.basename(s["file"]) : "",
          line: s["line"] }
      end
    end

    # The unqualified method name (drops `Class#` / `Class.`), for filtering and
    # for --instrument-only/-skip matching the way a user would type it.
    def short_name(ruby)
      ruby.to_s.split(/[#.]/).last
    end

    # Instrumentable records: drop builtins (spnl_emit*) and attach handlers
    # (kprobe__/xdp__/...) by short name; apply --instrument-only / --instrument-skip
    # (matched against full ruby name OR short name); then assign a stable idx.
    def instrumentable(records, only: nil, skip: nil)
      recs = records.reject do |r|
        sn = short_name(r[:ruby])
        CodegenBpf::BUILTIN_NAMES.include?(sn) || CodegenBpf.detect_attach(sn)
      end
      match = lambda { |r, list| list.include?(r[:ruby]) || list.include?(short_name(r[:ruby])) }
      recs = recs.select { |r| match.call(r, only) } if only && !only.empty?
      recs = recs.reject { |r| match.call(r, skip) } if skip && !skip.empty?
      recs.each_with_index.map { |r, i| r.merge(idx: i) }
    end

    # Top-level workload methods are eBPF-eligible free functions, so in
    # --instrument-self they must be forced :native + excluded from the eBPF IR.
    # Class/instance methods are never eBPF (not free functions) — native already.
    def self_target_names(records)
      records.select { |r| r[:kind] == "toplevel" }.map { |r| r[:ruby] }.uniq
    end

    # Add __attribute__((noinline)) to each C symbol's declaration + definition
    # lines so it is uprobe-able after -O2. Anchored at a line-leading
    # `static <rettype> <csym>(` — call sites are indented/embedded, never match.
    def inject_noinline(c_source, csyms)
      csyms.reduce(c_source) do |src, sym|
        src.gsub(/^static(\s+[A-Za-z_][\w *]*?\s+#{Regexp.escape(sym)}\s*\()/) do
          "static __attribute__((noinline))#{::Regexp.last_match(1)}"
        end
      end
    end

    # Keyed-hist map name the agent reads per-method duration from.
    HIST_MAP = "bpf_hist_keyed"

    # Per record r at r[:idx], both modes share the kernel-side probes on the real
    # C symbol r[:c]:
    #   uprobe   : lat_start((tid << 8) | idx)          -- keyed latency
    #   uretprobe: hist_observe_by(idx, lat_end(...))   -- per-method log2 hist
    # depth_collapse: record only the OUTERMOST recursive call.
    def probe_defs(records, depth_collapse: false)
      if depth_collapse
        uprobes = records.map do |r|
          "def uprobe__#{r[:c]}\n  k = (tid << 8) | #{r[:idx]}\n  if depth_inc(k) == 1\n    lat_start(k)\n  end\nend"
        end.join("\n\n")
        uretprobes = records.map do |r|
          "def uretprobe__#{r[:c]}\n  k = (tid << 8) | #{r[:idx]}\n  if depth_dec(k) == 0\n    d = lat_end(k)\n    hist_observe_by(#{r[:idx]}, d)\n  end\nend"
        end.join("\n\n")
      else
        uprobes = records.map do |r|
          "def uprobe__#{r[:c]}\n  lat_start((tid << 8) | #{r[:idx]})\nend"
        end.join("\n\n")
        uretprobes = records.map do |r|
          "def uretprobe__#{r[:c]}\n  d = lat_end((tid << 8) | #{r[:idx]})\n  hist_observe_by(#{r[:idx]}, d)\nend"
        end.join("\n\n")
      end
      "#{uprobes}\n\n#{uretprobes}"
    end

    # Dispatch by output mode (default :metrics — long-lived Prometheus endpoint).
    def generate_agent(records, target_bin:, mode: :metrics, wait_seconds: 10, port: 9100, depth_collapse: false)
      case mode
      when :dump then generate_dump_agent(records, target_bin: target_bin, wait_seconds: wait_seconds, depth_collapse: depth_collapse)
      else            generate_metrics_agent(records, target_bin: target_bin, port: port, depth_collapse: depth_collapse)
      end
    end

    # One-shot: observe wait_seconds, then dump per-method count/p50/p99/
    # log2-hist (labelled with the Ruby name) to stdout+stderr and exit.
    def generate_dump_agent(records, target_bin:, wait_seconds: 10, depth_collapse: false)
      reports = records.map do |r|
        [%(puts "#{r[:ruby]} calls"),
         %(puts SpnlHistFFI.spnl_hist_count_keyed("#{HIST_MAP}", #{r[:idx]})),
         %(puts "#{r[:ruby]} p50ns"),
         %(puts SpnlHistFFI.spnl_p_keyed("#{HIST_MAP}", #{r[:idx]}, 0.5)),
         %(puts "#{r[:ruby]} p99ns"),
         %(puts SpnlHistFFI.spnl_p_keyed("#{HIST_MAP}", #{r[:idx]}, 0.99)),
         %(SpnlHistFFI.spnl_dump_log2_hist_keyed("#{HIST_MAP}", #{r[:idx]}, "#{r[:ruby]} ns"))].join("\n")
      end.join("\n")
      <<~RUBY
        # GENERATED by spinel-ebpf --instrument --instrument-dump. Do not edit.
        # One-shot: observe #{wait_seconds}s, then dump per-method count/p50/p99/log2-hist.
        # run: SPNL_UPROBE_BINARY=#{target_bin} ./<agent> &  then run the target
        module SpnlHistFFI
          ffi_func :spnl_hist_count_keyed, [:str, :long], :long
          ffi_func :spnl_p_keyed, [:str, :long, :double], :long
          ffi_func :spnl_dump_log2_hist_keyed, [:str, :long, :str], :int
        end

        #{probe_defs(records, depth_collapse: depth_collapse)}

        sleep #{wait_seconds}

        #{reports}
      RUBY
    end

    # Shared Prometheus server source: sp_net FFI + per-method body helpers +
    # `def __spnl_run_agent` (the epoll /metrics loop). Each scrape reads the
    # kernel keyed-hist live (no ringbuf, overflow-immune). Metric labels carry
    # the Ruby name + source file/line from the symbol map.
    def metrics_server_defs(records, port:)
      calls = records.map { |r| %(  s = s + __spnl_mcalls("#{r[:ruby]}", "#{r[:file]}", #{r[:line] || 0}, #{r[:idx]})) }.join("\n")
      lats  = records.map { |r| %(  s = s + __spnl_mlat("#{r[:ruby]}", "#{r[:file]}", #{r[:line] || 0}, #{r[:idx]})) }.join("\n")
      # All agent helpers are __spnl_*-prefixed so the eBPF codegen excludes them
      # (cc_is_consumer_fn) and partition forces them native — they use FFI /
      # strings / to_i which can't lower to eBPF.
      <<~RUBY
        module Net
          ffi_func :sp_net_listen,         [:int, :int], :int
          ffi_func :sp_net_accept,         [:int],       :int
          ffi_func :sp_net_read_line,      [:int],       :str
          ffi_func :sp_net_write_str,      [:int, :str], :int
          ffi_func :sp_net_rl_close,       [:int],       :int
          ffi_func :sp_net_epoll_create,   [],           :int
          ffi_func :sp_net_epoll_add,      [:int, :int], :int
          ffi_func :sp_net_epoll_wait_one, [:int],       :int
          ffi_func :sp_net_install_term_handlers, [],    :int
        end

        module SpnlHistFFI
          ffi_func :spnl_hist_count_keyed, [:str, :long], :long
          ffi_func :spnl_p_keyed, [:str, :long, :double], :long
        end

        # one method's count line (labels carried as args so no escaping needed)
        def __spnl_mcalls(name, file, line, idx)
          'spnl_method_calls_total{method="' + name + '",file="' + file + '",line="' + line.to_s + '"} ' + SpnlHistFFI.spnl_hist_count_keyed("#{HIST_MAP}", idx).to_s + "\\n"
        end

        # one method's p50/p99 latency gauge lines (ns, approx from log2 hist)
        def __spnl_mlat(name, file, line, idx)
          p50 = SpnlHistFFI.spnl_p_keyed("#{HIST_MAP}", idx, 0.5)
          p99 = SpnlHistFFI.spnl_p_keyed("#{HIST_MAP}", idx, 0.99)
          lbl = 'method="' + name + '",file="' + file + '",line="' + line.to_s + '"'
          'spnl_method_latency_ns{' + lbl + ',quantile="0.5"} ' + p50.to_s + "\\n" +
          'spnl_method_latency_ns{' + lbl + ',quantile="0.99"} ' + p99.to_s + "\\n"
        end

        def __spnl_metrics_body
          s = "# HELP spnl_method_calls_total Calls per method observed via eBPF uprobe.\\n"
          s = s + "# TYPE spnl_method_calls_total counter\\n"
        #{calls}
          s = s + "# HELP spnl_method_latency_ns Approx latency quantiles per method (eBPF uretprobe).\\n"
          s = s + "# TYPE spnl_method_latency_ns gauge\\n"
        #{lats}
          s
        end

        def __spnl_run_agent
          port = (ENV["SPINEL_HTTP_PORT"] || "#{port}").to_i
          listen_fd = Net.sp_net_listen(port, 0)
          if listen_fd < 0
            puts "[instrument] listen failed"
            exit(1)
          end
          Net.sp_net_install_term_handlers
          ep = Net.sp_net_epoll_create
          Net.sp_net_epoll_add(ep, listen_fd)
          puts "[instrument] /metrics on 127.0.0.1:" + port.to_s
          loop do
            fd = Net.sp_net_epoll_wait_one(ep)
            break if fd < 0
            client = Net.sp_net_accept(listen_fd)
            if client >= 0
              Net.sp_net_read_line(client)
              loop do
                line = Net.sp_net_read_line(client)
                break if line.length == 0
              end
              body = __spnl_metrics_body
              resp = "HTTP/1.0 200 OK\\r\\n" +
                     "Content-Type: text/plain; version=0.0.4\\r\\n" +
                     "Content-Length: " + body.length.to_s + "\\r\\n" +
                     "Connection: close\\r\\n\\r\\n" + body
              Net.sp_net_write_str(client, resp)
              Net.sp_net_rl_close(client)
            end
          end
          puts "[instrument] shutdown"
        end
      RUBY
    end

    # Sidecar Prometheus /metrics endpoint (attaches to an external
    # target via SPNL_UPROBE_BINARY). probes + server + run_agent.
    def generate_metrics_agent(records, target_bin:, port: 9100, depth_collapse: false)
      <<~RUBY
        # GENERATED by spinel-ebpf --instrument (Prometheus /metrics). Do not edit.
        # uprobe+uretprobe per target sp_<method> -> kernel keyed-hist; /metrics reads it live.
        # build: bin/spinel-ebpf compile <this> --build --ebpf-dispatch
        # run:   SPNL_UPROBE_BINARY=#{target_bin} SPINEL_HTTP_PORT=#{port} ./<agent> &
        #        curl -s localhost:#{port}/metrics    # then exercise the target
        use_plugin :ebpf

        #{probe_defs(records, depth_collapse: depth_collapse)}

        #{metrics_server_defs(records, port: port)}
        __spnl_run_agent
      RUBY
    end

    # Single self-attaching binary. The workload (target_source, verbatim)
    # and the agent live in one unit; the uprobes self-attach (/proc/self/exe at
    # own pid — no SPNL_UPROBE_BINARY). The workload runs in this process (its
    # sp_<method> calls fire the self-uprobe -> kernel hist), then run_agent serves
    # /metrics. MVP is sequential: the workload must terminate before /metrics
    # serves (a long-running server would need fork — future / use sidecar).
    def generate_self_agent(records, target_source, port: 9100, depth_collapse: false)
      <<~RUBY
        # GENERATED by spinel-ebpf --instrument --instrument-self. Do not edit.
        # Single binary: the workload below + a self-attaching uprobe agent.
        # run: SPINEL_HTTP_PORT=#{port} ./<binary>   then curl localhost:#{port}/metrics
        use_plugin :ebpf

        #{probe_defs(records, depth_collapse: depth_collapse)}

        #{metrics_server_defs(records, port: port)}
        # === workload (your program, unchanged) — self-uprobe fires on its calls ===
        #{target_source}
        # === workload done -> serve /metrics from the accumulated kernel hist ===
        __spnl_run_agent
      RUBY
    end
  end
end
