# frozen_string_literal: true
#
# E314 (ADR-014 層1): ドメイン capability registry。
#
# ADR-014 は機能を 3 層に分ける。層1 (probe DSL、カーネル側) の builtin を
# **ドメイン (Observability / Enforcement / Net / L7)** で括る分類メタデータ。
#
# 目的 (ADR-014 の明示制約に忠実):
#   * builtin は **flat のまま** (必須 dotted 名にしない、ワンショットのエルゴノミクスを殺さない)。
#     このモジュールは新しい言語機構ではなく、**既存 builtin を分類する純データ + 内省配線**。
#   * 発見可能性: 「このドメインにどの builtin と attach 種別がセットで来るか」を一覧化。
#   * context 契約の中央化: E286 の d_path ゲート (この builtin はこの hook でしか使えない、
#     compile 時 die) の allowlist を **単一の権威 (DPATH_OK_SECS)** に集約し、
#     codegen (Ruby oracle) と krew カタログ・内省が同じ真実を参照する。
#
# 非目標: 既存 probe の挙動・生成コードは一切変えない。これは分類メタデータであって、
# codegen ではない。die() ロジック自体は codegen_bpf.rb / spinel_ebpf_cc.c にある
# (本モジュールは allowlist の値だけを所有し、Ruby oracle がそれを参照する)。
#
# 依存なし (codegen_bpf.rb を require しない): builtin 名は下にリテラルで持つ。
# codegen の BUILTIN_NAMES との一致は tests/spinel_ebpf/capabilities_test.rb が守る
# (完全分割 = 未分類の新 builtin があれば test が落ちる = ADR-014 のガバナンス)。

module SpinelEbpf
  module Capabilities
    module_function

    # E286/E287/E289 で実測した d_path ゲートの allowlist (単一の権威)。
    # bpf_d_path はカーネル gate 付きで、単純な名前リストではない — 実測で LOAD_OK した
    # hook のみ。codegen_bpf.rb の MethodEmitter::DPATH_OK_SECS はこの定数を参照する。
    # (production C codegen spinel_ebpf_cc.c は自前のコピーを持ち、両者の一致は golden が守る。)
    DPATH_OK_SECS = %w[
      lsm/file_open
      fmod_ret/security_file_open
      fmod_ret/security_file_permission
    ].freeze

    # 層1 ドメイン registry。各ドメイン = {summary, builtins, attach_kinds}。
    # builtins は flat 名のまま (dotted に畳まない)。attach_kinds は「このドメインの
    # builtin が典型的に載る attach 種別」で、緩いメタデータ (強制ではない)。
    DOMAINS = {
      observability: {
        summary: "汎用観測 — hist/latency/stack/profile/emit/task-storage、bcc tools 相当",
        builtins: %w[
          spnl_emit spnl_emit_str spnl_emit_pair spnl_emit3 spnl_emit4
          emit_argv emit_comm comm_hash
          hist_observe hist_observe_by hist_observe_linear
          ktime_ns latency_start latency_end lat_start lat_end
          stack_id user_stack_id off_cpu_start off_cpu_observe
          task_load task_store task_incr task_swap
          leak_record leak_forget lock_edge
          mim_inc mim_get fifo_push fifo_pop lifo_push lifo_pop
          iter_task depth_inc depth_dec path_counter_inc
          kfield kptr
        ].freeze,
        attach_kinds: %i[
          kprobe kretprobe tracepoint raw_tp fentry fexit
          uprobe uretprobe usdt perf_event timer user_ringbuf iter_task
        ].freeze,
      }.freeze,
      enforcement: {
        summary: "遮断・監査・lineage — deny(lsm/fmod_ret 戻り値) + path/parent-path セレクタ (Tetragon 相当)",
        builtins: %w[
          emit_path emit_parent_path path_eq path_starts_with path_contains parent_path_eq ppid
        ].freeze,
        attach_kinds: %i[lsm fmod_ret kprobe tracepoint].freeze,
      }.freeze,
      net: {
        summary: "パケット/ソケット datapath — pkt/xdp/tc/LB/NAT/conntrack/qdisc/tcp_cc/network span",
        builtins: %w[
          pkt_len pkt_eth_proto pkt_l4_proto pkt_ip4_src pkt_ip4_dst
          pkt_l4_sport pkt_l4_dport pkt_tcp_flags pkt_l4_payload_len
          pkt_ip6_src_hi pkt_ip6_src_lo pkt_ip6_dst_hi pkt_ip6_dst_lo
          pkt_tcp_seq pkt_tcp_ack pkt_dynptr_byte_at
          emit_connect sock_owner_set
          blocklist_match cidr_blocklist_match
          reuseport_hash worker_select
          xdp_match_health xdp_reply_health
          tail_call_to sock_ops_op sock_ops_state sock_addr_ip4 sock_addr_port
          cpumap_redirect xsk_redirect dev_redirect
          fib_lookup fib_lookup6 sk_lookup_tcp sk_assign_tcp redirect
          skb_load_byte skb_load_u16 skb_load_u32
          skb_store_byte skb_store_u16 skb_store_u32
          l3_csum_replace l3_csum_replace_ip l4_csum_replace l4_csum_replace_ip l4_offset
          flow_get flow_set flow_del
          tcp_syncookie_gen tcp_syncookie_check tcp_reply_header tcp_reply_synack
          tcp_synack_cookie tcp_reply_data payload_starts
          arena_set arena_get arena_hash_set arena_hash_get arena_hash_del
          arena_list_push arena_list_sum
          tcp_sock_snd_cwnd tcp_sock_snd_ssthresh tcp_sock_snd_nxt tcp_sock_snd_una
          tcp_sock_packets_out tcp_sock_delivered tcp_sock_snd_cwnd_cnt
          tcp_sock_snd_cwnd_clamp tcp_sock_prior_cwnd
          tcp_sock_snd_cwnd_set tcp_sock_snd_ssthresh_set tcp_sock_snd_cwnd_cnt_set
          tcp_sock_snd_cwnd_add tcp_sock_snd_cwnd_cnt_add
          qdisc_skb_drop qdisc_init_prologue qdisc_reset_destroy_epilogue
          qdisc_watchdog_schedule qdisc_bstats_update
          queue_push queue_pop
        ].freeze,
        attach_kinds: %i[
          xdp xdp_tail xdp_tcp_slice tc_ingress tc_egress
          sk_reuseport sk_msg sk_skb_verdict sk_skb_parser sock_ops
          cgroup_connect4 cgroup_bind4 sk_lookup socket_filter flow_dissector
          tcp_cc qdisc
        ].freeze,
      }.freeze,
      l7: {
        summary: "アプリケーションプロトコル観測 — HTTP/Redis/TLS 平文/DNS span + L7 latency + off-CPU 相関",
        builtins: %w[
          http_req_start http_resp_stash http_emit
          redis_req_start redis_resp_stash redis_emit
          ssl_req_start ssl_resp_stash ssl_emit
          go_tls_write go_tls_req go_tls_resp_stash go_tls_emit
          dns_req_start dns_resp_stash dns_emit emit_dns emit_tcp_payload emit_tcp_stream
          req_start emit_l7
          offcpu_recv_stash offcpu_begin offcpu_account offcpu_emit
        ].freeze,
        attach_kinds: %i[kprobe kretprobe uprobe uretprobe tracepoint].freeze,
      }.freeze,
      core: {
        summary: "ドメイン非依存の基本要素 — 算術/プロセス identity/cgroup id/制御チャネル/sched_ext",
        builtins: %w[
          divu i32 pid tgid tid cpu_id cgroup_id field_exists user_ringbuf_drain
          scx_dispatch scx_consume scx_kick_cpu scx_pick_idle_cpu scx_create_dsq
        ].freeze,
        attach_kinds: %i[sched_ext].freeze,
      }.freeze,
    }.freeze

    # E286 context ゲート: これらの builtin は attach SEC が valid_secs に無いと
    # compile 時に die() する。die() 本体は codegen にあり、ここは「どの builtin が
    # どの context を要求するか」の中央メタデータ (domain -> valid-context の正本)。
    CONTEXT_GATES = {
      "emit_path"        => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "emit_parent_path" => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "path_eq"          => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "path_starts_with" => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "path_contains"    => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "parent_path_eq"   => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
    }.freeze

    # E307 krew probe カタログ (--probe dns|file|l7|net) と層1 ドメインの対応。
    # file 監査 = Enforcement、dns/l7 = L7 (DNS は L7 プロトコル)、net = Net。
    KREW_PROBE_DOMAINS = {
      "dns"  => :l7,
      "file" => :enforcement,
      "l7"   => :l7,
      "net"  => :net,
    }.freeze

    # ===================================================================
    # E370 (S3、ringbuf 型付きチャネル計画): **record 契約を affordance に出す**。
    #
    # packed-record emit builtin (emit_dns 等) は「ringbuf に何バイト書き、それが
    # 最終的にどの OTLP 属性の span になるか」という契約の片端でしかない。S1 が
    # 物理レイアウトを、S3 (本節) が意味束縛を **data** にした。正本:
    #
    #   src/codegen_c/record_schema.h   -- 唯一の宣言 (フィールド + egress 属性)
    #     -> kernel の record struct     (S1、spinel_ebpf_cc.c が直読)
    #     -> userspace mirror + SPNL_EGRESS_* マクロ (S2/S3、runtime が消費)
    #     -> record_schema_gen.json      (S3、**この Ruby が読む**)
    #
    # **offset は読むだけで計算しない**。align 規則の実装は tools/gen_record_mirror.c の
    # layout() 1 箇所きり (E369 の申し送り: Ruby で書き直すのは 3 度目の手書き = 禁じ手)。
    # 再生成は `make -C src/codegen_c mirror` (JSON も header も同時に出る)。
    # ===================================================================

    RECORD_SCHEMA_JSON = File.expand_path("record_schema_gen.json", __dir__).freeze

    # ===================================================================
    # E374 (ADR-017 D3-5): **userspace consumer DSL の語彙**を機械可読に。
    #
    # channel ごとの契約 (上の record_channels) が「何が読めるか」なら、こちらは
    # 「どう書くか」— `on_emit :<ch>` / `to_span` / `send_otlp` / `consume_records`、
    # そして `to_span` の**解決規則**。ここに載せるのは ADR-017 D3-5 の要求:
    # 「`to_span` は `on_emit :<ch>` ブロック内で解決される。スコープを越える書き方では
    # `<ch>_span(ev)` を使え」を、散文でなく **`context_note` として** (emit_path の
    # context gate と同型に) 出す。
    #
    # 層の線引き (ADR-017 D1/D2): これらは層 1 の**汎用の口**であって、span の中身は
    # 層 2 (egress 宣言) が所有する。だから `to_span` に「属性を足す引数」は無い —
    # probe が持つ自由は「送るか / いつ / 何回」であって span の中身ではない (D2)。
    # ===================================================================
    CONSUMER_DSL = [
      { name: "on_emit :<channel>",
        form: "on_emit :<channel> do |ev| ... end",
        layer: 1,
        summary: "型付き record consumer。ブロックは 1 record ごとに呼ばれ、`ev` は drain 内の " \
                 "handle (不透明)。`ev.<prop>` の集合は channel 宣言由来 (channels[<id>].consumer.properties)。",
        context_note: "<channel> は **型付き consumer を publish した channel id** のみ。" \
                      "publish していない id (redis/offcpu/l7stream) を書くと E242 named event " \
                      "として扱われる (後方互換)。同名の `emit :<channel>, v` が同居したら compile 時に落ちる。",
        gotcha: "`ev` は現在の drain サイクル内でだけ有効。跨いで貯めるならプロパティを Ruby の変数にコピーする。" }.freeze,
      { name: "to_span",
        form: "to_span(ev)",
        layer: 1,
        summary: "1 record を egress 宣言どおりの span に組む (channels[<id>].egress が正本)。" \
                 "戻り値は span handle、0 = span にならない record。",
        context_note: "**`on_emit :<channel>` ブロックの中で、そのブロックの block-param に適用したときに解決される** " \
                      "(ADR-017 D3)。複数 channel を consume するプログラムで、ブロックの外に書いた / 別の変数に " \
                      "コピーした handle に適用した場合は **compile error**。そのときは明示形 `<channel>_span(ev)` を使う。" \
                      "型付き channel が 1 つだけのプログラムではどこに書いても解決する。",
        gotcha: "span の中身を Ruby から足す API は無い (ADR-017 D2: egress 宣言が正本)。" \
                "probe の自由は「送るか / いつ / 何回」。" }.freeze,
      { name: "<channel>_span",
        form: "dns_span(ev)",
        layer: 1,
        summary: "`to_span` の明示形 (channel を名指す escape hatch)。scope 規則が届かない書き方で使う。",
        context_note: "**逃げ道であって主ではない** (ADR-017 D3-4)。通常は `to_span(ev)` を " \
                      "`on_emit :<channel>` ブロック内で使う。consume していない channel を名指すと compile error。" }.freeze,
      { name: "send_otlp",
        form: "send_otlp(to_span(ev), endpoint)",
        layer: 1,
        summary: "span を送信バッチに積む (E308 の funnel と同じ)。handle 0 は no-op なので Ruby 側で分岐しなくてよい。",
        context_note: "endpoint はサイクル最初の呼出のものを使う。flush は生成 driver がサイクル末尾で 1 回行う " \
                      "(複数 channel を consume していても POST バッチは 1 つ)。" }.freeze,
      { name: "consume_records",
        form: "st = consume_records(timeout_ms)",
        layer: 1,
        summary: "drain -> 各 record を on_emit ブロックに dispatch -> 送信バッチを flush。戻りは最後の POST の HTTP status。",
        context_note: "**呼ばないとハンドラは一度も呼ばれない** (E325: compile も verify も green のまま span 0 本)。" \
                      "loop の中で周期的に呼ぶ。複数 channel を consume している場合は 1 呼出で全 channel を drain する。" }.freeze,
    ].freeze

    def self.deep_freeze(o)
      case o
      when Hash  then o.each_value { |v| deep_freeze(v) }; o.freeze
      when Array then o.each { |v| deep_freeze(v) }; o.freeze
      else o.freeze
      end
    end
    private_class_method :deep_freeze

    # 生成 JSON の channels (lazy、memoized)。欠けていたら **loud に落ちる**
    # (silent に空を返すと「契約が無い」と「生成し忘れ」が区別できない)。
    def record_channels
      @record_channels ||= begin
        require "json"
        unless File.exist?(RECORD_SCHEMA_JSON)
          raise "record schema artifact missing: #{RECORD_SCHEMA_JSON} " \
                "(regenerate with `make -C src/codegen_c mirror`)"
        end
        doc = JSON.parse(File.read(RECORD_SCHEMA_JSON), symbolize_names: true)
        deep_freeze(doc[:channels] || [])
      end
    end

    # channel id ("dns") -> channel hash (無ければ nil)。
    def record_channel(id)
      record_channels.find { |c| c[:id] == id.to_s }
    end

    # E372 (S5): **型付き consumer を公開している** channel だけ (`consumer` ブロックを
    # 持つもの)。S1-S3 だけ済んだ channel (conn/l7/http/…) は宣言的だが
    # `on_emit :<id>` の意味は変えない — そこは E242 named event のままでなければ
    # 既存プログラムが黙って別物になる。「宣言してある」と「Ruby の受け口がある」は
    # 別の話なので、id の集合も別にする。
    def typed_record_channels
      record_channels.select { |c| c[:consumer] }
    end

    # 型付き consumer を持つ channel id (`on_emit :<id>` が typed record になる集合)。
    def typed_record_channel_ids
      typed_record_channels.map { |c| c[:id] }
    end

    # emit builtin -> その builtin が書く channel (producer でなければ nil)。
    def record_channel_for(builtin)
      record_channels.find { |c| Array(c[:producers]).include?(builtin) }
    end

    # packed record を書く builtin すべて (sorted)。
    def record_producers
      record_channels.flat_map { |c| Array(c[:producers]) }.sort.freeze
    end

    # E371 (S4): channel id -> 型付き consumer が読めるプロパティ宣言
    # ([{name:, kind:, expose:, ffi:, ffi_ret:, source:, note:}])。
    # `on_emit :<id> do |ev|` の `ev.<name>` の**権威集合**で、consumer.rb の
    # 変換はここに無い名前を compile 時に落とす。
    def record_properties(id)
      c = record_channel(id)
      Array(c && c.dig(:consumer, :properties))
    end

    # --- query API (内省が使う) ---

    # すべての分類済 builtin (sorted)。
    def all_builtins
      DOMAINS.values.flat_map { |d| d[:builtins] }.sort.freeze
    end

    # builtin 名 -> ドメイン symbol (未分類なら nil)。
    def domain_of(name)
      DOMAINS.each { |dom, spec| return dom if spec[:builtins].include?(name) }
      nil
    end

    def builtins_for(domain)
      DOMAINS.dig(domain, :builtins) || []
    end

    # gated builtin -> {domain:, valid_secs:} (非 gate なら nil)。
    def gate_for(name)
      CONTEXT_GATES[name]
    end

    # 与えた builtin 名の集合を使っているドメインだけ {domain => [names(sorted)]} で返す。
    def domains_used(names)
      seen = names.to_a.uniq
      DOMAINS.each_key.filter_map do |dom|
        hit = builtins_for(dom) & seen
        [dom, hit.sort] unless hit.empty?
      end.to_h
    end

    # E370 (S3): packed-record チャネルの人間可読ダンプ。
    # 「この builtin を書くと ringbuf に何が流れ、どの属性の span になるか」の 1 画面。
    def record_channels_report
      out = +"record channels (E368-E371 — ringbuf に流れる byte 像 / 型付き consumer / 出る span):\n"
      record_channels.each do |c|
        out << format("  %-6s %s (%d B) <- %s\n",
                      c[:id], c[:record_struct], c[:record_bytes], Array(c[:producers]).join(" / "))
        c[:fields].each do |f|
          type = f[:count].to_i > 0 ? "#{f[:ctype]}[#{f[:count]}]" : f[:ctype]
          out << format("    @%-4d %-14s %-22s %s\n", f[:offset], f[:name], type, f[:note])
        end
        cons = c[:consumer]
        if cons
          # E371 (S4): 型付き consumer — 同じ record を Ruby で受けて自前ロジックを
          # 挟める形。properties が `ev.<name>` の権威集合 (これ以外は compile error)。
          out << format("    consumer: %s   (drain %s / to_span %s / send %s)\n",
                        cons[:form], cons[:drain_fn], cons[:to_span_fn], cons[:send_fn])
          Array(cons[:properties]).each do |p|
            # derived な文字列プロパティは **出力容量**も宣言の一部 (accessor と span
            # builder が同じ幅を渡す = E377)。宣言 >= 返しうる最大長 なので「この値は最大
            # 何バイトか」が層 1 から読める。フィールド由来は record のバイトを直接読むので
            # 幅はフィールドの bytes (上の行) が持つ。
            # 表示は「値の最大バイト数」= 宣言 cap - 1 (cap は NUL を含む器の大きさ)。
            width = p[:cap].to_i > 1 ? format(" (<=%dB)", p[:cap].to_i - 1) : ""
            out << format("      ev.%-12s %-4s %-8s <- %s%s\n",
                          p[:name], p[:expose], p[:kind], p[:source], width)
          end
        end
        e = c[:egress]
        next unless e
        out << format("    egress: %s -> span \"%s\" (SpanKind %s)\n", e[:push_fn], e[:span_name], e[:span_kind])
        e[:attributes].each do |a|
          out << format("      %-24s %-8s <- %s  [%s]\n", a[:key], a[:stability], a[:source], a[:condition])
        end
        out << format("      + 層2 enricher (env-gate、probe 無変更): %s\n", Array(e[:enrichers]).join(", ")) unless Array(e[:enrichers]).empty?
      end
      out << "\n"
      out << consumer_dsl_report
      out
    end

    # E374 (ADR-017 D3-5): consumer DSL の語彙 + `to_span` の解決規則 (人間可読)。
    def consumer_dsl_report
      ids = typed_record_channel_ids
      out = +"userspace consumer DSL (E371/E374 — ringbuf を Ruby の受け口に):\n"
      out << format("  型付き channel (`on_emit :<id>` が typed record になる id): %s\n",
                    ids.empty? ? "(none)" : ids.join(", "))
      out << "  それ以外の id は E242 named event のまま (後方互換)\n"
      CONSUMER_DSL.each do |v|
        out << format("  %-22s %s\n", v[:name], v[:form])
        out << format("      %s\n", v[:summary])
        out << format("      context: %s\n", v[:context_note])
        out << format("      注意: %s\n", v[:gotcha]) if v[:gotcha]
      end
      out << "\n"
      out
    end

    # 全 registry の人間可読ダンプ (CLI `spinel-ebpf capabilities`)。
    def catalog_report
      out = +"spinel-ebpf capabilities — ADR-014 層1 ドメイン registry\n\n"
      DOMAINS.each do |dom, spec|
        out << format("%-14s (%d builtins)\n", dom, spec[:builtins].length)
        out << "  #{spec[:summary]}\n"
        out << "  attach: #{spec[:attach_kinds].join(', ')}\n" unless spec[:attach_kinds].empty?
        out << "  builtins: #{spec[:builtins].sort.join(' ')}\n\n"
      end
      unless CONTEXT_GATES.empty?
        out << "context gates (E286 — compile 時 die、この hook でしか使えない):\n"
        CONTEXT_GATES.each do |name, g|
          out << format("  %-16s [%s] valid: %s\n", name, g[:domain], g[:valid_secs].join(" | "))
        end
        out << "\n"
      end
      out << "required sets (E317 — 単独では span を生まない相方組、compile 時 loud 強制):\n"
      REQUIRED_SETS.each do |rule|
        if rule[:mode] == :all
          out << format("  [%s] %s (all-or-none)\n", rule[:experiment], rule[:members].join(" + "))
        else
          out << format("  [%s] %s requires %s\n", rule[:experiment], rule[:trigger], rule[:requires].join(", "))
        end
      end
      out << "\n"
      out << "builtin groups (E322 — 関連 builtin: pack 関係/対/ファミリ、呼び出し例つき):\n"
      BUILTIN_GROUPS.each do |g|
        forms = g[:members].map { |m| example_for(m) || m }
        out << format("  %s\n", g[:name])
        out << "    #{forms.join('  ')}\n"
        out << "    #{g[:note]}\n"
      end
      out << "\n"
      out << record_channels_report
      out << "krew probe -> ドメイン:\n"
      KREW_PROBE_DOMAINS.each { |p, d| out << format("  --probe %-5s -> %s\n", p, d) }
      out << "\nattach kinds (#{ATTACH_KINDS.length}) — `spinel-ebpf capabilities --json` で作法込みの一覧:\n"
      out << "  #{ATTACH_KINDS.map { |a| a[:kind] }.join(' ')}\n"
      out << "\nAI-authoring 契約 (機械可読): spinel-ebpf capabilities --json\n"
      out
    end

    # ===================================================================
    # E316 (ADR-015 原則4「affordance を公開する」): 機械可読な authoring 契約。
    #
    # builtin の signature (arity/params)・attach-kind の作法・Ruby サブセットの
    # 書ける/書けない・層2 enricher を **純データ** として持ち、`capabilities --json`
    # で 1 つの JSON にまとめて出す。作者 (=AI) が「打てる手」を機械可読で読める。
    #
    # 完全性 (全 builtin/attach が現れる) と codegen との arity drift 無しは
    # tests/spinel_ebpf/capabilities_test.rb が機械強制する (ADR-015 の肝)。
    #
    # signature の正本: codegen_bpf.rb の `expects N` / `expect_no_args` チェック。
    # capabilities.rb は codegen を require できない (循環: codegen が本モジュールの
    # DPATH_OK_SECS を参照) ため arity をここに **ミラー** し、test がソースを parse
    # して drift を検出する。機械的に param 名が取れない builtin は opaque: true で正直に印。
    # ===================================================================

    # 構造グループ (codegen 側と同じ名前集合、drift は完全分割 test が守る)。
    PKT_FIELD_BUILTINS = %w[
      pkt_len pkt_eth_proto pkt_l4_proto pkt_ip4_src pkt_ip4_dst
      pkt_l4_sport pkt_l4_dport pkt_tcp_flags pkt_l4_payload_len
      pkt_ip6_src_hi pkt_ip6_src_lo pkt_ip6_dst_hi pkt_ip6_dst_lo
      pkt_tcp_seq pkt_tcp_ack
    ].freeze
    TCP_SOCK_READER_BUILTINS = %w[
      tcp_sock_snd_cwnd tcp_sock_snd_ssthresh tcp_sock_snd_nxt tcp_sock_snd_una
      tcp_sock_packets_out tcp_sock_delivered tcp_sock_snd_cwnd_cnt
      tcp_sock_snd_cwnd_clamp tcp_sock_prior_cwnd
    ].freeze
    TCP_SOCK_WRITER_BUILTINS = %w[
      tcp_sock_snd_cwnd_set tcp_sock_snd_ssthresh_set tcp_sock_snd_cwnd_cnt_set
    ].freeze
    TCP_SOCK_ADDER_BUILTINS = %w[
      tcp_sock_snd_cwnd_add tcp_sock_snd_cwnd_cnt_add
    ].freeze
    OPAQUE_KFUNC_BUILTINS = %w[
      scx_dispatch scx_consume scx_kick_cpu scx_pick_idle_cpu scx_create_dsq
      qdisc_skb_drop qdisc_init_prologue qdisc_reset_destroy_epilogue
      qdisc_watchdog_schedule qdisc_bstats_update
    ].freeze

    # 明示 signature 表。value = [arity, params|nil, summary]。opaque は params.nil? で導出。
    #   arity  : Integer | :variadic
    #   params : 引数名の配列 (codegen の "expects (...)" / expect_no_args から)、opaque は nil
    # arity/param は codegen が単一の権威 (test が drift を検出)。pkt_*/tcp_sock_* は下で生成。
    SIG_TABLE = {
      # --- observability: emit / hist / latency / task / stack / etc. ---
      "spnl_emit"        => [1, %w[value],            "ringbuf に __s64 を 1 個 emit (16B hdr)"],
      "spnl_emit_str"    => [1, %w[ptr],              "user ptr の文字列を str ringbuf に emit"],
      "spnl_emit_pair"   => [2, %w[a b],              "1 event に 2 値 emit"],
      "spnl_emit3"       => [3, %w[a b c],            "1 event に 3 値 emit"],
      "spnl_emit4"       => [4, %w[a b c d],          "1 event に 4 値 emit"],
      "emit_argv"        => [1, %w[argv],             "execve argv[] を走査して str ringbuf に emit"],
      "emit_comm"        => [0, [],                   "現プロセスの comm を str ringbuf に emit"],
      "comm_hash"        => [0, [],                   "comm 先頭 8B を __s64 として返す (grouping)"],
      "hist_observe"     => [1, %w[value],            "log2 ヒストグラムに 1 サンプル"],
      "hist_observe_by"  => [2, %w[key value],        "keyed log2 ヒストグラムに 1 サンプル"],
      "hist_observe_linear" => [1, %w[slot],          "linear ヒストグラム (caller pre-bucketed)"],
      "ktime_ns"         => [0, [],                   "bpf_ktime_get_ns()"],
      "latency_start"    => [0, [],                   "BEGIN: tid キーで entry ktime を記録"],
      "latency_end"      => [0, [],                   "END: delta ns を返し entry 削除"],
      "lat_start"        => [1, %w[key],              "任意キーの latency BEGIN"],
      "lat_end"          => [1, %w[key],              "任意キーの latency END (delta 返却)"],
      "task_load"        => [0, [],                   "per-task storage の値を読む"],
      "task_store"       => [1, %w[value],            "per-task storage に値を書く"],
      "task_incr"        => [1, %w[delta],            "per-task storage を delta 加算 (single-get RMW)"],
      "task_swap"        => [1, %w[value],            "per-task storage の値と swap (汎用 RMW)"],
      "stack_id"         => [0, [],                   "kernel stack id (STACK_TRACE map)"],
      "user_stack_id"    => [0, [],                   "user stack id (STACK_TRACE map)"],
      "off_cpu_start"    => [1, %w[pid],              "off-CPU 開始 (ktime+stack を pid キーで stash)"],
      "off_cpu_observe"  => [1, %w[pid],              "off-CPU 復帰: delta を keyed hist に bin"],
      "leak_record"      => [3, %w[ptr size stack_id],"alloc を記録 (memleak)"],
      "leak_forget"      => [1, %w[ptr],              "free で記録削除 (memleak)"],
      "lock_edge"        => [2, %w[a b],              "lock 取得順エッジを記録 (deadlock)"],
      "mim_inc"          => [2, %w[group key],        "map-in-map: inner[key] を加算"],
      "mim_get"          => [2, %w[group key],        "map-in-map: inner[key] を読む"],
      "fifo_push"        => [1, %w[value],            "QUEUE map に push"],
      "fifo_pop"         => [0, [],                   "QUEUE map から pop"],
      "lifo_push"        => [1, %w[value],            "STACK map に push"],
      "lifo_pop"         => [0, [],                   "STACK map から pop"],
      "depth_inc"        => [1, %w[key],              "再帰深さカウンタを +1"],
      "depth_dec"        => [1, %w[key],              "再帰深さカウンタを -1"],
      "path_counter_inc" => [1, %w[key],              "bpf_path_counts[key] を atomic 加算 (汎用 keyed counter)"],
      "kfield"           => [:variadic, %w[ptr struct field], "BPF_CORE_READ で kernel struct field を安全読取 (可変ホップ)"],
      "kptr"             => [2, %w[ptr struct],       "local→struct を登録 (.field dot accessor 用)"],
      # --- enforcement: audit / lineage / deny selector ---
      "emit_path"        => [1, %w[file],             "bpf_d_path で完全パスを str ringbuf に (gate 有)"],
      "emit_parent_path" => [0, [],                   "親 exe の完全パスを emit (直接 deref、gate 有)"],
      "path_eq"          => [2, %w[file path_literal], "file の完全パスがリテラルと一致するか判定する述語 (式、gate 有、用途中立: deny/audit/routing 等 — 動作は handler の戻り値で決まり path_eq 自体は判定のみ)"],
      "path_starts_with" => [2, %w[file path_literal_prefix], "file の完全パスがリテラル prefix で始まるか判定する述語 (式、gate 有、用途中立: deny/audit/routing 等 — 動作は handler の戻り値で決まり path_starts_with 自体は判定のみ。長い path も PATH_MAX まで正しく照合する percpu scratch 版)"],
      "path_contains"    => [2, %w[file path_literal_substr], "file の完全パスにリテラルが部分文字列として現れるか判定する述語 (任意 offset、式、gate 有、用途中立: deny/audit/routing 等 — 動作は handler の戻り値で決まり path_contains 自体は判定のみ。bpf_loop で PATH_MAX 全体を sliding-window 探索する no-bypass 版)"],
      "parent_path_eq"   => [1, %w[path_literal],     "親 exe パスがリテラルと一致するか判定する述語 (式、gate 有、用途中立 — 動作は戻り値で決まる)"],
      "ppid"             => [0, [],                   "親 tgid (init-ns pid)"],
      # --- l7: HTTP / TLS / DNS span + L7 latency + off-CPU 相関 ---
      "http_req_start"   => [2, %w[sk msg],           "送信バッファを読み HTTP req なら sock キーで記録"],
      "http_resp_stash"  => [2, %w[sk msg],           "受信バッファを tid キーで stash"],
      "http_emit"        => [1, %w[ret],              "stash を読み sock で相関、HTTP span 1 本 emit"],
      "redis_req_start"  => [3, %w[sk msg size],      "送信バッファ (先頭 size B) を読み RESP コマンドなら sock キーで記録 (Redis L7 RED)"],
      "redis_resp_stash" => [2, %w[sk msg],           "受信バッファを tid キーで stash (Redis L7 RED)"],
      "redis_emit"       => [1, %w[ret],              "stash を読み sock で相関、Redis span 1 本 emit (command/-ERR/duration)"],
      "ssl_req_start"    => [2, %w[ssl buf],          "SSL_write の平文を読み HTTP なら SSL* キーで記録"],
      "ssl_resp_stash"   => [2, %w[ssl buf],          "SSL_read entry で buf を tid stash"],
      "ssl_emit"         => [1, %w[ret],              "復号後 buf を SSL* で相関、TLS 平文 span emit"],
      "go_tls_write"     => [3, %w[conn ptr len],     "Go crypto/tls.(*Conn).Write の平文 slice (ptr,len) を読み HTTP req span emit (uprobe、no sock -> https)"],
      "go_tls_req"       => [3, %w[conn ptr len],     "Go (*Conn).Write の平文を len-bound で読み http_pending に conn キーで stash (full RED の request 半分)"],
      "go_tls_resp_stash"=> [2, %w[conn ptr],         "Go (*Conn).Read entry で受信バッファを g レジスタ(ゴルーチン)キーで stash — tid はブロック Read で移行するため"],
      "go_tls_emit"      => [1, %w[ret],              "Go (*Conn).Read RET (go_uret) で g キー引当 → conn で request 相関 → full RED span emit"],
      "dns_req_start"    => [2, %w[sk msg],           "DNS query の相関開始"],
      "dns_resp_stash"   => [2, %w[sk msg],           "DNS 応答バッファを stash"],
      "dns_emit"         => [1, %w[ret],              "DNS span emit"],
      "emit_dns"         => [1, %w[msg],              "udp_sendmsg の :53 query を packed emit (resolver 非依存)"],
      "emit_tcp_payload" => [1, %w[msg],              "tcp_sendmsg の送信バッファ先頭 128B を str emit (L7 の userspace パース用、protocol 非依存)"],
      "emit_tcp_stream"  => [3, %w[sk msg size],      "tcp_sendmsg の送信バッファを sock キー付き packed record (sock,len,raw[128]) で emit — 多接続 stream 再組立用、userspace が sock で per-connection accumulate"],
      "req_start"        => [1, %w[sk],               "tcp_sendmsg で L7 往復の開始時刻を記録"],
      "emit_l7"          => [1, %w[sk],               "tcp_cleanup_rbuf で L7 往復レイテンシ span emit"],
      "offcpu_recv_stash"=> [2, %w[sk msg],           "HTTP req で tid の off-CPU 窓を開く (stash)"],
      "offcpu_begin"     => [1, %w[ret],              "off-CPU 窓 open (kretprobe)"],
      "offcpu_account"   => [3, %w[prev_pid prev_state next_pid], "窓中の voluntary off-CPU stack を積む"],
      "offcpu_emit"      => [2, %w[sk msg],           "窓を閉じ off-CPU 内訳付き span emit"],
      # --- net: connect / L4 / datapath / conntrack / arena / tcp slice ---
      "emit_connect"     => [7, %w[skaddr daddr dport family oldstate daddr6_hi daddr6_lo], "connect を 1 packed record で emit (process+peer+srtt)"],
      "sock_owner_set"   => [1, %w[sk],               "tcp_v4_connect で sock→{pid,comm} を記録 (softirq 復元)"],
      "blocklist_match"  => [1, %w[ip],               "ip が集合 (exact HASH map) に在るか判定する述語 (host order、用途中立: match→deny=blocklist / match→allow=allowlist は戻り値で決まる)。userspace で集合を seed: `module M` (class 不可) に `ffi_func :sp_bpf_blocklist_add, [:uint32], :int` を宣言し top-level で `M.sp_bpf_blocklist_add(0x0a000001)` (整数リテラル ip) を呼ぶ"],
      "cidr_blocklist_match" => [1, %w[ip],           "ip が CIDR 集合 (LPM_TRIE、longest-prefix) に在るか判定する述語 (host order、用途中立: blocklist/allowlist は戻り値で決まる)。userspace で集合を seed: `module M` (class 不可) に `ffi_func :sp_bpf_cidr_blocklist_add, [:uint32,:uint32], :int` を宣言し、top-level で `M.sp_bpf_cidr_blocklist_add(0x7f000000, 8)` (整数リテラルの ip, prefixlen) を呼ぶ。実行時に再呼出で動的更新 (`_del` も同型)"],
      "reuseport_hash"   => [0, [],                   "ctx->hash (kernel 5-tuple hash)"],
      "worker_select"    => [1, %w[idx],              "bpf_sk_select_reuseport で worker socket 選択"],
      "cpumap_redirect"  => [1, %w[cpu],              "CPUMAP に bpf_redirect_map"],
      "xsk_redirect"     => [1, %w[qid],              "XSKMAP に bpf_redirect_map (AF_XDP)"],
      "dev_redirect"     => [1, %w[idx],              "DEVMAP に bpf_redirect_map"],
      "tail_call_to"     => [1, %w[slot],             "PROG_ARRAY の slot に bpf_tail_call"],
      "sock_ops_op"      => [0, [],                   "ctx->op (sock_ops)"],
      "sock_ops_state"   => [0, [],                   "ctx->args[1] (sock_ops state)"],
      "sock_addr_ip4"    => [0, [],                   "connect4/bind4 の宛先 IPv4 (host order)"],
      "sock_addr_port"   => [0, [],                   "connect4/bind4 の宛先 port (host order)"],
      "iter_task"        => [0, [],                   "iter/task の現 task_struct* (__s64)"],
      "xdp_match_health" => [0, [],                   "XDP frame が GET /health か (M004)"],
      "xdp_reply_health" => [0, [],                   "XDP frame を 200 OK に書換え XDP_TX (M004)"],
      "pkt_dynptr_byte_at" => [1, %w[offset],         "dynptr で任意 offset の byte を verifier-safe に読む"],
      "fib_lookup"       => [1, %w[dst],              "IPv4 FIB 経路探索 (egress ifindex)"],
      "fib_lookup6"      => [2, %w[dst_hi dst_lo],    "IPv6 FIB 経路探索"],
      "sk_lookup_tcp"    => [4, %w[saddr daddr sport dport], "4-tuple から TCP socket を引く"],
      "sk_assign_tcp"    => [4, %w[saddr daddr sport dport], "sk_lookup → socket に steer"],
      "redirect"         => [1, %w[ifindex],          "bpf_redirect (L3 forwarding)"],
      "skb_load_byte"    => [1, %w[offset],           "skb から 1 byte 読取"],
      "skb_load_u16"     => [1, %w[offset],           "skb から u16 読取"],
      "skb_load_u32"     => [1, %w[offset],           "skb から u32 読取"],
      "skb_store_byte"   => [2, %w[offset value],     "skb に 1 byte 書込"],
      "skb_store_u16"    => [2, %w[offset value],     "skb に u16 書込"],
      "skb_store_u32"    => [2, %w[offset value],     "skb に u32 書込"],
      "l3_csum_replace"  => [3, %w[offset from to],   "L3 checksum 差分修復 (16bit)"],
      "l3_csum_replace_ip" => [3, %w[offset from to], "L3 checksum 差分修復 (32bit IP)"],
      "l4_csum_replace"  => [3, %w[offset from to],   "L4 checksum 差分修復 (16bit)"],
      "l4_csum_replace_ip" => [3, %w[offset from to], "L4 checksum 差分修復 (32bit、pseudo-hdr)"],
      "l4_offset"        => [0, [],                   "L4 開始 offset (14 + IHL*4、IP options 対応)"],
      "flow_get"         => [2, %w[map_name field],   "conntrack: 現フローの field を読む (symbol 引数)"],
      "flow_set"         => [3, %w[map_name field value], "conntrack: 現フローの field を書く (symbol 引数)"],
      "flow_del"         => [1, %w[map_name],         "conntrack: 現フローのエントリ削除 (symbol 引数)"],
      "tcp_syncookie_gen"=> [0, [],                   "raw SYN-cookie 生成 (xdp)"],
      "tcp_syncookie_check" => [0, [],                "raw SYN-cookie 検証 (xdp)"],
      "tcp_reply_header" => [3, %w[seq ack flags],    "パケットを header-only TCP reply に (xdp)"],
      "tcp_reply_synack" => [1, %w[cookie],           "SYN-ACK (MSS option 付き) を作る (xdp)"],
      "tcp_synack_cookie"=> [0, [],                   "SYN→SYN-ACK+cookie 統合 (xdp)"],
      "tcp_reply_data"   => [3, %w[seq ack payload_literal], "パケットを data response に (xdp、payload はリテラル)"],
      "payload_starts"   => [1, %w[prefix_literal],   "TCP payload が prefix で始まるか (xdp、compile-time)"],
      "queue_push"       => [2, %w[skb to_free],      "BPF list に skb を enqueue (qdisc)"],
      "queue_pop"        => [0, [],                   "BPF list から skb を dequeue (qdisc)"],
      "arena_set"        => [2, %w[index value],      "arena flat 配列に書く"],
      "arena_get"        => [1, %w[index],            "arena flat 配列を読む"],
      "arena_hash_set"   => [2, %w[key value],        "arena hash に書く"],
      "arena_hash_get"   => [1, %w[key],              "arena hash を読む"],
      "arena_hash_del"   => [1, %w[key],              "arena hash から削除"],
      "arena_list_push"  => [1, %w[value],            "arena linked list に push"],
      "arena_list_sum"   => [0, [],                   "arena linked list を集計"],
      # --- core: identity / cgroup / control channel ---
      "divu"             => [2, %w[a b],              "unsigned 64bit 除算 (signed div reject 回避)"],
      "i32"              => [1, %w[x],                "32bit kernel arg を切って符号拡張 (arm64 上位ゴミ対策)"],
      "pid"              => [0, [],                   "userspace 的 pid (tgid の上位32bit)"],
      "tgid"             => [0, [],                   "thread group id"],
      "tid"              => [0, [],                   "kernel thread id"],
      "cpu_id"           => [0, [],                   "bpf_get_smp_processor_id()"],
      "cgroup_id"        => [0, [],                   "現 cgroup id (kernfs inode、k8s pod 相関の鍵)"],
      "field_exists"     => [3, %w[ptr struct field], "BTF に struct.field があるか (CO-RE)"],
      "user_ringbuf_drain" => [0, [],                 "USER_RINGBUF を drain (host→kernel command)"],
    }.freeze

    # 全 builtin の signature を組み立てる (SIG_TABLE + 構造生成)。
    SIGNATURES = begin
      sigs = {}
      SIG_TABLE.each do |name, (arity, params, summary)|
        sigs[name] = { arity: arity, params: params, opaque: params.nil?, summary: summary }.freeze
      end
      PKT_FIELD_BUILTINS.each do |name|
        field = name.sub(/\Apkt_/, "")
        sigs[name] = { arity: 0, params: [], opaque: false,
                       summary: "packet field #{field} (xdp/tc, host order)" }.freeze
      end
      TCP_SOCK_READER_BUILTINS.each do |name|
        f = name.sub(/\Atcp_sock_/, "")
        sigs[name] = { arity: 1, params: %w[sk], opaque: false,
                       summary: "read tcp_sock->#{f} (tcp_cc)" }.freeze
      end
      TCP_SOCK_WRITER_BUILTINS.each do |name|
        f = name.sub(/\Atcp_sock_/, "").sub(/_set\z/, "")
        sigs[name] = { arity: 2, params: %w[sk value], opaque: false,
                       summary: "set tcp_sock->#{f} (tcp_cc)" }.freeze
      end
      TCP_SOCK_ADDER_BUILTINS.each do |name|
        f = name.sub(/\Atcp_sock_/, "").sub(/_add\z/, "")
        sigs[name] = { arity: 2, params: %w[sk delta], opaque: false,
                       summary: "tcp_sock->#{f} += delta (tcp_cc)" }.freeze
      end
      # opaque kfunc: arity は codegen の kfunc table から既知、Ruby 側 param 名は
      # struct_ops member シグネチャ由来で機械的に取れない ⇒ 正直に opaque。
      { "scx_dispatch" => 4, "scx_consume" => 1, "scx_kick_cpu" => 2,
        "scx_pick_idle_cpu" => 2, "scx_create_dsq" => 2,
        "qdisc_skb_drop" => 2, "qdisc_init_prologue" => 2,
        "qdisc_reset_destroy_epilogue" => 1, "qdisc_watchdog_schedule" => 3,
        "qdisc_bstats_update" => 2 }.each do |name, arity|
        sigs[name] = { arity: arity, params: nil, opaque: true,
                       summary: "kfunc passthrough (kernel struct ptr を struct_ops member から渡す)" }.freeze
      end
      sigs.freeze
    end

    # builtin -> context 要件 (codegen が compile 時 die で強制する hook)。
    #   { secs: [SEC...] }   d_path gate
    #   { kinds: [attach kind...] }  attach-kind gate
    # 無い builtin は codegen 非強制 (best-effort の context_note を付ける)。
    CONTEXT_REQUIREMENTS = begin
      reqs = {
        "emit_path"        => { secs: DPATH_OK_SECS },
        "emit_parent_path" => { secs: DPATH_OK_SECS },
        "path_eq"          => { secs: DPATH_OK_SECS },
        "path_starts_with" => { secs: DPATH_OK_SECS },
        "path_contains"    => { secs: DPATH_OK_SECS },
        "parent_path_eq"   => { secs: DPATH_OK_SECS },
        "reuseport_hash"   => { kinds: %i[sk_reuseport] },
        "worker_select"    => { kinds: %i[sk_reuseport] },
        "xdp_match_health" => { kinds: %i[xdp] },
        "xdp_reply_health" => { kinds: %i[xdp] },
        "pkt_dynptr_byte_at" => { kinds: %i[xdp] },
        "cpumap_redirect"  => { kinds: %i[xdp xdp_tail] },
        "xsk_redirect"     => { kinds: %i[xdp xdp_tail] },
        "dev_redirect"     => { kinds: %i[xdp xdp_tail] },
        "tail_call_to"     => { kinds: %i[xdp xdp_tail] },
        "sock_ops_op"      => { kinds: %i[sock_ops] },
        "sock_ops_state"   => { kinds: %i[sock_ops] },
        "sock_addr_ip4"    => { kinds: %i[cgroup_connect4 cgroup_bind4] },
        "sock_addr_port"   => { kinds: %i[cgroup_connect4 cgroup_bind4] },
        "iter_task"        => { kinds: %i[iter_task] },
        "tcp_syncookie_gen" => { kinds: %i[xdp] },
        "tcp_syncookie_check" => { kinds: %i[xdp] },
        "tcp_reply_header" => { kinds: %i[xdp] },
        "tcp_reply_synack" => { kinds: %i[xdp] },
        "tcp_synack_cookie" => { kinds: %i[xdp] },
        "tcp_reply_data"   => { kinds: %i[xdp] },
        "payload_starts"   => { kinds: %i[xdp] },
        "flow_get"         => { kinds: %i[xdp tc_ingress tc_egress] },
        "flow_set"         => { kinds: %i[xdp tc_ingress tc_egress] },
        "flow_del"         => { kinds: %i[xdp tc_ingress tc_egress] },
      }
      PKT_FIELD_BUILTINS.each { |b| reqs[b] = { kinds: %i[xdp tc_ingress tc_egress] } }
      (TCP_SOCK_READER_BUILTINS + TCP_SOCK_WRITER_BUILTINS + TCP_SOCK_ADDER_BUILTINS)
        .each { |b| reqs[b] = { kinds: %i[tcp_cc] } }
      %w[scx_dispatch scx_consume scx_kick_cpu scx_pick_idle_cpu scx_create_dsq]
        .each { |b| reqs[b] = { kinds: %i[sched_ext] } }
      %w[qdisc_skb_drop qdisc_init_prologue qdisc_reset_destroy_epilogue
         qdisc_watchdog_schedule qdisc_bstats_update]
        .each { |b| reqs[b] = { kinds: %i[qdisc] } }
      reqs.each_value(&:freeze)
      reqs.freeze
    end

    # 非 gate builtin の best-effort context note (codegen は強制しない)。
    DOMAIN_CONTEXT_NOTE = {
      observability: "process-context probe (kprobe/kretprobe/tracepoint/fentry/fexit/perf_event/uprobe/usdt); codegen 非強制",
      enforcement:   "process-context security hook; codegen 非強制",
      net:           "packet/socket datapath prog (xdp/tc/sk_*); codegen 非強制",
      l7:            "tcp_*/SSL_* を狙う process-context kprobe/uprobe; codegen 非強制",
      core:          "任意の :ebpf method; codegen 非強制",
    }.freeze

    # builtin 別の context_note override (domain note が family に不正確なとき、E325)。
    # DNS builtin は l7 domain に属すが transport は **UDP (:53)** — canonical hook は
    # udp_sendmsg/udp_recvmsg。l7 domain の "tcp_*/SSL_*" は DNS には**積極的な誤誘導**
    # (E325 再検証で author-agent が指摘、emit_dns の summary は既に udp_sendmsg と整合)。
    # designed contract の canonical hook を bounded に名指す (全 kernel catalog ではなく、
    # この family の意図された hook だけ)。dns_correct.rb の実 hook に忠実。
    CONTEXT_NOTE_OVERRIDES = {
      "dns_req_start"  => "kprobe/udp_sendmsg (:53 query の送信時に相関開始); process-context; codegen 非強制",
      "dns_resp_stash" => "kprobe/udp_recvmsg entry (応答バッファを stash、コピー後は kretprobe); process-context; codegen 非強制",
      "dns_emit"       => "kretprobe/udp_recvmsg (応答を相関して span emit); process-context; codegen 非強制",
      "emit_dns"       => "kprobe/udp_sendmsg (:53 query を packed emit、resolver 非依存); process-context; codegen 非強制",
    }.freeze

    # ===================================================================
    # E322 (ADR-015 投資優先(a)、E321 GAP を畳む): 呼び出しコード例 + 関連 builtin。
    #
    # E321 の clean-room テストは affordance を「打てる手のカタログ」として十分と実証したが、
    # AI が prior knowledge で補った 2 GAP を残した:
    #   GAP-1: builtin ごとの Ruby コード例が皆無 (署名カードのみで呼び出し構文の見本が 0)。
    #   GAP-2: 関連 builtin の暗黙の関係が不明 (pid/tgid/tid のどれが process 粒度か等)。
    # E322 はこの 2 点だけを affordance に足す。
    #
    # 線引き (ADR-015 の thesis: affordance はブリッジ/ABI/合法性、意味論=ロジックは AI):
    #   * example は **構文見本 1 行** であって「使い方の指南」ではない。閾値の選び方・
    #     アルゴリズムの類は載せない (それは Ruby ロジック = AI の領分)。
    #   * related の note も「どれが process 粒度か・対か・ファミリか」という **選択に必要な
    #     事実 1 行** に留め、「いつ使うか」は書かない。
    # ===================================================================

    # 呼び出しコード例 (GAP-1)。原則は機械生成 (下の example_for):
    #   * arity N (params 判明) -> `name(p1, p2, ...)` (params を placeholder に構文を見せる)。
    #   * arity 0             -> `name` (bare 呼出。実 idiom の dominant 形、括弧不要を見せる)。
    #   * opaque kfunc (params 不明) -> nil (嘘の例より省略。opaque と同じ正直さ)。
    # 手書きが要るのは params 名だけでは正しい構文にならない builtin だけ:
    #   symbol 引数 (flow_*)、compile-time string リテラル引数 (path_eq/parent_path_eq/
    #   payload_starts/tcp_reply_data)、struct 名 string 引数 (kfield/kptr/field_exists)。
    EXAMPLE_OVERRIDES = {
      # conntrack: map 名と field を symbol で渡す
      "flow_get"       => "flow_get(:conn, :backend_ip)",
      "flow_set"       => "flow_set(:conn, :state, 1)",
      "flow_del"       => "flow_del(:conn)",
      # CO-RE: struct 名 + field 名を string で渡す
      "kfield"         => 'kfield(sk, "sock", "sk_sndbuf")',
      "kptr"           => 'kptr(sk, "sock")',
      "field_exists"   => 'field_exists(sk, "tcp_sock", "bytes_acked")',
      # compile-time string リテラル引数 (AOT がバイト列を unroll、E287/E053)
      "path_eq"        => 'path_eq(file, "/usr/bin/curl")',
      "path_starts_with" => 'path_starts_with(file, "/etc/secret/")',
      "path_contains"  => 'path_contains(file, "/.ssh/")',
      "parent_path_eq" => 'parent_path_eq("/usr/bin/curl")',
      "payload_starts" => 'payload_starts("GET ")',
      "tcp_reply_data" => 'tcp_reply_data(seq, ack, "HTTP/1.0 200 OK")',
    }.freeze

    # 関連 builtin のクロスリンク (GAP-2)。各グループ = {name, members, note}。
    # related: (builtin ごとの相互リンク) はここから導出する (単一の権威、related_for)。
    # note は選択に必要な事実 1 行 (粒度/対/ファミリ) に留める (「いつ使うか」は書かない)。
    # 多フック必須組 (http/ssl/dns/offcpu span 等) は REQUIRED_SETS が持つので重複させない
    # (l7_roundtrip だけは E321 が「対」と名指したので載せ、required_sets を xref する)。
    BUILTIN_GROUPS = [
      { name: "process_thread_identity",
        members: %w[pid tgid tid],
        note: "pid()==tgid()=プロセス粒度 (bpf_get_current_pid_tgid の上位32bit); tid()=スレッド粒度 (下位32bit)。グルーピングのキーを process/thread どちらの粒度にするかで選ぶ。" }.freeze,
      { name: "latency_tid_pair",
        members: %w[latency_start latency_end],
        note: "tid キーの BEGIN/END 対。start=entry ktime 記録 (kprobe)、end=delta ns 返却+削除 (kretprobe)。対で使う。" }.freeze,
      { name: "latency_keyed_pair",
        members: %w[lat_start lat_end],
        note: "任意キーの BEGIN/END 対 (latency_start/end の key 指定版)。" }.freeze,
      { name: "histogram",
        members: %w[hist_observe hist_observe_by hist_observe_linear],
        note: "log2 hist の 3 形: hist_observe=無キー / hist_observe_by=keyed(key,value) / hist_observe_linear=caller が pre-bucket した slot。" }.freeze,
      { name: "str_emit",
        members: %w[emit_comm emit_path emit_parent_path emit_argv spnl_emit_str],
        note: "str ringbuf への emit: comm / 完全パス(gate 有) / 親 exe パス(gate 有) / argv / 任意 user ptr の文字列。" }.freeze,
      { name: "scalar_emit",
        members: %w[spnl_emit spnl_emit_pair spnl_emit3 spnl_emit4],
        note: "スカラ ringbuf emit: 1 event に 1/2/3/4 値 (共通 16B hdr)。" }.freeze,
      { name: "stack_trace",
        members: %w[stack_id user_stack_id],
        note: "STACK_TRACE map の id: stack_id=kernel スタック / user_stack_id=user スタック。" }.freeze,
      { name: "off_cpu_profile",
        members: %w[off_cpu_start off_cpu_observe],
        note: "off-CPU プロファイル対: start=sched_switch で ktime+stack を stash、observe=復帰時に delta を keyed hist へ。多フック span の offcpu_* とは別物。" }.freeze,
      { name: "task_storage",
        members: %w[task_load task_store task_incr task_swap],
        note: "per-task storage: load/store/incr(RMW)/swap。task 終了で自動解放、明示 key 不要。" }.freeze,
      { name: "l7_roundtrip",
        members: %w[req_start emit_l7],
        note: "L7 往復レイテンシの対: req_start=sendmsg で開始時刻記録、emit_l7=cleanup_rbuf で往復 span emit。必須組は required_sets.l7_latency 参照。" }.freeze,
      { name: "pkt_fields",
        members: PKT_FIELD_BUILTINS,
        note: "XDP/TC の packet field accessor (0 引数、host order)。pkt.l4.proto 等の pkt.* chain accessor でも同じ値。" }.freeze,
      { name: "tcp_sock_accessors",
        members: (TCP_SOCK_READER_BUILTINS + TCP_SOCK_WRITER_BUILTINS + TCP_SOCK_ADDER_BUILTINS),
        note: "tcp_cc context の tcp_sock フィールド: reader(sk) / writer(sk,value)_set / adder(sk,delta)_add。sk.snd_cwnd 等の dot accessor でも同じ。" }.freeze,
      { name: "arena",
        members: %w[arena_set arena_get arena_hash_set arena_hash_get arena_hash_del arena_list_push arena_list_sum],
        note: "bpf_arena 共有メモリのデータ構造: flat 配列(set/get) / hash(set/get/del) / linked list(push/sum)。userspace と mmap 共有。" }.freeze,
      { name: "skb_rewrite",
        members: %w[skb_load_byte skb_load_u16 skb_load_u32 skb_store_byte skb_store_u16 skb_store_u32 l3_csum_replace l3_csum_replace_ip l4_csum_replace l4_csum_replace_ip l4_offset],
        note: "TC の skb 読み書き + checksum 修復: load/store(byte/u16/u32) + l3/l4_csum_replace(_ip) + l4_offset(L4 開始位置、IP options 対応)。NAT の部品。" }.freeze,
    ].freeze

    # attach-kind の作法一覧。codegen の ATTACH_PATTERNS と 1:1 (kind 集合の一致は
    # capabilities_test.rb が機械強制)。args_convention = 宣言 param がどの ABI で
    # attach context から取り出されるか (codegen の extract_attach_args)。
    ATTACH_KINDS = [
      { kind: :kprobe,        method_prefix: "kprobe__<func>",           sec: "kprobe/<func>",         ctx_type: "struct pt_regs *", args_convention: "PT_REGS_PARM<N>(ctx) — kernel func 引数 (BTF で名前解決)", context_note: "kernel 関数の entry" },
      { kind: :kretprobe,     method_prefix: "kretprobe__<func>",        sec: "kretprobe/<func>",      ctx_type: "struct pt_regs *", args_convention: "単一 param = 戻り値 (PT_REGS_RC)", context_note: "kernel 関数の return" },
      { kind: :uprobe,        method_prefix: "uprobe__<func>",           sec: "uprobe",                ctx_type: "struct pt_regs *", args_convention: "PT_REGS_PARM<N>(ctx); target binary/pid は env (SPNL_UPROBE_*)", context_note: "userspace 関数 entry" },
      { kind: :uretprobe,     method_prefix: "uretprobe__<func>",        sec: "uretprobe",             ctx_type: "struct pt_regs *", args_convention: "ret param; target は env (SPNL_UPROBE_*)", context_note: "userspace 関数 return" },
      { kind: :usdt,          method_prefix: "usdt__<provider>__<probe>", sec: "usdt",                 ctx_type: "struct pt_regs *", args_convention: "bpf_usdt_arg(ctx, i, &v); target は env (SPNL_USDT_*)", context_note: "USDT static probe" },
      { kind: :tracepoint,    method_prefix: "tracepoint__<cat>__<event>", sec: "tracepoint/<cat>/<event>", ctx_type: "void *", args_convention: "syscalls: 位置引数 ctx->args[i]; named-field TP: param 名→struct field", context_note: "kernel tracepoint" },
      { kind: :fentry,        method_prefix: "fentry__<func>",           sec: "fentry/<func>",         ctx_type: "__u64 *", args_convention: "ctx[i] = func 引数 (BTF で名前解決)", context_note: "BPF trampoline entry (~50ns)" },
      { kind: :fexit,         method_prefix: "fexit__<func>",            sec: "fexit/<func>",          ctx_type: "__u64 *", args_convention: "ctx[i] = func 引数、末尾 param = 戻り値", context_note: "BPF trampoline exit" },
      { kind: :lsm,           method_prefix: "lsm__<hook>",              sec: "lsm/<hook>",            ctx_type: "__u64 *", args_convention: "ctx[i] = hook 引数、末尾 param = prior verdict", context_note: "LSM security hook; deny=負 errno / allow=末尾 param (prior verdict) を返す — リテラル 0 で上書きしない (prior deny を保持し、path_eq gate 併用時に allow へリテラル定数を返すと起きる verifier state 爆発 (E328、1M insn) も回避)。⚠ enforcement には boot cmdline に bpf 必須 (lsm=…,bpf)。無いと attach 成功しても発火しない silent no-op → 環境非依存の deny は fmod_ret/security_* を使う" },
      { kind: :fmod_ret,      method_prefix: "fmod_ret__<func>",         sec: "fmod_ret/<func>",       ctx_type: "__u64 *", args_convention: "ctx[i] = func 引数、末尾 param = ret。handler の arity は hook 関数の引数数+1 (ret)。例: security_file_open は file 1 引数なので `def fmod_ret__security_file_open(file, ret)`", context_note: "BPF_MODIFY_RETURN; 対象関数の ret を置換 (deny=負 errno / allow=末尾 param の ret を返す)。security_* に attach すれば boot の lsm= 設定に依存しない portable な deny (lsm hook の silent no-op を回避、E328) = enforcement deny の既定" },
      { kind: :user_ringbuf,  method_prefix: "user_ringbuf__<name>(value)", sec: "(callback、SEC 無し)", ctx_type: nil, args_convention: "value = drain された 1 record", context_note: "USER_RINGBUF drain callback (host→kernel)" },
      { kind: :sock_ops,      method_prefix: "sock_ops__<name>",         sec: "sockops",               ctx_type: "struct bpf_sock_ops *", args_convention: "宣言 param 無し; sock_ops_op/sock_ops_state で ctx 読取", context_note: "TCP state 観測; cgroup attach ($SPNL_CGROUP_PATH)" },
      { kind: :cgroup_connect4, method_prefix: "cgroup__connect4__<name>", sec: "cgroup/connect4",     ctx_type: "struct bpf_sock_addr *", args_convention: "宣言 param 無し; sock_addr_ip4/sock_addr_port で ctx 読取", context_note: "outbound connect 制御; 戻り 1=allow/0=deny" },
      { kind: :cgroup_bind4,  method_prefix: "cgroup__bind4__<name>",    sec: "cgroup/bind4",          ctx_type: "struct bpf_sock_addr *", args_convention: "宣言 param 無し; sock_addr_* で ctx 読取", context_note: "bind 制御; 戻り 1=allow/0=deny" },
      { kind: :iter_task,     method_prefix: "iter__task__<name>",       sec: "iter/task",             ctx_type: "struct bpf_iter__task *", args_convention: "宣言 param 無し; iter_task() で task ptr", context_note: "task 列挙; userspace 駆動 (glue create+read)" },
      { kind: :raw_tp,        method_prefix: "raw_tp__<event>",          sec: "raw_tp/<event>",        ctx_type: "struct bpf_raw_tracepoint_args *", args_convention: "ctx->args[i]", context_note: "raw tracepoint (低 overhead)" },
      { kind: :socket_filter, method_prefix: "socket_filter__<name>",    sec: "socket",                ctx_type: "struct __sk_buff *", args_convention: "宣言 param 無し", context_note: "classic SO_ATTACH_BPF; 戻り=保持バイト数" },
      { kind: :flow_dissector, method_prefix: "flow_dissector__<name>",  sec: "flow_dissector",        ctx_type: "struct __sk_buff *", args_convention: "宣言 param 無し", context_note: "戻り BPF_OK/BPF_DROP" },
      { kind: :sk_lookup,     method_prefix: "sk_lookup__<name>",        sec: "sk_lookup",             ctx_type: "struct bpf_sk_lookup *", args_convention: "宣言 param 無し", context_note: "listener 選択; SEC は sub-name 不可; 戻り SK_PASS/SK_DROP" },
      { kind: :tcp_cc,        method_prefix: "class <N> < BPF::TcpCC (def <member>)", sec: "struct_ops/<member>",   ctx_type: nil, args_convention: "struct_ops は class 継承 (`class N < BPF::TcpCC` + `def init(sk)`/`def cong_avoid(sk,ack,acked)` 等) 推奨 — Ruby 正解形。flat `def tcp_cc__<member>` でも register する (E330-2)。member 引数 (sk 等) を __s64 で受け tcp_sock_* builtin (sk.snd_cwnd 等の dot accessor も可、E330) で読み書き", context_note: "struct_ops/tcp_congestion_ops member。class 継承推奨 (flat も可)" },
      { kind: :sched_ext,     method_prefix: "class <N> < BPF::SchedExt (def <member>)", sec: "struct_ops/<member>", ctx_type: nil, args_convention: "struct_ops は class 継承 (`class N < BPF::SchedExt` + `def <member>`) 推奨。flat `def sched_ext__<member>` でも register する (E330-2)。member 引数 (task 等) を __s64 で受け scx_* builtin に渡す", context_note: "struct_ops/sched_ext_ops member (CPU scheduler)。class 継承推奨 (flat も可)" },
      { kind: :qdisc,         method_prefix: "class <N> < BPF::Qdisc (def <member>)", sec: "struct_ops/<member>",   ctx_type: nil, args_convention: "struct_ops は class 継承 (`class N < BPF::Qdisc` + `def <member>`) 推奨。flat `def qdisc__<member>` でも register する (E330-2)。必須 member と signature: init(sch,opt,extack) / enqueue(skb,sch,to_free) / dequeue(sch) / reset(sch) / destroy(sch)。⚠ enqueue は skb ref を必ず解放する — drop なら qdisc_skb_drop(skb,to_free)、転送なら queue_push(skb,to_free)。解放しないと verifier が reference leak で reject", context_note: "struct_ops/Qdisc_ops member (tc 経由で spnl_qdisc として attach)。class 継承推奨 (flat も可)" },
      { kind: :xdp_tcp_slice, method_prefix: "xdp__tcp_slice__<name>",   sec: "xdp",                   ctx_type: "struct xdp_md *", args_convention: "body は marker (state machine を自動生成)", context_note: "pure-XDP TCP slice (M004、xdp__ より優先)" },
      { kind: :xdp_tail,      method_prefix: "xdp_tail__<name>",         sec: "xdp",                   ctx_type: "struct xdp_md *", args_convention: "宣言 param 無し; pkt_*/tail_call_to", context_note: "tail-callable sub-prog; auto-attach せず PROG_ARRAY slot" },
      { kind: :xdp,           method_prefix: "xdp__<name>",              sec: "xdp",                   ctx_type: "struct xdp_md *", args_convention: "宣言 param 無し; pkt_*/pkt.* builtin", context_note: "戻り XDP_PASS/DROP/TX/REDIRECT; env SPNL_XDP_IFACE" },
      { kind: :tc_ingress,    method_prefix: "tc__ingress__<name>",      sec: "tcx/ingress",           ctx_type: "struct __sk_buff *", args_convention: "宣言 param 無し; pkt_*/skb_* builtin", context_note: "戻り TC_ACT_*; env SPNL_TCX_IFACE" },
      { kind: :tc_egress,     method_prefix: "tc__egress__<name>",       sec: "tcx/egress",            ctx_type: "struct __sk_buff *", args_convention: "宣言 param 無し; pkt_*/skb_* builtin", context_note: "戻り TC_ACT_*; env SPNL_TCX_IFACE" },
      { kind: :sk_reuseport,  method_prefix: "sk_reuseport__<name>",     sec: "sk_reuseport",          ctx_type: "struct sk_reuseport_md *", args_convention: "宣言 param 無し; reuseport_hash/worker_select", context_note: "SO_REUSEPORT 選択; 戻り SK_PASS/SK_DROP" },
      { kind: :sk_msg,        method_prefix: "sk_msg__<name>",           sec: "sk_msg",                ctx_type: "struct sk_msg_md *", args_convention: "宣言 param 無し", context_note: "sockmap; BPF_SK_MSG_VERDICT で attach" },
      { kind: :sk_skb_verdict, method_prefix: "sk_skb__verdict__<name>", sec: "sk_skb/stream_verdict", ctx_type: "struct __sk_buff *", args_convention: "宣言 param 無し", context_note: "sockmap stream verdict" },
      { kind: :sk_skb_parser, method_prefix: "sk_skb__parser__<name>",   sec: "sk_skb/stream_parser",  ctx_type: "struct __sk_buff *", args_convention: "宣言 param 無し", context_note: "sockmap stream parser" },
      { kind: :timer,         method_prefix: "on :timer, every: N.<unit> (spnl_timer__<name>)", sec: "syscall", ctx_type: "void *", args_convention: "宣言 param 無し (周期コールバック)", context_note: "bpf_timer; DSL 合成、glue が load 時に arm" },
      { kind: :perf_event,    method_prefix: "perf_event__<name> / on :perf_event, hz: N", sec: "perf_event", ctx_type: "struct bpf_perf_event_data *", args_convention: "宣言 param 無し; stack_id() と組む", context_note: "per-CPU sampling profiler" },
    ].freeze

    # Ruby サブセット (書ける/書けない)。rejected は partition の loud-failure
    # (即エラー) を写像 — flag 名は partition.rb の MethodFlags と一致 (test が守る)。
    RUBY_SUBSET = {
      supported: [
        "Integer リテラル / 算術 (+ - * / %) / 比較 (== != < > <= >=)",
        "Integer リテラルの underscore 区切り (5_000_000 == 5000000、可読性のみ、値は不変) (E320/E319 GAP-4)",
        "if / elsif / else (式値も) / boolean 短絡 (|| &&) / bitwise (& | ^ << >>) / 括弧",
        "ローカル変数 / method 定義・引数・戻り値 / BPF-to-BPF call",
        "n.times { |i| ... } (closure capture 含む; literal N は open-coded、動的 N は bpf_loop)",
        "インスタンス変数 (int) / top-level ivar → per-unit HASH map (@x += n / @x = n)",
        "attach: def <prefix>__<name> (kprobe/tracepoint/xdp/tc/lsm/fmod_ret/... 上記 attach_kinds)",
        "attach ハンドラの引数宣言は 0..N 個 — 使わない kernel 関数引数は宣言省略可 (0 引数 kprobe も合法)、宣言分は args_convention (PT_REGS_PARM<N>/ctx[i]) に位置写像 (E320/E319 GAP-3)",
        "class 継承 (class C < BPF::XDP) / module + include (BPF::TcpCC) / reactor DSL (include BPF::EventLoop; on :kind)",
        "module-style 定数 (XDP::PASS / IP::Proto::TCP 等) + KNOWN_CONSTANTS の整数解決",
        "160 builtin 呼出 (上記 builtins registry; flat 名のまま)",
        "固定 (compile-time) String リテラル比較 (path_eq / payload_starts / tcp_reply_data 等)",
        "kfield/kptr の kernel field 読取 + dot accessor (sk.snd_cwnd / pkt.l4.proto chain)",
        "binary-safe FFI (:binstr、NUL 安全) — WebSocket 等を Ruby で",
      ].freeze,
      # 各 flag は partition.rb MethodFlags の impossible flag に対応 (loud failure = 即エラー)。
      rejected: [
        { flag: :uses_float,               construct: "Float 演算",            reason: "no FPU in BPF" },
        { flag: :uses_regex,               construct: "正規表現",              reason: "no regex helper in BPF" },
        { flag: :uses_io,                  construct: "任意の I/O",            reason: "host 側のみ" },
        { flag: :uses_thread,              construct: "Thread 生成",           reason: "kernel は thread を作れない" },
        { flag: :uses_fiber,               construct: "Fiber",                 reason: "BPF に fiber 概念なし" },
        { flag: :uses_closure,             construct: "非対応 closure (outer 捕捉)", reason: "n.times 以外の一般 closure" },
        { flag: :uses_recursion,           construct: "再帰呼び出し",          reason: "BPF call graph は DAG" },
        { flag: :uses_bignum,              construct: "bignum",                reason: "BPF integer は 64bit 上限" },
        { flag: :uses_unbounded_loop,      construct: "上限なしループ",        reason: "verifier がループ上限を要求" },
        { flag: :uses_unsupported_type,    construct: "非 int 型シグネチャ (string/array/hash/...)", reason: "eBPF 適格は int 系のみ" },
      ].freeze,
      note: "partition 失敗は即エラー (silent fallback 無し、ADR-003)。inherits_unsupported は上記を呼ぶ method に伝播。",
    }.freeze

    # 層2 enricher (参考、ADR-014 層2 / E313-E315)。probe (.rb) を **変えず** に
    # runtime が env-gate で属性を足す。AI は「pod 帰属は probe でなく env で付く」を読める。
    ENRICHERS = [
      { name: "k8s",  experiment: "E304", layer: 2, signal_scope: "all",
        attributes: %w[k8s.pod.name k8s.namespace.name k8s.pod.uid k8s.container.name],
        gate: "cgroup_id() builtin + kubepods cgroup 解決 (env)",
        note: "probe 無変更で pod 帰属が付く (未設定なら no-op)" },
      { name: "cri",  experiment: "E315", layer: 2, signal_scope: "all",
        attributes: %w[k8s.container.name],
        gate: "CRIMAP (env)",
        note: "container id → 実 container 名で上書き (last-writer-wins; 未設定なら no-op)" },
      { name: "peer", experiment: "E310", layer: 2, signal_scope: "conn",
        attributes: %w[peer.address peer.pod peer.service peer.external],
        gate: "宛先 IP 解決 (env)",
        note: "conn span のみ (宛先アドレスを持つ経路)" },
    ].freeze

    # ===================================================================
    # E317 (ADR-015 原則2「loud failure」+ 投資優先(b)): 必須組 (multi-hook)
    # の contract。
    #
    # いくつかの builtin は **単独では意味を持たず**、相方 (別 SEC の別メソッド)
    # と組んで初めて 1 本の span を生む。片方だけ書くと **silent に壊れた program**
    # になる (record を貯めるが誰も読まない → span が出ない、exit 0)。これは
    # ADR-015 原則2 に反する最悪ケース。ここに contract を **純データ**で持ち、
    #   * compile 時の loud 検査 (SpinelEbpf::Validate) がこれを参照して落とす、
    #   * E316 affordance (`--json` の `required_sets`) にも載る (相方が読める)、
    # を両立する。E316 残課題「組み合わせ recipe」への回答。
    #
    # mode:
    #   :all      -- members のどれか 1 つでも使えば **全員** 必須 (相互依存)。
    #   :requires -- trigger を使ったら requires を **全部** 必須 (一方向)。
    #                相方は trigger 無しでも単独で valid (後方互換)。
    #
    # 契約は実測に忠実 (2 軸ハーネス: 締めすぎない):
    #   * emit_connect / emit_dns は **単独で valid** ⇒ ここに載せない。
    #   * sock_owner_set は emit_connect が読む相方が無いと無意味 ⇒ 一方向 requires。
    #   examples/observability/otlp/ の完全 probe は全て本契約を満たす (E317 で実測)。
    #
    # E325 (ADR-015 原則「穴はハーネスに畳み込む」): span を生む組には **もう半分**
    # がある。上の members は **kernel 側 builtin** で、これらは span record を map に
    # **貯めるだけ**。userspace が `ffi_func` 宣言 + drain ループ (`Otlp.<push>(endpoint)`)
    # を書いて初めて OTLP に export される。この userspace-export 半分が affordance から
    # **完全に不可視**だったため (E325: 2 モデルが正しい kernel probe を書いたが drain を
    # 落とし → compile+verify は green でも span 0 本 = thesis が消したはずの kernel/userspace
    # ブリッジ bug class の再来)。各 span 組に `userspace_export` companion を **純データ**で
    # 載せ、相方 FFI 名と drain-loop の **構文見本** (interval は author が決める、
    # E322 の「構文見本に留めロジック指南はしない」) を読めるようにする。push 関数の実体は
    # bin/spinel-ebpf で定義 (全て `[:str], :int` = endpoint のみ)。
    # endpoint は **env `OTLP_ENDPOINT` を読むのが harness 慣行** (E327: 裸の placeholder
    # だと author が hardcode してポート違いで 0 span → env-fallback を pattern で教える。
    # 値の決定はなお author/env の仕事 = ロジック指南ではなく可搬性の構文)。
    REQUIRED_SETS = [
      { name: "http_span", mode: :all, experiment: "E298",
        members: %w[http_req_start http_resp_stash http_emit],
        why: "req が http_pending に記録し、resp_stash が受信バッファを stash、emit が相関して span 化する。1 つでも欠けると span が出ない。",
        userspace_export: {
          fn: "spnl_otlp_http_span_push",
          ffi_decl: "ffi_func :spnl_otlp_http_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_http_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_http_span_push(ep) }",
          why: "kernel builtin は span record を map に貯めるだけ。userspace が この FFI で drain して初めて OTLP に export される。書かないと compile+verify は green でも span 0 本。",
        }.freeze }.freeze,
      { name: "redis_span", mode: :all, experiment: "E341",
        members: %w[redis_req_start redis_resp_stash redis_emit],
        why: "req が redis_pending に記録し、resp_stash が受信バッファを stash、emit が相関して span 化する (db.system=redis, command/-ERR/duration)。1 つでも欠けると span が出ない。",
        userspace_export: {
          fn: "spnl_otlp_redis_span_push",
          ffi_decl: "ffi_func :spnl_otlp_redis_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_redis_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_redis_span_push(ep) }",
          why: "kernel builtin は span record を map に貯めるだけ。userspace が この FFI で drain して初めて OTLP に export される。書かないと compile+verify は green でも span 0 本。",
        }.freeze }.freeze,
      { name: "ssl_span", mode: :all, experiment: "E299",
        members: %w[ssl_req_start ssl_resp_stash ssl_emit],
        why: "SSL 平文の req/resp/emit の 3 フックで 1 span。欠けると平文 span が出ない。",
        userspace_export: {
          fn: "spnl_otlp_http_span_push",
          ffi_decl: "ffi_func :spnl_otlp_http_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_http_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_http_span_push(ep) }",
          why: "E299 は E298 の HTTP push を再利用 (専用 ssl push は無い)。kernel builtin は span record を map に貯めるだけで、この FFI で drain して初めて OTLP に export される。書かないと compile+verify は green でも span 0 本。",
        }.freeze }.freeze,
      { name: "dns_span", mode: :all, experiment: "E295",
        members: %w[dns_req_start dns_resp_stash dns_emit],
        why: "DNS の相関 req/resp/emit の 3 フックで 1 span (latency 付き)。",
        userspace_export: {
          fn: "spnl_otlp_dns_span_push",
          ffi_decl: "ffi_func :spnl_otlp_dns_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_dns_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_dns_span_push(ep) }",
          why: "kernel builtin は span record を map に貯めるだけ。userspace が この FFI で drain して初めて OTLP に export される。書かないと compile+verify は green でも span 0 本。",
        }.freeze }.freeze,
      { name: "l7_latency", mode: :all, experiment: "E297",
        members: %w[req_start emit_l7],
        why: "req_start が送信時刻を記録し、emit_l7 が往復レイテンシを読んで span 化する。片方では duration が出ない。",
        userspace_export: {
          fn: "spnl_otlp_l7_span_push",
          ffi_decl: "ffi_func :spnl_otlp_l7_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_l7_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_l7_span_push(ep) }",
          why: "kernel builtin は span record を map に貯めるだけ。userspace が この FFI で drain して初めて OTLP に export される。書かないと compile+verify は green でも span 0 本。",
        }.freeze }.freeze,
      { name: "offcpu_span", mode: :all, experiment: "E300",
        members: %w[offcpu_recv_stash offcpu_begin offcpu_account offcpu_emit],
        why: "recv_stash/begin が off-CPU 窓を開き、account が待ちを積み、emit が窓を閉じて span 化する。4 フック 1 組。",
        userspace_export: {
          fn: "spnl_otlp_offcpu_span_push",
          ffi_decl: "ffi_func :spnl_otlp_offcpu_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_offcpu_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_offcpu_span_push(ep) }",
          why: "kernel builtin は span record を map に貯めるだけ。userspace が この FFI で drain して初めて OTLP に export される。書かないと compile+verify は green でも span 0 本。",
        }.freeze }.freeze,
      { name: "sock_owner_correlation", mode: :requires, experiment: "E296",
        trigger: "sock_owner_set", requires: %w[emit_connect],
        why: "sock_owner_set は sock→process を記録するだけで、emit_connect が同じ sock で引いて初めて相関が効く。",
        userspace_export: {
          fn: "spnl_otlp_conn_span_push",
          ffi_decl: "ffi_func :spnl_otlp_conn_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_conn_span_push, [:str], :int\nend\n# ... kernel handlers (sock_owner_set + emit_connect) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_conn_span_push(ep) }",
          why: "この相関は emit_connect が生む conn span で export される (専用 push は無い)。kernel builtin は record を map に貯めるだけで、この FFI で drain して初めて OTLP に export される。",
        }.freeze }.freeze,
    ].freeze

    # --- query API (E316: 機械可読 affordance) ---

    # builtin -> signature hash ({arity:, params:, opaque:, summary:})。
    def signature_for(name)
      SIGNATURES[name] || { arity: nil, params: nil, opaque: true, summary: nil }
    end

    # builtin -> context 要件 ({secs:}|{kinds:}) or nil (codegen 非強制)。
    def context_for(name)
      CONTEXT_REQUIREMENTS[name]
    end

    # builtin -> valid context 文字列配列 (JSON 用)。gate 無しは nil。
    def context_strings(name)
      req = CONTEXT_REQUIREMENTS[name]
      return nil unless req
      return req[:secs] if req[:secs]
      req[:kinds].map(&:to_s)
    end

    # builtin -> context の人間可読ノート (gate 有=強制、無=best-effort)。
    def context_note(name)
      return "codegen が compile 時に強制 (この hook 外なら die)" if CONTEXT_REQUIREMENTS[name]
      CONTEXT_NOTE_OVERRIDES[name] || DOMAIN_CONTEXT_NOTE[domain_of(name)] || "codegen 非強制"
    end

    # builtin -> 1 行の Ruby 呼び出しコード例 (構文見本、E322 GAP-1)。opaque は nil
    # (params 不明なので嘘の例より省略 = opaque と同じ正直さ)。
    def example_for(name)
      sig = signature_for(name)
      return nil if sig[:opaque]              # 省略は意図的 (example.nil? iff opaque)
      ov = EXAMPLE_OVERRIDES[name]
      return ov if ov
      params = sig[:params]
      return name if params.nil? || params.empty?   # arity 0 = bare 呼出 (dominant idiom)
      "#{name}(#{params.join(', ')})"
    end

    # builtin -> 関連 builtin (BUILTIN_GROUPS の同一グループの他メンバ、sorted、E322 GAP-2)。
    # どのグループにも属さなければ [] (単一の権威 = BUILTIN_GROUPS)。
    def related_for(name)
      BUILTIN_GROUPS.each_with_object([]) do |g, acc|
        acc.concat(g[:members] - [name]) if g[:members].include?(name)
      end.uniq.sort
    end

    # 1 builtin の完全 affordance entry。
    def builtin_entry(name)
      sig = signature_for(name)
      chan = record_channel_for(name)   # E370 (S3): packed record を書く builtin だけ非 nil
      {
        name: name,
        domain: domain_of(name),
        arity: sig[:arity],
        params: sig[:params],
        opaque: sig[:opaque],
        example: example_for(name),   # E322 GAP-1: 呼び出し構文見本 (opaque は null)
        related: related_for(name),   # E322 GAP-2: 関連 builtin (BUILTIN_GROUPS 由来)
        gated: !CONTEXT_REQUIREMENTS[name].nil?,
        valid_contexts: context_strings(name),
        context_note: context_note(name),
        summary: sig[:summary],
        # E370 (S3): この builtin が ringbuf に書く record と、それが最終的に何の span に
        # なるか (フィールド/offset は生成器の layout() 由来、属性は egress 宣言由来)。
        record_channel: chan && chan[:id],
        record_schema: chan,
      }
    end

    # 機械可読 affordance ドキュメント全体 (Ruby Hash)。CLI が JSON 化する。
    def affordance
      {
        schema: "spinel-ebpf.affordance/1",
        adr: "ADR-015",
        note: "AI-authoring 契約 (introspection、codegen 出力は不変)。" \
              "builtin は flat のまま (ADR-014: 必須 dotted 名にしない)。",
        summary: {
          builtin_count: all_builtins.length,
          opaque_builtins: all_builtins.count { |b| signature_for(b)[:opaque] },
          attach_kind_count: ATTACH_KINDS.length,
          domains: DOMAINS.keys,
          record_channel_count: record_channels.length,
        },
        domains: DOMAINS.each_with_object({}) { |(d, s), h|
          h[d] = { summary: s[:summary], attach_kinds: s[:attach_kinds] }
        },
        builtins: all_builtins.map { |b| builtin_entry(b) },
        # E322 GAP-2: 関連 builtin のクロスリンク (pack 関係/対/ファミリ、選択に必要な事実)。
        builtin_groups: BUILTIN_GROUPS,
        attach_kinds: ATTACH_KINDS,
        context_gates: CONTEXT_GATES.map { |n, g|
          { builtin: n, domain: g[:domain], valid_secs: g[:valid_secs] }
        },
        ruby_subset: RUBY_SUBSET,
        enrichers: ENRICHERS,
        krew_probes: KREW_PROBE_DOMAINS,
        # 必須組 (multi-hook) の contract。単独では span を生まない builtin 群。
        # compile 時に SpinelEbpf::Validate が loud に強制する。
        required_sets: REQUIRED_SETS,
        # E370 (S3): packed-record チャネルの契約 (ringbuf に書く byte 像 + そこから
        # 出る OTLP 属性)。src/codegen_c/record_schema.h の生成物を読んでいるだけで、
        # offset をここで計算はしていない (単一の layout 実装 = 生成器)。
        record_channels: record_channels,
        # E374 (ADR-017 D3-5): userspace consumer DSL の語彙と `to_span` の解決規則。
        # typed_channels = `on_emit :<id>` が型付き consumer になる id (それ以外は E242 named event)。
        consumer_dsl: { typed_channels: typed_record_channel_ids, verbs: CONSUMER_DSL },
      }
    end

    # affordance を JSON 文字列 (pretty) に。
    def affordance_json
      require "json"
      JSON.pretty_generate(affordance)
    end

    # --- query API (E317: 必須組 contract) ---

    # 使用中の builtin 名集合を与え、各 REQUIRED_SET 契約の**欠けている相方**を返す。
    # 返り値: [ { name:, mode:, experiment:, present: [...], missing: [...], why: } , ... ]
    # 契約を満たす (missing 空) セットは含めない。Validate と affordance が共有。
    def missing_companions(used_names)
      used = used_names.to_a.to_set
      REQUIRED_SETS.filter_map do |rule|
        case rule[:mode]
        when :all
          present = rule[:members].select { |m| used.include?(m) }
          next if present.empty?
          missing = rule[:members] - present
          next if missing.empty?
          { name: rule[:name], mode: :all, experiment: rule[:experiment],
            present: present, missing: missing, why: rule[:why] }
        when :requires
          next unless used.include?(rule[:trigger])
          missing = rule[:requires].reject { |m| used.include?(m) }
          next if missing.empty?
          { name: rule[:name], mode: :requires, experiment: rule[:experiment],
            trigger: rule[:trigger], present: [rule[:trigger]], missing: missing, why: rule[:why] }
        end
      end
    end
  end
end
