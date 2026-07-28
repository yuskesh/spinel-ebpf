# frozen_string_literal: true
#
# E317 (ADR-015 原則2「loud failure」+ 投資優先(b)): compile 時の loud で
# actionable な拒否。AI が誤った Ruby を書いたとき、**何が・なぜ・どこ・どう直すか**
# を返して自己修正を助ける (E316 affordance = 読む、本モジュール = 直す)。
#
# partition と codegen の隙間に落ちる穴を、**codegen を呼ぶ前**に Ruby で
# 塞ぐ (C 版・Ruby oracle どちらの codegen でも同じ loud エラーが CLI から出る):
#
#   1. attach ハンドラが :native に落ちる = silent no-op
#      (`def kprobe__x` が float/regex/io で eBPF 不適格 → 誰も発火させない。
#       exit 0 のまま黙って消える最悪ケース)。attach prefix を持つメソッドが
#       ebpf-impossible で :native なら **hard error** + 具体的理由。
#
#   2. attach 名の typo (E320 / E319 GAP-2、最重大) — `def kprobe_do_sys_openat2`
#      (アンダースコア 1 個、正しくは `kprobe__`)。既知の attach-kind (kprobe/…) の
#      後に単一 `_` が続くと、どの ATTACH_PATTERNS にもマッチせず **孤児 SEC("syscall")
#      program に silent フォールバック**する (partition/codegen/clang/verifier 全緑
#      なのにカーネルに attach されず一生発火しない)。`__` にすれば valid attach に
#      なるものを typo とみなし **did-you-mean** で loud に落とす。
#
#   3. 0 引数 builtin の余分な引数 (E320 / E319 GAP-1) — `latency_start(1)`。C 版
#      codegen は sibling の `lat_start`/`lat_end` (arity 1) は arity を検査するのに
#      `latency_start`/`latency_end` (arity 0) は引数を silent に捨てる非対称がある。
#      余分な引数を **loud** に落として整合させる (`expects no arguments`)。
#
#   4. 未知 builtin (typo) — `hist_observ(x)`。codegen は "CallNode not yet ported"
#      や "not lowerable" と cryptic に落ちる。ここで **did-you-mean** (Levenshtein、
#      依存なし) を出す。
#
#   5. 不完全な必須組 — `http_req_start` だけ書いて `http_emit` を書かない等。
#      現状は **silent に壊れた program** (span が出ないが exit 0)。
#      Capabilities::REQUIRED_SETS を参照して **loud** に落とす。
#
# +heap: `[1,2,3].map { }` 等の enumerable ブロックは eBPF 不可。partition は
#   これを捕まえないので (map は DYNAMIC_ARRAY_OPS 外)、ここで名指しして落とす。
#
# 非目標: **成功する probe の生成コードは 1 byte も変えない** (golden 不変)。
# エラー経路だけを賢くする。過剰に厳しくしない (2 軸ハーネス: 良い probe は通す)。

require "set"
require_relative "capabilities"
require_relative "codegen_bpf"

module SpinelEbpf
  module Validate
    # 拒否は ADR-003 に従い即エラー。CLI は rescue して `error: <message>` で abort。
    class Error < StandardError; end

    module_function

    # 全 builtin の権威集合 (codegen の BUILTIN_NAMES + dynptr)。
    BUILTINS = (CodegenBpf::BUILTIN_NAMES + CodegenBpf::DYNPTR_BUILTINS).uniq.to_set.freeze

    # eBPF サブセットで唯一許される受信あり反復は `n.times { }`。それ以外の
    # enumerable ブロック呼出は heap 反復 = eBPF 不可。ブロック付きに限定して
    # 判定するので、kfield の dot-field read (`t.min`、ブロック無し) や
    # dot-accessor (`sk.snd_cwnd`) を誤検出しない。
    ENUMERABLE_BLOCK_METHODS = %w[
      map collect select filter reject filter_map
      reduce inject each each_with_object each_with_index each_pair
      flat_map find detect find_all group_by partition
      sort_by min_by max_by sum count chunk_while zip
    ].to_set.freeze

    # 受信なし control 形 (万一 :ebpf に残っても typo 扱いしない安全網)。
    CONTROL_NAMES = %w[times loop lambda proc].to_set.freeze

    # E320 (GAP-2): 既知の attach-kind word。affordance と検出を同じデータ源に
    # するため、Capabilities::ATTACH_KINDS の method_prefix から先頭識別子 (最初の
    # `__` より前) を機械的に抜く。例: "kprobe__<func>" -> "kprobe"、"xdp__<name>"
    # -> "xdp"、"xdp_tail__<name>" -> "xdp_tail"、"sk_skb__verdict__<name>" ->
    # "sk_skb"。timer だけ method_prefix が "on :timer, …" 形 (作者が手で def しない
    # 合成名) なので先頭が識別子でなく自然に除外される。長い word を先に試すため
    # 長さ降順 (xdp_tail を xdp より優先 = 良い suggestion)。
    ATTACH_WORDS = Capabilities::ATTACH_KINDS
                   .filter_map { |a| a[:method_prefix][/\A([a-z0-9_]+?)__/, 1] }
                   .uniq
                   .sort_by { |w| -w.length }
                   .freeze

    # E320 (GAP-1): 引数を取らない (arity 0) builtin のうち、sibling (lat_start/
    # lat_end) が arity を検査するのに C codegen が silent に引数を捨てる非対称を
    # 持つもの。余分な引数を loud に落とす。tid キーは builtin 内部で取るので 0 引数。
    ZERO_ARG_STRICT = %w[latency_start latency_end].to_set.freeze

    # 全チェックを走らせる (loud 検査 = 最初の違反で raise)。
    #   ast    -- ParseSpinelAst
    #   result -- Partition::Result (tag 決定済)
    def validate!(ast, result)
      return if result.nil? || ast.nil?
      check_attach_handlers_are_ebpf!(result)              # (1)
      check_attach_name_typos!(result)                     # (2) E320 GAP-2
      used, unknown = scan_ebpf_calls(ast, result)         # 1 回の walk で両方
      check_heap_iteration!(ast, result)                   # +heap
      check_zero_arg_builtins!(ast, result)                # (3) E320 GAP-1
      check_unknown_builtins!(unknown)                     # (4)
      check_required_sets!(used)                           # (5)
      nil
    end

    # (1) attach ハンドラが ebpf-impossible で :native に落ちていたら loud に落とす。
    # attach は eBPF でしか動かない (native 実行パスが無い) ので、黙って native 化
    # すると **一切発火しない**。partition table には理由が出るが exit 0 なので AI は
    # 成功と誤読する ⇒ hard error にする。
    def check_attach_handlers_are_ebpf!(result)
      result.methods.each do |mi|
        next unless mi.tag == :native
        next unless mi.scope == :top_level
        # ebpf-impossible が原因のときだけ (force_native / __spnl_ / <main> は対象外)。
        next unless mi.flags && mi.flags.ebpf_impossible?
        attach = CodegenBpf.detect_attach(mi.method_name)
        next unless attach
        reasons = mi.flags.reasons.join("; ")
        raise Error,
              "attach handler `def #{mi.method_name}` (#{attach[:sec]}) can't be lowered to eBPF: " \
              "#{reasons}. An attach handler MUST be eBPF — there is no native execution path for a " \
              "#{attach[:kind]} hook, so this probe would silently never fire. Rewrite the body to the " \
              "eBPF subset (integers + builtins only; see `spinel-ebpf capabilities`)."
      end
    end

    # (2) E320 GAP-2 (最重大、loud-failure 違反の是正): attach 名の 1 文字 typo
    # (`kprobe_x` = 単一 `_`、正しくは `kprobe__x`) を compile 時に loud に落とす。
    #
    # 単一 `_` はどの ATTACH_PATTERNS にもマッチせず、top-level :ebpf メソッドは
    # 孤児 SEC("syscall") program に化ける — partition/codegen/clang/verifier は全緑
    # なのに **カーネルの何にも attach されず一生発火しない** (E319 で実測)。verifier
    # は「安全か」しか見ないのでこの穴は check でも捕まらなかった。ここで名前規則
    # から高確度に検出する。
    #
    # 締めすぎ回避 (2 軸ハーネス): detect_attach が既に valid とみなす名前 (= 正しい
    # `__` 形、DSL 合成名) は対象外。かつ「word + 単一 `_` + rest を `__` に直すと
    # valid attach になる」場合だけ flag する (attach_name_typo_suggestion が
    # detect_attach で検証)。corpus 403 メソッド名で false-reject 0 を実測。
    def check_attach_name_typos!(result)
      result.methods.each do |mi|
        next unless mi.tag == :ebpf
        next unless mi.scope == :top_level
        name = mi.method_name
        next if name.nil? || name.empty?
        next if CodegenBpf.detect_attach(name)     # 既に valid attach 形 — 正当
        hit = attach_name_typo_suggestion(name)
        next unless hit
        word, suggestion = hit
        raise Error,
              "method `#{name}` looks like an attach handler but uses a single underscore after " \
              "the attach kind `#{word}`; did you mean `#{suggestion}`? A single `_` here is NOT a " \
              "valid attach prefix, so it lowers to an orphaned SEC(\"syscall\") program that is never " \
              "attached to any kernel event and never fires — yet partition/codegen/clang/verifier all " \
              "stay green. Use the double-underscore form `#{word}__<target>`, or rename it if this is " \
              "intentionally a plain (BPF-to-BPF) helper."
      end
    end

    # name が「attach word + 単一 `_` + rest」で、`__` に直すと valid attach になる
    # なら [word, suggestion] を返す (無ければ nil)。単一 fix (1 個の `_` → `__`) で
    # valid になる高確度 typo だけを対象にする (rest が `_` 始まりなら既に `__` =
    # valid 形なので除外)。長い word 優先で最良の suggestion を出す。
    def attach_name_typo_suggestion(name)
      ATTACH_WORDS.each do |w|
        prefix = "#{w}_"
        next unless name.start_with?(prefix)
        rest = name[prefix.length..]
        next if rest.nil? || rest.empty? || rest.start_with?("_")
        candidate = "#{w}__#{rest}"
        return [w, candidate] if CodegenBpf.detect_attach(candidate)
      end
      nil
    end

    # (3) E320 GAP-1: 0 引数 builtin (latency_start/latency_end) に余分な引数が
    # 渡っていたら loud に落とす。sibling の lat_start/lat_end (arity 1) との非対称
    # (C codegen が黙って引数を捨てる) を是正。成功 probe は 0 引数なので不変。
    def check_zero_arg_builtins!(ast, result)
      each_ebpf_body(result) do |mi, body_id|
        walk_calls(body_id, ast) do |nid|
          next unless ast.receiver_of(nid) < 0   # 受信なし builtin 呼出のみ
          name = ast.name_of(nid)
          next unless ZERO_ARG_STRICT.include?(name)
          n = call_arg_count(ast, nid)
          next if n.zero?
          raise Error,
                "`#{name}` expects no arguments but got #{n} in `#{mi.method_name}` — it captures the " \
                "tid key automatically, so it takes 0 args. Its siblings `lat_start`/`lat_end` take a " \
                "key argument, but `latency_start`/`latency_end` do not. Remove the argument(s)."
        end
      end
    end

    # CallNode の実引数個数 (ArgumentsNode が無ければ 0)。
    def call_arg_count(ast, nid)
      aid = ast.arguments_of(nid)
      return 0 if aid < 0
      an = ast.node(aid)
      return 0 unless an && an.type == "ArgumentsNode"
      an.arrays.fetch("arguments", []).length
    end

    # +heap: :ebpf メソッド本体に enumerable ブロック呼出があれば loud に落とす。
    def check_heap_iteration!(ast, result)
      each_ebpf_body(result) do |mi, body_id|
        walk_calls(body_id, ast) do |nid|
          name = ast.name_of(nid)
          next unless ENUMERABLE_BLOCK_METHODS.include?(name)
          next if ast.ref(nid, "block", default: -1) < 0   # ブロック付きのみ
          raise Error,
                "`.#{name} { ... }` in `#{mi.method_name}` is heap/enumerable iteration, which is " \
                "eBPF-illegal (no heap, no dynamic allocation in BPF). The only bounded loop in the " \
                "eBPF subset is `n.times { |i| ... }`. Rewrite the iteration with `n.times`."
        end
      end
    end

    # (4) 未知 builtin (typo) を did-you-mean 付きで落とす。
    def check_unknown_builtins!(unknown)
      return if unknown.empty?
      u = unknown.first
      name, method = u[:name], u[:method]
      best, dist = nearest_builtin(name)
      # 近い builtin があれば did-you-mean。閾値は名前長に応じて緩める。
      threshold = [2, (name.length / 3.0).ceil].max
      if best && dist <= threshold
        sig = Capabilities.signature_for(best)
        hint = sig[:params] ? "(#{sig[:params].join(', ')})" : "(#{sig[:arity]} args)"
        raise Error,
              "unknown builtin `#{name}` in `#{method}` — did you mean `#{best}`#{hint}? " \
              "#{sig[:summary]} (run `spinel-ebpf capabilities --json` for all #{BUILTINS.size} builtins)."
      end
      raise Error,
            "unknown builtin/method `#{name}` in `#{method}` — not a known builtin, defined method, or " \
            "eBPF construct. Run `spinel-ebpf capabilities` (#{BUILTINS.size} builtins) or define it."
    end

    # (5) 不完全な必須組を loud に落とす (Capabilities::REQUIRED_SETS を参照)。
    def check_required_sets!(used)
      gaps = Capabilities.missing_companions(used.keys)
      return if gaps.empty?
      g = gaps.first
      if g[:mode] == :all
        raise Error,
              "incomplete builtin set `#{g[:name]}` (#{g[:experiment]}): you use " \
              "#{g[:present].join(', ')} but not #{g[:missing].join(', ')}. These builtins only work " \
              "as a set — #{g[:why]} Add the missing hook(s), or remove the ones you have."
      else
        raise Error,
              "`#{g[:trigger]}` (#{g[:experiment]}) needs #{g[:missing].join(', ')} to have any effect — " \
              "#{g[:why]} Add #{g[:missing].join(', ')}, or remove `#{g[:trigger]}`."
      end
    end

    # ---------- 内部ヘルパー ----------

    # 全 :ebpf メソッドを 1 回 walk し、(a) 使用中 builtin -> [method,...]、
    # (b) 未知の受信なし呼出 [{name:, method:}] を集める。
    #
    # chain accessor の base (`pkt.l4.proto` の `pkt`) は「受信なし CallNode だが
    # 別 CallNode の receiver」= codegen の accessor が処理する正当形。builtin/typo
    # は leaf 呼出 (誰の receiver でもない) なので、**receiver 位置の call は unknown
    # 判定から除外** (E317 の 2 軸ハーネス: 正当な chain accessor を弾かない)。
    def scan_ebpf_calls(ast, result)
      known = method_name_set(result)
      used = Hash.new { |h, k| h[k] = [] }
      candidates = []          # [{ nid:, name:, method: }] receiver-less unknowns
      receiver_ids = Set.new   # 他 CallNode の receiver になっている node id
      each_ebpf_body(result) do |mi, body_id|
        walk_calls(body_id, ast) do |nid|
          rid = ast.receiver_of(nid)
          receiver_ids << rid if rid >= 0
          next unless rid < 0                      # builtin / bpf-to-bpf は受信なし
          name = ast.name_of(nid)
          next if name.nil? || name.empty?
          if BUILTINS.include?(name)
            used[name] << mi.method_name
          elsif known.include?(name) || CONTROL_NAMES.include?(name) || BINARY_OP_NAMES.include?(name)
            # 定義済メソッド (bpf-to-bpf) / control / 二項演算 — 既知、無視
          else
            candidates << { nid: nid, name: name, method: mi.method_name }
          end
        end
      end
      # chain accessor の base (receiver 位置) は除外。
      unknown = candidates.reject { |c| receiver_ids.include?(c[:nid]) }
      [used, unknown]
    end

    BINARY_OP_NAMES = CodegenBpf::MethodEmitter::BINARY_OPS.to_set.freeze

    # result 内の全メソッド名 (bare + dsl 元名) の集合。bpf-to-bpf 呼出の解決に使う。
    # 広めに取る (permissive) — 誤検出で正当な呼出を弾くより did-you-mean を逃す方が安全。
    def method_name_set(result)
      s = Set.new
      result.methods.each do |m|
        s << m.method_name if m.method_name
        s << m.dsl_orig_name if m.dsl_orig_name
      end
      s
    end

    def each_ebpf_body(result)
      result.methods.each do |mi|
        next unless mi.tag == :ebpf
        next if mi.body_id.nil? || mi.body_id < 0
        yield mi, mi.body_id
      end
    end

    # body_id 以下の CallNode を yield (nested def/class/module には入らない;
    # partition の walk と同じガード)。
    def walk_calls(body_id, ast, &blk)
      visited = {}
      stack = [body_id]
      until stack.empty?
        nid = stack.pop
        next if nid.nil? || !nid.is_a?(Integer) || nid < 0
        next if visited[nid]
        visited[nid] = true
        node = ast.node(nid)
        next unless node
        case node.type
        when "DefNode", "ClassNode", "ModuleNode"
          next   # 別メソッドとして解析される — 二重カウント回避
        when "CallNode"
          blk.call(nid)
        end
        # refs は Integer 値のみ辿る (IntegerNode#value=0 を node 0 と誤認しない)。
        node.refs.each_value { |c| stack << c if c.is_a?(Integer) && c >= 0 }
        node.arrays.each_value { |arr| arr.each { |c| stack << c if c.is_a?(Integer) && c >= 0 } }
      end
    end

    # 依存なしの Levenshtein 距離。
    def levenshtein(a, b)
      return b.length if a.empty?
      return a.length if b.empty?
      prev = (0..b.length).to_a
      a.each_char.with_index do |ca, i|
        cur = [i + 1]
        b.each_char.with_index do |cb, j|
          cost = ca == cb ? 0 : 1
          cur << [cur[j] + 1, prev[j + 1] + 1, prev[j] + cost].min
        end
        prev = cur
      end
      prev[b.length]
    end

    # name に最も近い builtin と距離を返す [best, dist] (BUILTINS 空なら [nil, ∞])。
    def nearest_builtin(name)
      best = nil
      best_d = Float::INFINITY
      BUILTINS.each do |b|
        d = levenshtein(name, b)
        if d < best_d
          best_d = d
          best = b
        end
      end
      [best, best_d]
    end
  end
end
