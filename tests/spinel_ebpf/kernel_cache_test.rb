# frozen_string_literal: true

require "minitest/autorun"
require "spinel_ebpf/parse_spinel_ast"
require "spinel_ebpf/kernel_cache"
require "spinel_ebpf/partition"
require "spinel_ebpf/codegen_bpf"

# Parsing `kernel_cache "/path","body"` declarations.
# The AST text below is the verbatim `spinel --dump-ast --no-line-map` output
# for:
#   kernel_cache "/health", "OK\n"
#   kernel_cache "/version", "spinel 1.0\n"
class KernelCacheTest < Minitest::Test
  TWO_DECLS = <<~AST
    ROOT 0
    SOURCE_FILE kc.rb
    N 0 ProgramNode
    N 1 StatementsNode
    N 2 CallNode
    S 2 name kernel_cache
    R 2 receiver -1
    N 3 ArgumentsNode
    N 4 StringNode
    S 4 content /health
    N 5 StringNode
    S 5 content OK%0A
    A 3 arguments 4,5
    R 2 arguments 3
    R 2 block -1
    S 2 call_operator .
    N 6 CallNode
    S 6 name kernel_cache
    R 6 receiver -1
    N 7 ArgumentsNode
    N 8 StringNode
    S 8 content /version
    N 9 StringNode
    S 9 content spinel%201.0%0A
    A 7 arguments 8,9
    R 6 arguments 7
    R 6 block -1
    S 6 call_operator .
    A 1 body 2,6
    R 0 statements 1
  AST

  def parse(text)
    SpinelEbpf::ParseSpinelAst.parse(text)
  end

  def test_parses_two_declarations_in_order
    decls = SpinelEbpf::KernelCache.declarations(parse(TWO_DECLS))
    assert_equal 2, decls.length
    assert_equal "/health", decls[0].path
    assert_equal "OK\n", decls[0].body                 # %0A decoded
    assert_equal "/version", decls[1].path
    assert_equal "spinel 1.0\n", decls[1].body         # %20 / %0A decoded
  end

  def test_http_response_builds_framing_from_body
    decls = SpinelEbpf::KernelCache.declarations(parse(TWO_DECLS))
    assert_equal "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nOK\n", decls[0].http_response
  end

  def test_no_declarations_when_none_present
    plain = <<~AST
      ROOT 0
      N 0 ProgramNode
      N 1 StatementsNode
      N 2 CallNode
      S 2 name puts
      R 2 receiver -1
      N 3 ArgumentsNode
      N 4 StringNode
      S 4 content hi
      A 3 arguments 4
      R 2 arguments 3
      R 2 block -1
      A 1 body 2
      R 0 statements 1
    AST
    assert_empty SpinelEbpf::KernelCache.declarations(parse(plain))
  end

  # AST for: kernel_cache "/api", "PONG\n"  (distinct from the default /health route)
  API_DECL = <<~AST
    ROOT 0
    N 0 ProgramNode
    N 1 StatementsNode
    N 2 CallNode
    S 2 name kernel_cache
    R 2 receiver -1
    N 3 ArgumentsNode
    N 4 StringNode
    S 4 content /api
    N 5 StringNode
    S 5 content PONG%0A
    A 3 arguments 4,5
    R 2 arguments 3
    R 2 block -1
    A 1 body 2
    R 0 statements 1
  AST

  NO_DECL = <<~AST
    ROOT 0
    N 0 ProgramNode
    N 1 StatementsNode
    A 1 body
    R 0 statements 1
  AST

  # partition synthesizes a pure-XDP TCP slice from declarations.
  def test_partition_synthesizes_slice_method_when_declared
    methods = []
    SpinelEbpf::Partition.synthesize_kernel_cache_slice!(methods, parse(API_DECL))
    m = methods.find { |x| x.method_name == "xdp__tcp_slice__kernel_cache" }
    refute_nil m, "expected a synthesized xdp__tcp_slice__kernel_cache method"
    assert_equal :ebpf, m.tag
    assert_equal :top_level, m.scope
  end

  # runtime body: `kernel_cache "/ping", body` (body is a variable).
  # Only the path must be a literal; the body is populated at runtime via sp_kc_set.
  RUNTIME_BODY = <<~AST
    ROOT 0
    N 0 ProgramNode
    N 1 StatementsNode
    N 2 CallNode
    S 2 name kernel_cache
    R 2 receiver -1
    N 3 ArgumentsNode
    N 4 StringNode
    S 4 content /ping
    N 5 LocalVariableReadNode
    S 5 name body
    A 3 arguments 4,5
    R 2 arguments 3
    R 2 block -1
    A 1 body 2
    R 0 statements 1
  AST

  def test_parses_runtime_body_declaration_path_only
    decls = SpinelEbpf::KernelCache.declarations(parse(RUNTIME_BODY))
    assert_equal 1, decls.length
    assert_equal "/ping", decls[0].path
    assert_nil decls[0].body          # runtime body -> not known at compile time
    refute decls[0].literal?
    # still synthesizes the slice (the path drives the XDP match)
    methods = []
    SpinelEbpf::Partition.synthesize_kernel_cache_slice!(methods, parse(RUNTIME_BODY))
    assert(methods.any? { |m| m.method_name == "xdp__tcp_slice__kernel_cache" })
  end

  def test_partition_no_synthesis_without_declarations
    methods = []
    SpinelEbpf::Partition.synthesize_kernel_cache_slice!(methods, parse(NO_DECL))
    assert_empty methods
  end

  # the tcp_slice bundle matches the declared route, and serves the response from
  # the runtime-populated bpf_kc_resp map (not a const array).
  def test_bundle_uses_declared_path_and_map_backed_response
    ast = parse(API_DECL)
    ctx = SpinelEbpf::CodegenBpf::EmitContext.new(ast: ast)
    bundle = SpinelEbpf::CodegenBpf.emit_tcp_slice_bundle(ctx)
    assert_includes bundle, 'prefix "GET /api "'
    refute_includes bundle, "GET /health "
    # Phase 1: response comes from the map, not a baked-in const array.
    assert_includes bundle, "bpf_kc_resp SEC(\".maps\")"
    assert_includes bundle, "struct spnl_kc_resp { __u8 bytes[#{SpinelEbpf::CodegenBpf::KERNEL_CACHE_RESP_CAP}]; }"
    assert_includes bundle, "bpf_map_lookup_elem(&bpf_kc_resp"
    # wire frame sized to the ACTUAL response length (runtime _rlen), copied
    # with a bounded loop, payload checksummed via the precomputed seed (fixed-size
    # bpf_csum_diff) — so real-client frames SHRINK (no adjust_tail-grow), which
    # native XDP_TX needs on NICs like nxp_enetc4.
    assert_includes bundle, "bpf_kc_resp_len SEC(\".maps\")"
    assert_includes bundle, "bpf_kc_resp_csum SEC(\".maps\")"
    assert_includes bundle, "out[_i] = _kc->bytes[_i];"             # bounded variable-length copy
    assert_includes bundle, "spnl_tcp_slice_recompute_csums_pc"      # precompute-seed csum path
    assert_includes bundle, "20 + 20 + (int)_rlen"                   # frame sized to actual length
    refute_includes bundle, "__builtin_memcpy(out, _kc->bytes,"      # no fixed CAP memcpy for kernel_cache
    refute_includes bundle, "spnl_tcp_slice_resp_body"          # no compile-time const array for kernel_cache
  end

  # multiple declarations => multi-route match_route + N-slot map.
  def test_bundle_multi_route_dispatch
    ctx = SpinelEbpf::CodegenBpf::EmitContext.new(ast: parse(TWO_DECLS))   # /health + /version
    bundle = SpinelEbpf::CodegenBpf.emit_tcp_slice_bundle(ctx)
    assert_includes bundle, "spnl_tcp_slice_match_route"
    # both declared paths checked, returning their declaration-order slot
    assert_match(/p\[4\] == '\/'.*return 0;/m, bundle)   # /health -> slot 0
    assert_includes bundle, "return 1;"                  # /version -> slot 1
    assert_includes bundle, "__uint(max_entries, 2);"    # one map slot per route
    # response looked up by the matched slot, not a fixed entry 0
    assert_includes bundle, "(kc_slot >= 0) ? (__u32)kc_slot : 0"
  end

  def test_bundle_falls_back_to_const_array_without_declarations
    ctx = SpinelEbpf::CodegenBpf::EmitContext.new(ast: parse(NO_DECL))
    bundle = SpinelEbpf::CodegenBpf.emit_tcp_slice_bundle(ctx)
    assert_includes bundle, 'prefix "GET /health "'
    assert_includes bundle, "spnl_tcp_slice_resp_body"          # hand-written slice keeps the const path
    refute_includes bundle, "bpf_kc_resp"
  end

  def test_ignores_wrong_arity_and_method_receiver
    # `kernel_cache "/x"` (1 arg) and `obj.kernel_cache "/y","z"` (has receiver)
    # must both be ignored — only bare 2-arg calls are declarations.
    ast = <<~AST
      ROOT 0
      N 0 ProgramNode
      N 1 StatementsNode
      N 2 CallNode
      S 2 name kernel_cache
      R 2 receiver -1
      N 3 ArgumentsNode
      N 4 StringNode
      S 4 content /x
      A 3 arguments 4
      R 2 arguments 3
      R 2 block -1
      N 5 CallNode
      S 5 name kernel_cache
      R 5 receiver 6
      N 6 CallNode
      S 6 name obj
      R 6 receiver -1
      R 6 arguments -1
      R 6 block -1
      N 7 ArgumentsNode
      N 8 StringNode
      S 8 content /y
      N 9 StringNode
      S 9 content z
      A 7 arguments 8,9
      R 5 arguments 7
      R 5 block -1
      A 1 body 2,5
      R 0 statements 1
    AST
    assert_empty SpinelEbpf::KernelCache.declarations(parse(ast))
  end
end
