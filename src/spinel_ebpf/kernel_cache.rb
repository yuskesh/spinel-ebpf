# frozen_string_literal: true
#
# Auto kernel-cache (response-granularity partition).
#
# Parses top-level `kernel_cache "/path", "body"` declarations from the spinel
# AST. Each declaration asks the compiler to serve that path's response from the
# kernel (XDP_TX), so requests that hit it never reach userspace — no accept /
# read_line / sp_str_dup_external on the data plane (avoiding the measured
# FFI-marshalling cost). This module only extracts the (path, body) contract;
# the codegen generalizes the XDP match/reply machinery to it.
#
# AST shape (from `spinel --dump-ast`):
#   ProgramNode -> StatementsNode body[] -> CallNode(name="kernel_cache", receiver=-1)
#     -> ArgumentsNode arguments[] -> [StringNode(path), StringNode(body)]
#
# MVP scope: literal path + literal body, 2 args. Hash form (`"/p" => "body"`),
# block bodies, and computed bodies are later phases.

module SpinelEbpf
  module KernelCache
    # `body` is the literal response body when the 2nd arg is a string literal,
    # or nil when it's a runtime expression (Phase 1: the body is computed at
    # startup and pushed into the kernel via sp_kc_set; only `path` is needed at
    # compile time, to emit the XDP match). `path` is always a literal.
    Entry = Struct.new(:path, :body, keyword_init: true) do
      def literal? ; !body.nil? ; end

      # Full HTTP/1.0 response for a literal body (framing built here so the Ruby
      # surface only carries the body). Only meaningful when literal?.
      def http_response
        "HTTP/1.0 200 OK\r\n" \
        "Content-Length: #{body.bytesize}\r\n" \
        "\r\n" \
        "#{body}"
      end
    end

    module_function

    # Returns an Array<Entry> for every top-level `kernel_cache "/path","body"`.
    def declarations(ast)
      out = []
      stmts = ast.statements_of(ast.root_id)
      return out if stmts.nil? || stmts < 0
      ast.body_array_of(stmts).each do |sid|
        n = ast.node(sid)
        next unless n && n.type == "CallNode"
        next unless ast.str_attr(sid, "name") == "kernel_cache"
        next unless ast.ref(sid, "receiver") == -1          # bare call, not recv.kernel_cache
        args = ast.ref(sid, "arguments")
        next if args < 0
        items = ast.array(args, "arguments")
        next unless items.length == 2
        pn = ast.node(items[0])
        next unless pn && pn.type == "StringNode"          # path must be a literal
        bn = ast.node(items[1])
        body = (bn && bn.type == "StringNode") ? ast.str_attr(items[1], "content") : nil  # nil = runtime body
        out << Entry.new(path: ast.str_attr(items[0], "content"), body: body)
      end
      out
    end
  end
end
