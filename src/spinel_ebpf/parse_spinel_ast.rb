# frozen_string_literal: true
#
# SPINEL AST text-format parser (read + dump, byte-identical round-trip).
#
# Implements the format documented in deps/spinel/docs/AST.md
#
# Format recap:
#   ROOT <int>
#   N <id> <NodeType>
#   S <id> <field> <string>     -- escape_str-encoded string
#   I <id> <field> <int>
#   F <id> <field> <float>
#   R <id> <field> <child-id-or--1>
#   A <id> <field> <id,id,...>  -- comma-joined; empty body allowed
#
# Strings use C-style backslash escapes: \\n \\t \\r \\\\ \\" \\0

module SpinelEbpf
  module ParseSpinelAst
    Record = Struct.new(
      :tag,        # "ROOT" / "N" / "S" / "I" / "F" / "R" / "A"
      :id,         # integer node id (nil for ROOT — see :root_id)
      :field,      # field name (nil for ROOT, N)
      :payload,    # raw payload string (post-field)
      :raw_line,   # entire original line (byte-identical re-dump)
      keyword_init: true,
    )

    # A parsed node. We split attribute storage by source tag so callers
    # can distinguish a literal integer (I) from a child reference (R) —
    # both arrive as Ruby Integer otherwise, which causes catastrophic
    # AST walker bugs (an IntegerNode literal value of 0 would be mistaken
    # for a reference to node id 0).
    #
    # attrs:  Hash<String, String|Integer|Float>  -- S, I, F values
    # refs:   Hash<String, Integer>               -- R values (may be -1)
    # arrays: Hash<String, Array<Integer>>        -- A values (may be empty)
    Node = Struct.new(:id, :type, :attrs, :refs, :arrays, keyword_init: true) do
      # Combined lookup — checks all 3 maps. Useful when caller doesn't
      # care about origin tag.
      def lookup(field)
        return attrs[field]  if attrs&.key?(field)
        return refs[field]   if refs&.key?(field)
        return arrays[field] if arrays&.key?(field)
        nil
      end
    end

    # The full AST.
    class AST
      attr_reader :root_id, :records, :nodes

      def initialize(root_id:, records:, nodes:)
        @root_id = root_id
        @records = records
        @nodes = nodes
      end

      def node(id) ; @nodes[id] ; end
      def type_of(id) ; @nodes[id]&.type ; end

      # Generic accessor — searches S/I/F first, then R, then A.
      def attr(id, field, default: nil)
        n = @nodes[id]
        return default unless n
        v = n.lookup(field)
        v.nil? ? default : v
      end

      # Tag-specific accessors (use these in walkers that must distinguish).
      def str_attr(id, field, default: "") ; (n = @nodes[id]) ? n.attrs.fetch(field, default)  : default; end
      def int_attr(id, field, default: 0)  ; (n = @nodes[id]) ? n.attrs.fetch(field, default)  : default; end
      def float_attr(id, field, default: 0.0) ; (n = @nodes[id]) ? n.attrs.fetch(field, default) : default; end
      def ref(id, field, default: -1)      ; (n = @nodes[id]) ? n.refs.fetch(field, default)   : default; end
      def array(id, field, default: [])    ; (n = @nodes[id]) ? n.arrays.fetch(field, default) : default; end

      # Common ref accessors (R-typed fields).
      def name_of(id)       ; str_attr(id, "name",       default: "") ; end
      def receiver_of(id)   ; ref(id, "receiver",   default: -1) ; end
      def arguments_of(id)  ; ref(id, "arguments",  default: -1) ; end
      def block_of(id)      ; ref(id, "block",      default: -1) ; end
      def body_of(id)       ; ref(id, "body",       default: -1) ; end
      def value_of(id)      ; ref(id, "value",      default: -1) ; end
      def expression_of(id) ; ref(id, "expression", default: -1) ; end
      def statements_of(id) ; ref(id, "statements", default: -1) ; end
      def predicate_of(id)  ; ref(id, "predicate",  default: -1) ; end
      def parameters_of(id) ; ref(id, "parameters", default: -1) ; end

      # For A-typed body fields (e.g., StatementsNode#body).
      def body_array_of(id) ; array(id, "body", default: []) ; end
    end

    module_function

    # --- public API ---

    def parse_file(path)
      parse(File.read(path, encoding: "UTF-8"))
    end

    def parse(text)
      lines = text.split("\n", -1)
      lines.pop if lines.last == ""

      raise ArgumentError, "empty AST text" if lines.empty?

      records = []
      nodes = {}
      root_id = nil

      lines.each_with_index do |line, i|
        rec = parse_line(line, i + 1)
        records << rec
        case rec.tag
        when "ROOT"
          root_id = Integer(rec.payload)
        when "N"
          # N <id> <NodeType> : payload is the type name
          nodes[rec.id] = Node.new(id: rec.id, type: rec.payload, attrs: {}, refs: {}, arrays: {})
        when "S"
          ensure_node!(nodes, rec.id)
          nodes[rec.id].attrs[rec.field] = unescape_str(rec.payload || "")
        when "I"
          ensure_node!(nodes, rec.id)
          nodes[rec.id].attrs[rec.field] = Integer(rec.payload)
        when "F"
          ensure_node!(nodes, rec.id)
          nodes[rec.id].attrs[rec.field] = Float(rec.payload)
        when "R"
          ensure_node!(nodes, rec.id)
          nodes[rec.id].refs[rec.field] = Integer(rec.payload)
        when "A"
          ensure_node!(nodes, rec.id)
          body = rec.payload || ""
          nodes[rec.id].arrays[rec.field] = body.empty? ? [] : body.split(",").map { |s| Integer(s) }
        when "SOURCE_FILE"
          # informational metadata (source path); no node/attr to build.
        else
          raise ArgumentError, "line #{i + 1}: unknown tag #{rec.tag.inspect}"
        end
      end

      raise ArgumentError, "missing ROOT record" if root_id.nil?

      AST.new(root_id: root_id, records: records, nodes: nodes)
    end

    def dump(ast)
      out = String.new
      ast.records.each do |r|
        out << r.raw_line
        out << "\n"
      end
      out
    end

    # --- string encoding (escape_str / unescape_str compatibility) ---

    # Apply C-style backslash escapes per spinel_parse.c#escape_str.
    # Encode order: backslash first, then characters that map to backslash sequences.
    def escape_str(s)
      out = String.new
      s.each_char do |c|
        case c
        when "\\" then out << "\\\\"
        when "\n" then out << "\\n"
        when "\t" then out << "\\t"
        when "\r" then out << "\\r"
        when "\""  then out << "\\\""
        when "\0" then out << "\\0"
        else out << c
        end
      end
      out
    end

    # Inverse of escape_str (spinel_parse.c). Two encoding styles coexist for
    # historical reasons:
    #   - percent-encoding (current spinel_parse.c): %XX for %, \n, \r, \t, ' '
    #   - backslash-encoding (legacy / future-proofing): \n, \t, \r, \\, \", \0
    # Decode both so existing fixtures and freshly-generated ASTs both work.
    def unescape_str(s)
      out = String.new
      i = 0
      n = s.length
      while i < n
        c = s[i]
        if c == "%" && i + 2 < n
          # Percent-encoded byte (spinel_parse.c escape_str).
          hi = s[i + 1]
          lo = s[i + 2]
          if hi.match?(/[0-9A-Fa-f]/) && lo.match?(/[0-9A-Fa-f]/)
            out << (hi + lo).to_i(16).chr
            i += 3
            next
          end
        end
        if c == "\\" && i + 1 < n
          nxt = s[i + 1]
          out <<
            case nxt
            when "n"  then "\n"
            when "t"  then "\t"
            when "r"  then "\r"
            when "\\" then "\\"
            when "\""  then "\""
            when "0"  then "\0"
            else
              # unknown escape: keep verbatim (rare; future-proofing)
              "\\" + nxt
            end
          i += 2
        else
          out << c
          i += 1
        end
      end
      out
    end

    # --- internal record parsing ---

    def ensure_node!(nodes, id)
      raise ArgumentError, "attribute for unknown node id #{id} (N record missing or out of order)" unless nodes[id]
    end

    def parse_line(line, lineno)
      # Tag is the first space-separated token.
      tag, rest = split2(line)
      raise ArgumentError, "line #{lineno}: empty line" if tag.nil? || tag.empty?

      case tag
      when "ROOT"
        Record.new(tag: tag, payload: rest, raw_line: line)
      when "N"
        # N <id> <NodeType>
        id_s, type = split2(rest)
        Record.new(tag: tag, id: Integer(id_s), payload: type, raw_line: line)
      when "S", "I", "F", "R", "A"
        # <Tag> <id> <field> <payload>
        id_s, after_id = split2(rest)
        field, payload = split2(after_id)
        raise ArgumentError, "line #{lineno}: #{tag} record missing field" if field.nil? || field.empty?
        Record.new(
          tag: tag,
          id: Integer(id_s),
          field: field,
          payload: payload, # may be nil only for empty payload (e.g. empty A list with trailing space)
          raw_line: line,
        )
      when "SOURCE_FILE"
        # spinel upstream (post-409d73f base) prefixes the AST with the
        # source path: `SOURCE_FILE <path>`. It carries no node structure,
        # so keep it as an informational record (round-trips via dump) and
        # let the parse loop skip it.
        Record.new(tag: tag, payload: rest, raw_line: line)
      else
        raise ArgumentError, "line #{lineno}: unknown tag #{tag.inspect}"
      end
    end

    def split2(s)
      return [nil, nil] if s.nil?
      i = s.index(" ")
      return [s, nil] if i.nil?
      [s[0, i], s[(i + 1)..]]
    end
  end
end
