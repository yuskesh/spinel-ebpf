# frozen_string_literal: true
#
# SPINEL-IR v1 parser (read + dump, byte-equivalent round-trip).
#
# Implements the format documented in
# deps/spinel/docs/ANALYZE-IR.md
#
# The parser is intentionally schema-light: it reads any well-formed
# SPINEL-IR v1 file into a plain Hash of records, without re-deriving
# spinel's compiler state. The output Hash preserves source ordering
# of records so re-dump produces byte-identical text.
#
# Usage:
#
#   require_relative "spinel_ebpf/parse_spinel_ir"
#
#   ir = SpinelEbpf::ParseSpinelIR.parse_file("hello.ir")
#   ir.records.each { |r| ... }
#   SpinelEbpf::ParseSpinelIR.dump(ir)   # => string, byte-identical to input

module SpinelEbpf
  module ParseSpinelIR
    VERSION_STAMP = "SPINEL-IR v1"

    # Percent-encoding table from ANALYZE-IR.md §"Encoding".
    # IMPORTANT: '%' must be encoded first (and decoded last) to avoid
    # double-encoding the substitute hex digits.
    ENCODE_MAP = {
      "%"  => "%25",
      " "  => "%20",
      "\n" => "%0A",
      "\r" => "%0D",
      "\t" => "%09",
      "|"  => "%7C",
    }.freeze

    DECODE_MAP = {
      "%20" => " ",
      "%0A" => "\n",
      "%0D" => "\r",
      "%09" => "\t",
      "%7C" => "|",
      "%25" => "%",
    }.freeze

    # An IR record. We keep the raw payload string for byte-equivalent
    # re-dump, plus parsed fields where applicable.
    Record = Struct.new(
      :tag,        # "INT" / "STR" / "SA" / "IA" / "T" / "NM" / "NB" / "SN" / "ST"
      :name,       # "@ivar" for ivar tags, integer nid for per-node tags
      :count,      # Integer for SA/IA (length-prefixed), else nil
      :payload,    # raw payload string (post-count for SA/IA)
      :raw_line,   # entire original line (for byte-equivalent re-dump)
      keyword_init: true,
    )

    # In-memory container for a whole IR file.
    class IR
      attr_reader :version, :records

      def initialize(version: VERSION_STAMP, records: [])
        @version = version
        @records = records
      end

      def records_by_tag
        @records.group_by(&:tag)
      end

      def int_records   ; records_by_tag["INT"] || []; end
      def str_records   ; records_by_tag["STR"] || []; end
      def sa_records    ; records_by_tag["SA"]  || []; end
      def ia_records    ; records_by_tag["IA"]  || []; end
      def t_records     ; records_by_tag["T"]   || []; end
      def nm_records    ; records_by_tag["NM"]  || []; end
      def nb_records    ; records_by_tag["NB"]  || []; end
      def sn_records    ; records_by_tag["SN"]  || []; end
      def st_records    ; records_by_tag["ST"]  || []; end

      # Convenience: look up the INT scalar for an ivar (e.g. "@nd_count").
      def int(ivar)
        rec = int_records.find { |r| r.name == ivar }
        rec ? Integer(rec.payload) : nil
      end

      def str(ivar)
        rec = str_records.find { |r| r.name == ivar }
        rec ? ParseSpinelIR.decode(rec.payload) : nil
      end

      # SA payload: "count e1|e2|...|en" — returns Array<String>, decoded.
      def sa(ivar)
        rec = sa_records.find { |r| r.name == ivar }
        return nil unless rec
        ParseSpinelIR.split_strs_n(rec.payload, rec.count)
      end

      # IA payload: "count e1,e2,...,en" — returns Array<Integer>.
      def ia(ivar)
        rec = ia_records.find { |r| r.name == ivar }
        return nil unless rec
        ParseSpinelIR.split_ints_n(rec.payload, rec.count)
      end

      # Decoded per-method-body local-scope type table. spinel analyze
      # emits two scope records per method body node — SN (local variable names)
      # and ST (their inferred spinel types), both "|"-joined then %-escaped and
      # keyed by the body node id. Returns { body_nid => [[name, spinel_type], ...] }.
      # The eBPF codegen uses this to type local declarations instead of the
      # blanket __s64 it used to emit (the type info was parsed but discarded).
      def scope_locals
        @scope_locals ||= begin
          names = {}
          sn_records.each { |r| names[r.name] = ParseSpinelIR.decode(r.payload).split("|", -1) }
          types = {}
          st_records.each { |r| types[r.name] = ParseSpinelIR.decode(r.payload).split("|", -1) }
          out = {}
          names.each do |bid, ns|
            ts = types[bid] || []
            pairs = []
            ns.each_with_index do |n, i|
              next if n.nil? || n.empty?
              pairs << [n, ts[i] || ""]
            end
            out[bid] = pairs
          end
          out
        end
      end
    end

    module_function

    # --- public API ---

    def parse_file(path)
      parse(File.read(path, encoding: "UTF-8"))
    end

    def parse(text)
      lines = text.split("\n", -1) # -1 to preserve trailing empty fields
      # Spec: trailing newline yields one empty element at the end; drop it.
      lines.pop if lines.last == ""

      first = lines.shift
      raise ArgumentError, "missing SPINEL-IR header" unless first
      # Spec §"Format version": loader treats the first line as comment-ish;
      # only "SPINEL-IR v1" is recognised but other text is silently ignored.
      version = first

      records = lines.map.with_index do |line, i|
        parse_line(line, i + 2) # +2: 1-based, after skipped version line
      end

      IR.new(version: version, records: records)
    end

    def dump(ir)
      out = String.new(ir.version)
      out << "\n"
      ir.records.each do |r|
        out << r.raw_line
        out << "\n"
      end
      out
    end

    # --- encoding helpers ---

    def encode(s)
      # Encode '%' first so we don't double-encode the substitutes.
      s = s.gsub("%", "%25")
      s.gsub(/[ \n\r\t|]/) { |c| ENCODE_MAP[c] }
    end

    def decode(s)
      # Decode '%' last for the same reason.
      s = s.gsub(/%(?:20|0A|0D|09|7C)/i) { |m| DECODE_MAP[m.upcase] }
      s.gsub("%25", "%")
    end

    # --- internal record parsing ---

    def parse_line(line, lineno)
      # Records: <tag> <name> [<count>] <payload>
      # We can't naively split on space because payloads may contain
      # encoded spaces (%20). Instead split into 2 or 3 leading tokens.
      tag, rest = split2(line)
      raise ArgumentError, "line #{lineno}: empty tag" if tag.nil? || tag.empty?

      case tag
      when "INT"
        name, payload = split2(rest)
        Record.new(tag: tag, name: name, payload: payload, raw_line: line)
      when "STR"
        name, payload = split2(rest)
        Record.new(tag: tag, name: name, payload: payload || "", raw_line: line)
      when "SA", "IA"
        name, after_name = split2(rest)
        count_s, payload = split2(after_name)
        Record.new(
          tag: tag, name: name,
          count: Integer(count_s),
          payload: payload || "",
          raw_line: line,
        )
      when "T", "NM"
        nid_s, payload = split2(rest)
        Record.new(tag: tag, name: Integer(nid_s), payload: payload || "", raw_line: line)
      when "NB"
        nid_s, payload = split2(rest)
        Record.new(tag: tag, name: Integer(nid_s), payload: payload, raw_line: line)
      when "SN", "ST"
        nid_s, payload = split2(rest)
        Record.new(tag: tag, name: Integer(nid_s), payload: payload || "", raw_line: line)
      else
        raise ArgumentError, "line #{lineno}: unknown tag #{tag.inspect}"
      end
    end

    # Split into [first_token, rest]. nil rest if no separator.
    def split2(s)
      return [nil, nil] if s.nil?
      i = s.index(" ")
      return [s, nil] if i.nil?
      [s[0, i], s[(i + 1)..]]
    end

    # SA payload split: "count e1|e2|...|en". Decodes each element.
    # Pads with empty strings up to count (spec §"Length-prefixed split").
    def split_strs_n(payload, count)
      return [] if count == 0
      parts = (payload || "").split("|", -1)
      parts << "" while parts.length < count
      parts.map { |e| decode(e) }
    end

    # IA payload split: "count e1,e2,...,en". Pads with 0 up to count.
    def split_ints_n(payload, count)
      return [] if count == 0
      parts = (payload || "").split(",", -1)
      parts << "0" while parts.length < count
      parts.map { |e| Integer(e) }
    end

    # Inverse helpers (encode side, useful for synthesizing records in tests).

    def join_strs(arr)
      arr.map { |e| encode(e) }.join("|")
    end

    def join_ints(arr)
      arr.map(&:to_s).join(",")
    end

    def build_record(tag, name, payload, count: nil)
      raw =
        case tag
        when "INT", "STR", "T", "NM", "NB", "SN", "ST"
          "#{tag} #{name} #{payload}"
        when "SA", "IA"
          raise ArgumentError, "SA/IA needs count" if count.nil?
          "#{tag} #{name} #{count} #{payload}"
        else
          raise ArgumentError, "unknown tag #{tag.inspect}"
        end
      Record.new(tag: tag, name: name, count: count, payload: payload, raw_line: raw)
    end
  end
end
