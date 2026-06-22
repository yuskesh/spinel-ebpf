# frozen_string_literal: true

# BtfSchema: derive kernel struct field schemas from BTF instead of
# hand-written tables. Reads the same BTF the build already dumps for
# vmlinux.h (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`) and scans
# the requested struct's field declarations.
#
# Used by the tracepoint codegen to auto-resolve `trace_event_raw_<event>` field
# names + types (incl. detecting a __u8[4] address array as the "ipv4" read),
# so new tracepoints no longer need a manual TRACEPOINT_FIELDS entry.
#
# This is BEST-EFFORT: when BTF / bpftool is unavailable (e.g. the host macOS
# unit-test run), `available?` is false and callers fall back to the hand-written
# tables — so behavior is unchanged where BTF can't be read.
module SpinelEbpf
  class BtfSchema
    # Env knobs:
    #   SPNL_BTF=/path/to/btf   override the BTF source (default /sys/kernel/btf/vmlinux)
    #   SPNL_BTF=off            disable BTF derivation (force table fallback)
    DEFAULT_BTF = "/sys/kernel/btf/vmlinux"

    def initialize(btf_path: ENV["SPNL_BTF"], bpftool: ENV["SPNL_BPFTOOL"] || "bpftool")
      @btf_path = btf_path && !btf_path.empty? ? btf_path : DEFAULT_BTF
      @disabled = btf_path == "off"
      @bpftool  = bpftool
      @loaded   = false
      @load_ok  = false
      @text     = nil
      @raw      = nil
      @raw_loaded = false
      @struct_cache = {}   # struct_name => { field => spnl_type } | nil
      @func_cache   = {}   # func_name   => [param_name, ...] | nil
      @enum_cache   = {}   # enumerator  => Integer | nil
    end

    # True when BTF could be loaded and queried on this host.
    def available?
      ensure_loaded
      @load_ok
    end

    # Resolve the BTF struct to cast a tracepoint ctx to. Returns the struct name
    # when a *complete* `trace_event_raw_<event>` definition exists in BTF, else
    # nil (caller applies its template-override table / default).
    def tracepoint_struct(event)
      return nil unless available?
      name = "trace_event_raw_#{event}"
      struct_fields(name) ? name : nil
    end

    # Map a struct's field to a spnl-ebpf tracepoint field type:
    #   "int"  scalar integer / enum / pointer (read the value / pointer)
    #   "ipv4" a 4-byte unsigned char array (read as a u32, network order)
    #   nil    field absent, or a type we can't auto-read (struct/long array/...)
    # Returns nil when BTF is unavailable so the caller falls back to its table.
    def field_type(struct_name, field)
      return nil unless available?
      f = struct_fields(struct_name)
      f && f[field]
    end

    # Parsed { field => spnl_type } for a struct, or nil if the struct has no
    # complete definition in BTF. Cached.
    def struct_fields(struct_name)
      return nil unless available?
      return @struct_cache[struct_name] if @struct_cache.key?(struct_name)
      @struct_cache[struct_name] = parse_struct(struct_name)
    end

    # Ordered parameter names of a kernel function, from its BTF FUNC /
    # FUNC_PROTO. Returns e.g. ["sk", "msg", "size"] for tcp_sendmsg,
    # or nil if BTF is unavailable / the function isn't in BTF. Cached.
    def func_params(func_name)
      return nil unless available?
      return @func_cache[func_name] if @func_cache.key?(func_name)
      @func_cache[func_name] = parse_func_params(func_name)
    end

    # Resolve an enumerator value from BTF (named or anonymous ENUM / ENUM64),
    # e.g. enum_value("XDP_PASS") => 2, enum_value("TCP_CLOSE")
    # => 7. Returns nil when BTF is unavailable or the name isn't an enumerator
    # (macros like TCP_FLAG_* / ETH_P_* aren't in BTF and stay table-driven).
    def enum_value(name)
      return nil unless available?
      return @enum_cache[name] if @enum_cache.key?(name)
      @enum_cache[name] = parse_enum_value(name)
    end

    private

    # Enumerator lines are `'<name>' val=<N>` (signed decimal or 0x hex); BTF
    # FUNC_PROTO params use `type_id=`, so matching `val=` is unambiguous.
    def parse_enum_value(name)
      raw = @raw || raw_text
      return nil unless raw
      m = raw.match(/^\s+'#{Regexp.escape(name)}'\s+val=(-?0x[0-9a-fA-F]+|-?\d+)/)
      return nil unless m
      Integer(m[1])
    end

    # Lazy raw BTF dump (has FUNC / FUNC_PROTO entries that `format c` omits).
    def raw_text
      return @raw if @raw_loaded
      @raw_loaded = true
      return (@raw = nil) if @disabled || !File.exist?(@btf_path)
      out = `#{@bpftool} btf dump file #{@btf_path} format raw 2>/dev/null`
      @raw = ($?.success? && out && !out.empty?) ? out : nil
    rescue StandardError
      @raw = nil
    end

    # Find `FUNC '<name>' type_id=<P>`, then the `[P] FUNC_PROTO ... vlen=V`
    # block whose next V indented `'<param>' type_id=...` lines give the params.
    def parse_func_params(func_name)
      raw = @raw || raw_text
      return nil unless raw
      m = raw.match(/^\[\d+\]\s+FUNC\s+'#{Regexp.escape(func_name)}'\s+type_id=(\d+)/)
      return nil unless m
      proto_id = m[1]
      pm = raw.match(/^\[#{proto_id}\]\s+FUNC_PROTO\b[^\n]*\bvlen=(\d+)(.*?)(?=^\[\d+\]\s|\z)/m)
      return nil unless pm
      vlen = pm[1].to_i
      names = pm[2].scan(/^\s+'([^']*)'\s+type_id=\d+/).flatten
      names = names.first(vlen)
      # Anonymous params (no name in BTF) can't be resolved by name -> give up
      # so the caller falls back to positional extraction.
      return nil if names.any?(&:empty?) || names.length != vlen
      names
    end

    def ensure_loaded
      return if @loaded
      @loaded = true
      return if @disabled
      return unless File.exist?(@btf_path)
      # `format c` gives the same header text we generate for vmlinux.h; scanning
      # one struct out of it is cheap and avoids a full BTF/JSON parse.
      text = `#{@bpftool} btf dump file #{@btf_path} format c 2>/dev/null`
      if $?.success? && text && !text.empty?
        @text = text
        @load_ok = true
      end
    rescue StandardError
      @load_ok = false
    end

    # Find `struct <name> { ... };` in the dumped header and parse its members.
    def parse_struct(struct_name)
      return nil unless @text
      start = @text.index("struct #{struct_name} {")
      return nil unless start
      open_brace = @text.index("{", start)
      close = @text.index("\n};", open_brace)
      return nil unless close
      body = @text[(open_brace + 1)...close]

      fields = {}
      body.each_line do |line|
        line = line.strip
        next if line.empty? || line.start_with?("/*")
        t = parse_member(line)
        next unless t
        fields[t[0]] = t[1]
      end
      fields.empty? ? nil : fields
    end

    # Parse one C member declaration line -> [field_name, spnl_type] or nil.
    # Handles: scalars, pointers, and __u8[N] arrays. Skips bitfields, function
    # pointers, anonymous members, and the flexible `char __data[0]` trailer.
    def parse_member(line)
      return nil if line.include?(":")          # bitfield
      return nil if line.include?("(")          # function pointer / fn-like
      m = line.match(/\A(?<type>[\w\s]+?)\s*(?<ptr>\**)\s*(?<name>\w+)\s*(?:\[(?<arr>\d+)\])?\s*;\z/)
      return nil unless m
      name = m[:name]
      type = m[:type].strip
      ptr  = m[:ptr]
      arr  = m[:arr]&.to_i

      # pointer field -> read the pointer value as an integer
      return [name, "int"] unless ptr.empty?

      if arr
        # __u8[4] / unsigned char[4] -> an IPv4 address read as a u32
        return [name, "ipv4"] if byte_type?(type) && arr == 4
        # other arrays aren't a single readable scalar
        return nil
      end

      return [name, "int"] if scalar_int?(type)
      nil
    end

    def byte_type?(type)
      %w[__u8 u8 unsigned\ char char __s8 s8 u_char].include?(type)
    end

    def scalar_int?(type)
      return true if type =~ /\A(__[us](8|16|32|64)|u(8|16|32|64)|s(8|16|32|64))\z/
      %w[
        int unsigned\ int short unsigned\ short long unsigned\ long
        long\ long unsigned\ long\ long char unsigned\ char signed\ char
        bool _Bool size_t ssize_t pid_t uid_t gid_t loff_t sector_t dev_t
        umode_t u_int u_long __kernel_pid_t
      ].include?(type)
    end
  end
end
