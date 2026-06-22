# frozen_string_literal: true
#
# The spinel-ebpf *plugin* layer — declaration semantics, manifest discovery,
# and ABI validation.
#
# A source declares its plugin dependency with `use_plugin :ebpf`. The CLI:
#   - discovers the plugin by convention + search path (no central registry),
#   - validates the manifest's abi_version,
#   - errors fast when a declared plugin is not installed / abi mismatches,
#   - errors (strict) / warns when the BPF namespace is used WITHOUT a
#     declaration (no silent native fallback).
#
# spinel's native codegen (`-c`) rejects a top-level `use_plugin :ebpf`
# ("unsupported call"), so the directive is stripped (-> comment, line count
# preserved) before any spinel/in-process invocation. Detection runs on the
# original source. This layer adds NO upstream patch; the faithful "spinel is
# the entry that delegates" reversal is deferred to a future upstream PR.

module SpinelEbpf
  module Plugin
    # ABI the CLI implements; a manifest declaring anything else is a load error
    # (GCC-plugin style). Bump when the plugin<->driver contract changes.
    SUPPORTED_ABI = "1"

    # Raised for an installed-but-incompatible plugin (abi mismatch / malformed
    # manifest) and for a declared-but-missing plugin.
    class LoadError < StandardError; end
    # Raised by the build-time arbiter when multiple declared plugins conflict
    # (e.g. claim the same namespace).
    class ArbitrationError < StandardError; end
    # Raised when the BPF namespace is used without `use_plugin` and strict mode
    # is on (SPNL_STRICT_PLUGINS=1).
    class DeclarationError < StandardError; end

    Manifest = Struct.new(:name, :abi_version, :entrypoint, :owns_namespace,
                          :link_libs, :lifecycle, :drive, :root, keyword_init: true)

    # Drive model: who owns the userland run loop.
    #   passive       — no loop (kernel-driven, e.g. pure-XDP slice)
    #   source        — registers fd/timer/ringbuf to the program's loop, owns none
    #   loop-owning   — supplies the main loop (e.g. libuv). At most ONE per build.
    DRIVE_MODELS = %w[passive source loop-owning].freeze

    # Fixed lifecycle phase buckets, in deterministic order. A manifest's
    # `lifecycle` maps hook name -> phase (e.g. init=pre_main); the arbiter
    # orders hooks by this bucket, tie-broken by declaration order.
    LIFECYCLE_PHASES = %w[pre_main before_fork after_fork detach].freeze

    module_function

    # ---------- declaration detection / sanitization ----------

    # `use_plugin :ebpf` / `use_plugin(:ebpf)` as a top-level statement
    # (optional trailing comment). A `#`-led line never matches (so a commented
    # directive is inert).
    DECL_RE = /\A\s*use_plugin\s*\(?\s*:(\w+)\s*\)?\s*(?:#.*)?\z/.freeze

    # Returns the declared plugin names (symbols), in source order, de-duped.
    def detect_declarations(source)
      source.each_line.filter_map { |line| line.chomp[DECL_RE, 1]&.to_sym }.uniq
    end

    # Replace each `use_plugin ...` line with a comment, preserving the line
    # count (so node ids / any line maps are unperturbed) — spinel's -c aborts
    # on the directive otherwise.
    def strip_declarations(source)
      source.each_line.map do |line|
        line.match?(/\A\s*use_plugin\b/) ? "# [spinel-ebpf plugin directive] #{line}" : line
      end.join
    end

    # ---------- discovery (convention + search path, no central registry) ----------

    # Search path: $SPINEL_PLUGIN_PATH (':'-sep), then the bundled spinel-ebpf
    # project root (so the in-tree plugin finds itself), then ~/.spinel/plugins.
    def search_paths
      paths = []
      env = ENV["SPINEL_PLUGIN_PATH"]
      paths.concat(env.split(File::PATH_SEPARATOR)) if env && !env.empty?
      paths << File.expand_path(File.join(__dir__, "..", "..")) # project root (bundled)
      paths << File.expand_path("~/.spinel/plugins")
      paths.uniq
    end

    # `:ebpf` -> the manifest whose name == "ebpf", found either at
    # `<dir>/plugin.toml` (bundled/self) or `<dir>/spinel-<name>/plugin.toml`
    # (convention). Returns a Manifest or nil.
    def discover(name)
      want = name.to_s
      search_paths.each do |dir|
        [File.join(dir, "plugin.toml"),
         File.join(dir, "spinel-#{want}", "plugin.toml")].each do |cand|
          next unless File.file?(cand)
          m = load_manifest(cand)
          return m if m && m.name == want
        end
      end
      nil
    end

    # ---------- manifest (minimal TOML subset) ----------

    def load_manifest(path)
      # Force UTF-8: a container/CI locale may default external encoding to
      # US-ASCII, which would choke on non-ASCII manifest comments.
      data = parse_toml(File.read(path, encoding: "UTF-8"))
      Manifest.new(
        name: data["name"], abi_version: data["abi_version"]&.to_s,
        entrypoint: data["entrypoint"], owns_namespace: Array(data["owns_namespace"]),
        link_libs: Array(data["link_libs"]), lifecycle: data["lifecycle"] || {},
        drive: data["drive"] || "passive",
        root: File.dirname(File.expand_path(path)),
      )
    rescue StandardError => e
      raise LoadError, "malformed plugin manifest #{path}: #{e.message}"
    end

    # Build-time arbiter. Given the manifests for all declared plugins, enforce
    # cross-plugin invariants. Foundation: **namespace exclusivity** — a
    # namespace token (owns_namespace entry) has exactly one owner; two plugins
    # claiming the same token is a hard error. (Lifecycle ordering / single
    # run-loop owner await a real second plugin to exercise.)
    def arbitrate!(manifests)
      # (1) namespace exclusivity — a namespace token has exactly one owner.
      owner = {} # namespace token -> claiming plugin name
      manifests.each do |m|
        m.owns_namespace.each do |ns|
          prev = owner[ns]
          if prev && prev != m.name
            raise ArbitrationError,
                  "plugin namespace conflict: `#{ns}` is claimed by both " \
                  "'#{prev}' and '#{m.name}' — a namespace has exactly one owner. " \
                  "Resolve by narrowing one plugin's owns_namespace."
          end
          owner[ns] = m.name
        end
      end

      # (2) single run-loop owner — at most one loop-owning plugin.
      loop_owners = manifests.select { |m| m.drive == "loop-owning" }.map(&:name)
      if loop_owners.size > 1
        raise ArbitrationError,
              "run-loop conflict: plugins #{loop_owners.map { |n| "'#{n}'" }.join(' and ')} " \
              "are both loop-owning — a build has at most one. " \
              "Make all but one 'source'-contributing."
      end

      manifests
    end

    # Deterministic lifecycle plan across declared plugins — hooks grouped into
    # fixed phase buckets (LIFECYCLE_PHASES order), tie-broken by declaration
    # order. Returns [[phase, plugin_name, hook_name], ...]. This is the order a
    # driver fires init/fork/fini hooks; foundation for real multi-plugin
    # composition (single-plugin = its own hooks in phase order).
    def lifecycle_order(manifests)
      plan = []
      LIFECYCLE_PHASES.each do |phase|
        manifests.each do |m|
          (m.lifecycle || {}).each do |hook, ph|
            plan << [phase, m.name, hook] if ph == phase
          end
        end
      end
      plan
    end

    # Discover + ABI-validate every declared plugin, then arbitrate the set.
    # Returns the validated manifests. Raises LoadError (missing/abi) — caller
    # maps a nil discovery to its own "not installed" message — or
    # ArbitrationError (cross-plugin conflict).
    def resolve_all(names)
      manifests = names.map do |name|
        m = discover(name) or raise LoadError, "plugin '#{name}' not installed"
        validate!(m)
      end
      arbitrate!(manifests)
    end

    # Validate a discovered manifest against the driver's SUPPORTED_ABI + drive model.
    def validate!(manifest)
      unless manifest.abi_version == SUPPORTED_ABI
        raise LoadError,
              "plugin '#{manifest.name}' abi_version #{manifest.abi_version.inspect} " \
              "!= driver #{SUPPORTED_ABI.inspect} (manifest #{manifest.root}/plugin.toml)"
      end
      unless DRIVE_MODELS.include?(manifest.drive)
        raise LoadError,
              "plugin '#{manifest.name}' drive #{manifest.drive.inspect} unknown " \
              "(expected #{DRIVE_MODELS.join('/')})"
      end
      manifest
    end

    # Flat-key TOML subset: `key = "s"` / `["a","b"]` / `123` / inline table
    # `{ k = "v", ... }`. Full-line `#` comments + `[section]` headers ignored.
    def parse_toml(text)
      data = {}
      text.each_line do |raw|
        line = raw.strip
        next if line.empty? || line.start_with?("#", "[")
        key, sep, val = line.partition("=")
        next if sep.empty?
        k = key.strip
        data[k] = parse_toml_value(val.strip) unless k.empty?
      end
      data
    end

    def parse_toml_value(val)
      case val
      when /\A"(.*)"\z/, /\A'(.*)'\z/ then Regexp.last_match(1)
      when /\A\[(.*)\]\z/m
        Regexp.last_match(1).split(",").map { |e| parse_toml_value(e.strip) }.reject { |e| e == "" }
      when /\A\{(.*)\}\z/m
        Regexp.last_match(1).split(",").each_with_object({}) do |pair, h|
          pk, sep, pv = pair.partition("=")
          h[pk.strip] = parse_toml_value(pv.strip) unless sep.empty? || pk.strip.empty?
        end
      when /\A-?\d+\z/ then val.to_i
      else val
      end
    end

    # ---------- namespace-usage signal (for the undeclared check) ----------

    # The program uses the BPF plugin namespace if partition produced any
    # eBPF-tagged method (attach handler / DSL / builtin-bearing). Pure-native
    # programs return false and need no declaration.
    def uses_bpf_namespace?(partition_result)
      partition_result.methods.any? { |m| m.tag == :ebpf }
    end

    def strict?
      ENV["SPNL_STRICT_PLUGINS"] == "1"
    end
  end
end
