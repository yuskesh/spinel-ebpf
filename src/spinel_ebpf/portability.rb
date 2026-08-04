# frozen_string_literal: true

# The portability contract, stated per partition.
#
# Upstream spinel's promise is "emit one self-contained .c, ship it, build it
# anywhere with any cc" (README "Portability"). Adding eBPF narrows that -- but
# it narrows it only for the *eBPF partition*. The native partition keeps the
# upstream contract verbatim (`--native-only` output is byte-identical to
# `spinel -c`; tools/form_verify.sh gates it).
#
# So the contract is not a property of the program, it is a property of each
# side of the partition. This module computes it and states it out loud, in the
# same spirit as the partition table: the reader never has to guess where a
# probe will run.
#
# The kernel floor is derived from what the generated .bpf.c actually uses.
# Entries live in MIN_KERNEL only when we are confident about the version;
# anything else lands in `undeclared` instead of inventing a number. An unknown
# is reported as unknown, never as a guess.
#
# The same rule governs *where the artifact can travel* (ARCH_NOTE /
# ENDIAN_NOTE below): we state the endianness the skeleton was built for, and
# we call a big-endian target untested rather than supported or broken.
module SpinelEbpf
  module Portability
    # CO-RE relocation + BTF. Every eBPF partition we emit goes through
    # BPF_CORE_READ / libbpf CO-RE, so this is the floor under all of them.
    BASE_EBPF_KERNEL = "5.2"

    # Endianness is the one axis on which eBPF bytecode is *not* neutral, and
    # the contract used to claim it was ("architecture-independent", unqualified).
    #
    # Correction: clang has three BPF targets -- `bpf` (host byte order),
    # `bpfel`, `bpfeb` -- and upstream tooling treats the choice as a build-time
    # axis. ebpf-go's bpf2go defaults its target to "bpfel,bpfeb", i.e. it always
    # emits one object per endianness, and its GOARCH table routes s390x / mips /
    # mips64 / ppc64 to bpfeb.
    #
    # We build with `clang -target bpf` (bin/spinel-ebpf, bpf_clang_argv), so
    # the skeleton we ship carries bytecode in the BUILD HOST's byte order.
    #
    # What we say is therefore bounded by what we know: neutrality holds within
    # one endianness, and crossing endianness is *untested* -- not "broken",
    # not "fine". That is the same discipline as UNDECLARED above: an unknown is
    # reported as unknown rather than resolved by guessing.
    ARCH_NOTE = "eBPF bytecode is architecture-independent **within one endianness** " \
                "(what CO-RE fixes up at run time is the layout of kernel structs, " \
                "not the byte order of the instruction stream). Within that range, " \
                "shipping the generated skeleton is enough: the destination needs " \
                "neither clang nor bpftool"

    ENDIAN_NOTE = "this skeleton was built with `clang -target bpf` = **the build host's " \
                  "endianness** (clang's BPF targets are bpf / bpfel / bpfeb, and upstream " \
                  "tooling builds one object per endianness -- bpf2go's default target is " \
                  "`bpfel,bpfeb`). Every host spinel-ebpf has built and run on is arm64 or " \
                  "x86_64, both little-endian, so **shipping across an endianness boundary " \
                  "(big-endian s390x / mips / ppc64 and the like) is untested** -- not known " \
                  "to be broken, just not verified"

    # --- arch binding --------------------------------------------------------
    #
    # The endianness bound above was still not the whole story: for a subset of
    # probes portability breaks *before* endianness ever comes up, between two
    # little-endian architectures.
    #
    # Measured on an arm64 host over the whole golden corpus as it stood at the
    # time (118 units):
    #
    #   PT_REGS_PARM or USDT   35 + 2 = 37 units   -D__TARGET_ARCH_x86 -> 0 compile
    #   neither                     81 units       -D__TARGET_ARCH_x86 -> 80 compile,
    #                                              all 80 instruction-identical to
    #                                              the arm64 build (the 81st fails
    #                                              under BOTH macros, for an
    #                                              arch-independent reason)
    #
    # Why: vmlinux.h is generated from the RUNNING kernel's BTF, so on arm64
    # `struct pt_regs` carries `regs[]` and has no `di` / `si` / `dx`.
    # PT_REGS_PARM<N> picks a FIELD NAME at preprocessing time, and CO-RE
    # relocates a field's *offset* -- it cannot conjure a field that the struct
    # does not have. So the choice is baked at compile time, not at load time.
    #
    # Two refinements the measurement forced on the initial hypothesis, both of
    # which the predicate below encodes:
    #
    #   * it is not "kprobe" that binds the arch, it is READING ARGUMENTS FROM
    #     REGISTERS. A handler on the same attach point with no parameters emits
    #     no PT_REGS_PARM and builds BYTE-IDENTICAL under both macros (measured
    #     with a matched pair through the real pipeline).
    #   * the dependency is not always visible as PT_REGS_PARM in our own
    #     output. USDT pulls in <bpf/usdt.bpf.h>, which reads `pt_regs.ip`
    #     itself, so two USDT goldens with zero PT_REGS_PARM still fail under
    #     the foreign macro.
    #
    # What we deliberately do NOT say: "this will not work on another arch".
    # What was measured is "THIS HOST cannot build it for that arch" -- the
    # behaviour of a correctly built object on its own architecture was not
    # measured, and a probe has been shipped to a foreign machine by supplying
    # that machine's BTF (SPNL_BTF_PATH). Same discipline as UNDECLARED and
    # ENDIAN_NOTE: report the bound that was measured, not the one that would
    # sound decisive.
    ARCH_BOUND_MARKERS = {
      "PT_REGS_PARM" =>
        "reads kprobe / uprobe handler arguments out of registers (`PT_REGS_PARM<N>`)",
      # Both markers describe the same binding, worded identically so that a
      # unit hitting both reports it once (the values are uniq'd, not the keys).
      "bpf_usdt_arg" =>
        "reads USDT arguments (`<bpf/usdt.bpf.h>` itself reads `pt_regs.ip`)",
      "usdt.bpf.h" =>
        "reads USDT arguments (`<bpf/usdt.bpf.h>` itself reads `pt_regs.ip`)",
    }.freeze

    # Stated when the unit IS bound: names the arch it was built for, says what
    # binds it, and says what it costs to target another one.
    def self.arch_bound_note(arch, reasons)
      "this unit is **built and verified for #{arch} only** (architecture-bound). " \
      "It #{reasons.join(" / ")}, which **picks a field name of `struct pt_regs` at " \
      "compile time** (`vmlinux.h` comes from the BTF of the running kernel; what CO-RE " \
      "can fix up at run time is a field's offset, and **it cannot create a field that " \
      "is not there**). Measured on an arm64 host: building the same source with " \
      "`-D__TARGET_ARCH_x86` **does not compile** -- `no member named '...' in 'struct " \
      "pt_regs'` (di/si/dx for `PT_REGS_PARM`, ip for USDT). To ship it for another " \
      "architecture, **rebuild it against that architecture's BTF**. " \
      "**This is not a finding that it fails to run elsewhere** -- what was measured " \
      "stops at \"this host cannot build it for that target\"; the behaviour given the " \
      "right BTF was not measured, and shipping to another machine by carrying that " \
      "machine's BTF (`SPNL_BTF_PATH`) has been demonstrated"
    end

    # Stated when it is NOT bound: the same portability the contract used to
    # claim for everything, now claimed only where it was measured.
    ARCH_FREE_NOTE = "this unit **does not read arguments out of registers** " \
                     "(no `PT_REGS_PARM`, no USDT), so it is not bound to an architecture. " \
                     "Measured: of the golden corpus, all 80 units in this class built " \
                     "under **both** `-D__TARGET_ARCH_arm64` and `-D__TARGET_ARCH_x86`, " \
                     "and the instruction streams matched. The only limit left is the " \
                     "endianness one below"

    Feature = Struct.new(:key, :kernel, :why, keyword_init: true)

    # marker (matched against the generated .bpf.c) => Feature
    MIN_KERNEL = {
      "bpf_ringbuf_reserve" =>
        Feature.new(key: "ringbuf", kernel: "5.8", why: "BPF ring buffer (how spnl_emit* gets out)"),
      'SEC("xdp' =>
        Feature.new(key: "xdp", kernel: "5.9", why: "attaching XDP through a bpf_link (does not displace an incumbent, and detaches itself even on SIGKILL)"),
      'SEC("tcx/' =>
        Feature.new(key: "tcx", kernel: "6.6", why: "TC attach via tcx (bpf_mprog) -- coexists with an incumbent"),
      'SEC("fentry/' =>
        Feature.new(key: "fentry", kernel: "5.5", why: "fentry through the BPF trampoline"),
      'SEC("fexit/' =>
        Feature.new(key: "fexit", kernel: "5.5", why: "fexit through the BPF trampoline"),
      'SEC("fmod_ret/' =>
        Feature.new(key: "fmod_ret", kernel: "5.6", why: "fmod_ret (replacing a return value = blocking)"),
      'SEC("lsm/' =>
        Feature.new(key: "lsm", kernel: "5.7", why: "BPF LSM"),
      # kprobe_multi attaches to thousands of symbols with one program and one
      # link, at the cost of raising the floor from plain kprobe (5.2) to 5.18.
      # What measurement caught is that without this row a multi probe declares
      # `>= 5.8` (inherited from ringbuf) -- an UNDER-declaration, the one
      # direction a portability contract must never get wrong. Choosing
      # `via: :expand` keeps the floor at 5.2, which makes this the one case
      # where picking a mechanism moves the deployment constraint.
      'SEC("kprobe.multi' =>
        Feature.new(key: "kprobe_multi", kernel: "5.18",
                    why: "kprobe_multi (one definition -> many symbols, per-symbol cookie)"),
      'SEC("iter/' =>
        Feature.new(key: "bpf_iter", kernel: "5.8", why: "BPF_ITER (enumerating kernel objects)"),
      'SEC("sk_lookup' =>
        Feature.new(key: "sk_lookup", kernel: "5.9", why: "sk_lookup programs"),
      "bpf_loop" =>
        Feature.new(key: "bpf_loop", kernel: "5.17", why: "bpf_loop (n.times with a dynamic count)"),
      "bpf_iter_num_new" =>
        Feature.new(key: "open_coded_iter", kernel: "6.4", why: "open-coded iterator (n.times with a literal count)"),
      # Two unrelated surfaces reach this marker and the `why` has to name both,
      # or an author of a TCP slice reads "on :timer" and concludes the line is
      # not about their probe. `on :timer` arms one timer in an array slot at
      # load time; the pure-XDP TCP slice embeds one per CONNECTION in the
      # LRU_HASH value and arms it from BPF. Same struct, same floor.
      "bpf_timer_init" =>
        Feature.new(key: "bpf_timer", kernel: "5.15",
                    why: "bpf_timer (on :timer, and the TCP slice's per-connection time-to-live)"),
      "bpf_user_ringbuf_drain" =>
        Feature.new(key: "user_ringbuf", kernel: "6.1", why: "USER_RINGBUF (the host -> kernel command channel)"),
      "bpf_task_storage_get" =>
        Feature.new(key: "task_storage", kernel: "5.11", why: "task local storage"),
      "bpf_d_path" =>
        Feature.new(key: "d_path", kernel: "5.10", why: "bpf_d_path (reading a full path)"),
      # bpf_tail_call plus PROG_ARRAY. This entry can never BE the floor: every
      # program that can hold either is an XDP program, so SEC("xdp") at 5.9
      # always dominates it. It is here as a record, not as a constraint --
      # a MISSING marker was measured to cost a multi-symbol probe declaring 5.8
      # when it needed 5.18, which is under-reporting, the one direction this
      # contract may never take. The cheap defence is to state the floor of every
      # feature rather than only the ones expected to win.
      "BPF_MAP_TYPE_PROG_ARRAY" =>
        Feature.new(key: "prog_array", kernel: "4.2",
                    why: "bpf_tail_call + PROG_ARRAY (transferring control to an xdp_tail__ target)"),
      # SO_REUSEPORT selection. Like PROG_ARRAY above, this can never BE the
      # floor -- 4.19 is below BASE_EBPF_KERNEL (5.2) -- and it is here for the
      # same reason. BPF_PROG_TYPE_SK_REUSEPORT, the socket array it selects from
      # and bpf_sk_select_reuseport all arrived together in 4.19; the older
      # SO_ATTACH_REUSEPORT_EBPF (4.5) took a SOCKET_FILTER program, which is a
      # different thing and not what this code generator emits.
      'SEC("sk_reuseport' =>
        Feature.new(key: "sk_reuseport", kernel: "4.19",
                    why: "BPF_PROG_TYPE_SK_REUSEPORT (choosing within an SO_REUSEPORT group)"),
      "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY" =>
        Feature.new(key: "reuseport_sockarray", kernel: "4.19",
                    why: "REUSEPORT_SOCKARRAY + bpf_sk_select_reuseport (the table worker_select indexes)"),
      # The pure-XDP TCP slice. The two raw SYN-cookie kfuncs arrived together in
      # 6.8, which makes this the HIGHEST floor any generated program carries --
      # higher than SEC("xdp") at 5.9, higher than the bpf_timer at 5.15 the
      # slice also embeds, and higher than USER_RINGBUF at 6.1, which was the
      # previous ceiling. So unlike the two entries above, this one is not a
      # record: on a slice probe it IS the floor.
      #
      # Two markers rather than one, because the seven builtins can be used
      # WITHOUT the bundle (the hand-written slice surface): whichever of the two
      # appears, the frame is being handed to a raw syncookie kfunc.
      "bpf_tcp_raw_gen_syncookie_ipv4" =>
        Feature.new(key: "tcp_raw_syncookie", kernel: "6.8",
                    why: "bpf_tcp_raw_gen_syncookie_ipv4 (the pure-XDP TCP slice's handshake)"),
      "bpf_tcp_raw_check_syncookie_ipv4" =>
        Feature.new(key: "tcp_raw_syncookie", kernel: "6.8",
                    why: "bpf_tcp_raw_check_syncookie_ipv4 (the pure-XDP TCP slice's handshake)"),
      "BPF_MAP_TYPE_ARENA" =>
        Feature.new(key: "arena", kernel: "6.9", why: "bpf_arena (shared memory)"),
      "sched_ext_ops" =>
        Feature.new(key: "sched_ext", kernel: "6.12", why: "sched_ext (CPU scheduler)"),
    }.freeze

    # Features whose minimum we have not established. Reported by name so the
    # reader knows the floor below is a lower bound, not the whole story.
    UNDECLARED = {
      "Qdisc_ops"           => "BPF qdisc (struct_ops/Qdisc_ops)",
      "tcp_congestion_ops"  => "TCP congestion control (struct_ops/tcp_congestion_ops)",
      # The shape shipped here puts `bpf_tail_call` inside `<name>_inner`, a
      # `static __noinline` function -- the kernel's own translated dump confirms
      # it is a real BPF-to-BPF subprogram (a call instruction, then the tail
      # call inside it) and not something clang inlined away. Mixing BPF-to-BPF
      # calls with tail calls is a later, per-architecture-JIT capability than
      # PROG_ARRAY itself (4.2, declared above), so the 4.2 line is the floor of
      # the feature and NOT the floor of this shape. Measured working on
      # 7.1.5 / aarch64 (17 of 20 packets jumped). The exact kernel where it
      # started working is not established here, so it is reported as unknown
      # rather than guessed.
      "bpf_tail_call"       => "a bpf_tail_call made from a subprogram (`_inner`) -- later than " \
                               "PROG_ARRAY's own 4.2 and dependent on the architecture's JIT " \
                               "(measured working on 7.1.5/aarch64; the floor was not measured)",
    }.freeze

    # Runtime conditions that no compile-time check can settle -- the probe
    # loads and attaches, and then does or does not fire. The silent LSM is
    # exactly this class, so it is stated here rather than discovered.
    RUNTIME_CAVEATS = {
      'SEC("lsm/' =>
        "BPF LSM needs `lsm=...,bpf` on the kernel command line. Where it is not enabled, " \
        "load and attach still succeed and **only the firing does not happen** (a silent " \
        "failure). Use fmod_ret when it has to take effect",
      'SEC("xdp' =>
        "if another XDP program is already on the target interface, attach fails loudly with " \
        "EBUSY (the incumbent is not displaced). Name the interface with SPNL_XDP_IFACE",
      'SEC("tcx/' =>
        "name the target interface with SPNL_TCX_IFACE (being tcx, it coexists with an incumbent)",
      'SEC("sk_reuseport' =>
        "the loader does not attach this one -- the SO_REUSEPORT listening socket is created by " \
        "the probe itself, so the probe's own userspace half has to call " \
        "`sp_bpf_reuseport_attach(listen_fd, \"sk_reuseport__<name>\")`. Without that call the " \
        "program is loaded and **never fires once**",
      "bpf_user_ringbuf_drain" =>
        "**a record is a fixed 8 bytes** -- the generated callback reads `sizeof(__s64)` with " \
        "`bpf_dynptr_read`. Sending a shorter record from a hand-rolled pusher (code driving " \
        "libbpf reserve/submit directly) makes **the callback fire and the count rise while only " \
        "the value stays 0**: `bpf_dynptr_read` returns -E2BIG and gives up silently (measured). " \
        "A check that looks only at the count passes this failure, so look at **both the count " \
        "and the value**. Using the bundled `sp_bpf_user_cmd_push(value)` avoids the hole " \
        "entirely. Note also that **if nobody pushes, the drain simply returns 0 records**, which " \
        "is silent too: \"no command arrived\" and \"the sender is broken\" are indistinguishable " \
        "in anything the probe emits",
      "bpf_sk_select_reuseport" =>
        "naming an empty slot -- one no worker registered with `sp_bpf_reuseport_register` -- " \
        "**is not an error**: the kernel quietly falls back to its own 5-tuple spread, so " \
        "\"the program chose\" and \"the kernel chose\" cannot be told apart from where the " \
        "connections land. To check it, ask for a **skew the default spread cannot produce** and " \
        "measure that",
    }.freeze

    Contract = Struct.new(:native, :ebpf, keyword_init: true)

    # native side: upstream spinel's contract, verbatim.
    NATIVE_CONTRACT = {
      "platform"  => "POSIX (Linux / macOS / *BSD)",
      "toolchain" => "any C compiler (gcc / clang)",
      "note"      => "upstream spinel's portability, unchanged. The --native-only output is " \
                     "byte-identical to `spinel -c`",
    }.freeze

    # The architecture the eBPF object is being built for. Mirrors exactly how
    # bin/spinel-ebpf (bpf_clang_argv) picks -D__TARGET_ARCH_*, so the contract
    # names the arch the compiler was actually told about rather than a guess.
    def self.build_arch
      RbConfig::CONFIG["host_cpu"].to_s =~ /aarch64|arm64/ ? "arm64" : "x86_64"
    end

    # Compute the contract for one compiled unit.
    #
    # bpf_c_source: the generated .bpf.c text ("" / nil when the unit has no
    # eBPF partition, in which case only the native contract applies).
    # build_arch: overridable so the contract can be exercised for an arch other
    # than the one running the tests.
    def self.contract(bpf_c_source, build_arch: self.build_arch)
      src = bpf_c_source.to_s
      return Contract.new(native: NATIVE_CONTRACT, ebpf: nil) if src.empty?

      hits = MIN_KERNEL.select { |marker, _| src.include?(marker) }.values
      floor = ([BASE_EBPF_KERNEL] + hits.map(&:kernel)).max_by { |v| version_key(v) }
      caveats = RUNTIME_CAVEATS.select { |marker, _| src.include?(marker) }.values
      undeclared = UNDECLARED.select { |marker, _| src.include?(marker) }.values

      # Derived from the generated source, like every other line of this
      # contract -- never a hand-applied attribute on the probe.
      bound_by = ARCH_BOUND_MARKERS.select { |marker, _| src.include?(marker) }.values.uniq

      ebpf = {
        "platform"    => "Linux only",
        "min_kernel"  => floor,
        "requires"    => [
          "BTF (CONFIG_DEBUG_INFO_BTF=y) -- CO-RE relocates against kernel structs at run time",
          "root, or CAP_BPF / CAP_PERFMON",
        ],
        "reasons"     => hits.sort_by { |f| [version_key(f.kernel), f.key] }.reverse
                             .map { |f| { "feature" => f.key, "kernel" => f.kernel, "why" => f.why } },
        "caveats"     => caveats,
        "undeclared"  => undeclared,
        "arch_note"   => ARCH_NOTE,
        "endian_note" => ENDIAN_NOTE,
        # --- the arch verdict; the keys above keep their meaning unchanged ---
        "build_arch"     => build_arch,
        "arch_bound"     => !bound_by.empty?,
        "arch_bound_by"  => bound_by,
        "arch_unit_note" => bound_by.empty? ? ARCH_FREE_NOTE : arch_bound_note(build_arch, bound_by),
      }
      Contract.new(native: NATIVE_CONTRACT, ebpf: ebpf)
    end

    def self.version_key(v)
      v.split(".").map(&:to_i)
    end

    # Human-readable block, printed right after the partition table so that
    # "which side does this run on" and "what does that side require" are read
    # together.
    def self.human(contract)
      out = []
      out << "## portability contract"
      out << "   native  : #{contract.native["platform"]} / #{contract.native["toolchain"]}"
      if (e = contract.ebpf)
        out << "   eBPF    : #{e["platform"]} / kernel >= #{e["min_kernel"]} + BTF + root(CAP_BPF)"
        e["reasons"].each { |r| out << "             - #{r["kernel"]}: #{r["feature"]} -- #{r["why"]}" }
        unless e["undeclared"].empty?
          e["undeclared"].each { |u| out << "             - (floor not established) #{u}" }
        end
        # Where the artifact can travel belongs next to which kernel it needs:
        # both answer "what does shipping this cost me". Endianness is stated
        # every time, because it is a property of the emitted bytecode itself
        # and not of the features the probe happens to use.
        #
        # The verdict for THIS unit goes on the `arch` line, and the general
        # property of bytecode is demoted below it. The other order was tried and
        # rejected: a reader (or an AI) who stops after the first line would come
        # away with "architecture-independent" about a unit that cannot even be
        # built for another arch. `!` marks the bound case as a cost, the same
        # convention the caveats use.
        out << "   arch    : #{e["arch_bound"] ? "! " : ""}#{e["arch_unit_note"]}"
        out << "             (in general) #{e["arch_note"]}"
        out << "   ! #{e["endian_note"]}"
        e["caveats"].each { |c| out << "   ! #{c}" }
      else
        out << "   eBPF    : (none -- this unit is entirely native)"
      end
      out.join("\n")
    end

    def self.to_h(contract)
      { "native" => contract.native, "ebpf" => contract.ebpf }
    end
  end
end
