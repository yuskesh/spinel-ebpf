# frozen_string_literal: true
#
# The capability registry: what a probe can do, grouped by domain.
#
# The probe DSL's builtins -- the ones that run in the kernel -- are classified
# here into domains: observability, enforcement, networking and L7. This is
# metadata about the language, not part of it.
#
# What it is for:
#   * Builtins stay flat. They are deliberately not renamed into dotted
#     namespaces, because that would cost the ergonomics of writing a probe in one
#     sitting. This module adds no language mechanism; it is data that classifies
#     what already exists, plus the introspection wired on top of it.
#   * Discoverability: which builtins and which attach kinds go together.
#   * One authority for the context contracts. Some builtins are only valid under
#     certain hooks and the compiler refuses them elsewhere; that allowlist lives
#     here once, so the generator, the catalogue and the introspection all read the
#     same truth.
#
# What it is not: it changes nothing about how an existing probe behaves or what
# code is generated for it. The rejection logic itself lives in the generators;
# this module owns only the values they consult.
#
# It has no dependencies -- it does not require the generator -- so the builtin
# names appear here as literals. That the two lists agree is enforced by the unit
# tests: a new builtin that nobody classified makes them fail, which is the point.

module SpinelEbpf
  module Capabilities
    module_function

    # The measured allowlist for the d_path gate, and the single authority for it.
    #
    # bpf_d_path is gated by the kernel, and the gate is not a simple name list. Every
    # hook below was tried and observed to load; nothing here was added by prediction.
    # Sweeping every candidate made the shape of the gate visible:
    #
    #   * LSM programs    -- allowed only on a *sleepable* LSM hook. That is why
    #                        lsm/file_open loads while lsm/file_permission and
    #                        lsm/path_chroot do not.
    #   * fmod_ret/fentry -- allowed only for functions on the kernel's own
    #                        btf_allowlist_d_path. That is why fmod_ret/security_mmap_file
    #                        is rejected even though the LSM form of the same hook loads.
    #   * kprobe          -- impossible by construction: "program of this type cannot use
    #                        helper bpf_d_path".
    #
    # The second axis is *which argument carries the path*. It differs per hook, so the
    # table maps SEC -> shape:
    #
    #   :file   -> &((struct file *)arg)->f_path
    #   :path   -> (struct path *)arg    (the security_path_* family; no conversion)
    #   :binprm -> &((struct linux_binprm *)arg)->file->f_path
    #
    # guard: true emits a NULL check before bpf_d_path. On lsm/mmap_file that check is
    # not defensive but required to load at all: the argument is file__nullable, and
    # without it the verifier rejects the program with "R1 pointer arithmetic on
    # trusted_ptr_or_null_ prohibited".
    #
    # MethodEmitter::DPATH_OK_SECS in codegen_bpf.rb reads this constant. The production
    # C generator carries its own copy, and the unit tests keep the two in agreement.
    #
    # **`measured` only ever said "it loads".** What a user actually wants to know is
    # whether the policy they wrote will FIRE, so all 32 hooks were then measured to
    # actual firing, and these columns were added:
    #
    #   fire:   :deny      fires, and the denial itself was observed (hooks with a verdict)
    #           :observe   firing observed, but the RETURN VALUE IS IGNORED (fentry/fexit
    #                      carry no verdict, and a void hook runs after creds are settled)
    #                      -- auditing only
    #           :load_only only the load was ever confirmed  <- none left
    #   by:     the operation that was OBSERVED to reach this hook. Not "the operation
    #           you would expect to" -- close(2) does NOT reach filp_close, stat(2) does
    #           NOT reach vfs_getattr, and open(2) does NOT reach dentry_open.
    #   fired:  where that firing was measured (a weak tier owes its evidence, the same
    #           rule this tree applies to a map claim)
    #   caveat: present only on hooks where the obvious operation does not reach them, or
    #           where the path they render is not the one you expect. **This is the most
    #           valuable column in the registry** -- the silent misreadings collect here.
    #   no_select: present only on hooks where the path is readable but is NOT the path
    #           the caller sees, so selecting on it (`path_eq` / `path_starts_with` /
    #           `path_contains`) is structurally wrong (4 today). A prose caveat was the
    #           first answer; a compile-time refusal is the right one, because the
    #           generator knows both facts at compile time -- which builtin was written
    #           and under which SEC -- so the C side (`CcDpathHook.no_select`) dies. The
    #           ASYMMETRY is the point: `emit_path` (recording) and `parent_path_eq`
    #           (whose path comes from the task chain) still compile on the same hook.
    #           The unit tests keep this set equal to the C one.
    #
    # Note: an `lsm/*` program ATTACHES AND THEN SAYS NOTHING unless `bpf` is among the
    # active LSMs (measured twice, most recently with one probe counting 605 hits on a
    # kernel booted with it and 0 on one without). `fmod_ret` / `fentry` / `fexit` are
    # tracing programs and do not depend on it. That is a property of the KIND, not of
    # an individual hook, so it is reported by `lsm_active_required?`.
    DPATH_HOOKS = {
      # --- the three hooks the gate was first built from ---
      "lsm/file_open"                      => { form: :file,   guard: false, measured: "loads",
        fire: :deny,    by: "open(2)",                                fired: "per-hook probe in the firing sweep" },
      "fmod_ret/security_file_open"        => { form: :file,   guard: false, measured: "loads",
        fire: :deny,    by: "open(2)",                                fired: "per-hook probe in the firing sweep" },
      "fmod_ret/security_file_permission"  => { form: :file,   guard: false, measured: "loads; the LSM form of the same hook does not",
        fire: :deny,    by: "an access check on read(2) / write(2) and friends",
        fired: "per-hook probe in the firing sweep" },
      # --- argument is a `struct file *` ---
      "lsm/mmap_file"                      => { form: :file,   guard: true,  measured: "loads only with the null guard: the argument is file__nullable",
        fire: :deny,    by: "mmap(2) mapping a file",                 fired: "per-hook probe in the firing sweep" },
      "lsm/file_ioctl"                     => { form: :file,   guard: false, measured: "loads",
        fire: :deny,    by: "ioctl(2)",                               fired: "per-hook probe in the firing sweep",
        caveat: "an ioctl on a regular file fails with **ENOTTY** even when nothing blocks it, " \
                "so judge a denial by the ERRNO, not by whether the call succeeded " \
                "(measured: target = EPERM, control = ENOTTY)" },
      "lsm/file_lock"                      => { form: :file,   guard: false, measured: "loads",
        fire: :deny,    by: "flock(2)",                               fired: "per-hook probe in the firing sweep" },
      "lsm/file_receive"                   => { form: :file,   guard: false, measured: "loads",
        fire: :deny,    by: "recvmsg(2) receiving an fd over SCM_RIGHTS",
        fired: "per-hook probe in the firing sweep" },
      # --- argument is a `struct linux_binprm *` (exec) ---
      "lsm/bprm_check_security"            => { form: :binprm, guard: true,  measured: "loads with the null guard",
        fire: :deny,    by: "execve(2)",                              fired: "the end-to-end deny run" },
      "lsm/bprm_creds_for_exec"            => { form: :binprm, guard: true,  measured: "loads with the null guard",
        fire: :deny,    by: "execve(2)",                              fired: "per-hook probe in the firing sweep" },
      "lsm/bprm_committed_creds"           => { form: :binprm, guard: true,  measured: "loads with the null guard",
        fire: :observe, by: "execve(2)",                              fired: "per-hook probe in the firing sweep",
        caveat: "**a void hook** -- it fires, but the return value is thrown away, because it " \
                "runs after the credentials are settled. Returning `-1` here was measured to " \
                "let the exec succeed anyway. Use it for auditing (emit_path) only" },
      # --- argument is already a `struct path *` ---
      "lsm/path_unlink"                    => { form: :path,   guard: false, measured: "loads",
        fire: :deny,    by: "unlink(2) (ctx[0] is the PARENT directory)",
        fired: "the end-to-end deny run" },
      "lsm/path_rename"                    => { form: :path,   guard: false, measured: "loads for both the old and the new path",
        fire: :deny,    by: "rename(2) (ctx[0]=old_dir, ctx[2]=new_dir; both are parent directories)",
        fired: "per-hook probe in the firing sweep" },
      "lsm/path_mkdir"                     => { form: :path,   guard: false, measured: "loads",
        fire: :deny,    by: "mkdir(2) (ctx[0] is the PARENT directory)",
        fired: "per-hook probe in the firing sweep" },
      "lsm/path_rmdir"                     => { form: :path,   guard: false, measured: "loads",
        fire: :deny,    by: "rmdir(2) (ctx[0] is the PARENT directory)",
        fired: "per-hook probe in the firing sweep" },
      "lsm/path_symlink"                   => { form: :path,   guard: false, measured: "loads",
        fire: :deny,    by: "symlink(2) (ctx[0] is the PARENT directory)",
        fired: "per-hook probe in the firing sweep" },
      "lsm/path_link"                      => { form: :path,   guard: false, measured: "loads",
        fire: :deny,    by: "link(2)",                                fired: "per-hook probe in the firing sweep",
        caveat: "**the path is ctx[1] (new_dir)** -- the only member of this family where it is " \
                "not ctx[0] (ctx[0] is old_dentry, which is not a `struct path *`)" },
      "lsm/path_truncate"                  => { form: :path,   guard: false, measured: "loads",
        fire: :deny,    by: "truncate(2) (the path-based form)",      fired: "the end-to-end deny run",
        caveat: "**ftruncate(2) and open(O_TRUNC) do not fire here** -- those start from a file and " \
                "go to `security_file_truncate`, which is outside this gate. A policy written here " \
                "against ftruncate was measured to be silently inert" },
      "lsm/path_chmod"                     => { form: :path,   guard: false, measured: "loads",
        fire: :deny,    by: "chmod(2)",                               fired: "per-hook probe in the firing sweep" },
      "lsm/path_chown"                     => { form: :path,   guard: false, measured: "loads",
        fire: :deny,    by: "chown(2)",                               fired: "per-hook probe in the firing sweep" },
      "lsm/inode_getattr"                  => { form: :path,   guard: false, measured: "loads",
        fire: :deny,    by: "stat(2) / statx(2)",                     fired: "per-hook probe in the firing sweep" },
      "fmod_ret/security_path_truncate"    => { form: :path,   guard: false, measured: "loads",
        fire: :deny,    by: "truncate(2) (the path-based form)",      fired: "the end-to-end deny run",
        caveat: "**ftruncate(2) and open(O_TRUNC) do not fire here** (same granularity as " \
                "lsm/path_truncate)" },
      "fmod_ret/security_inode_getattr"    => { form: :path,   guard: false, measured: "loads",
        fire: :deny,    by: "stat(2) / statx(2)",                     fired: "per-hook probe in the firing sweep" },
      # --- the kernel's own btf_allowlist_d_path. Observation only: fentry and fexit
      # carry no verdict, so a deny written here is silently ignored -- measured, not
      # assumed. ---
      "fentry/filp_close"                  => { form: :file,   guard: false, measured: "loads; observation only",
        fire: :observe, by: "fd teardown at process exit (put_files_struct), O_CLOEXEC teardown " \
                            "at exec (do_close_on_exec), dup2(2)",
        fired: "per-hook probe in the firing sweep",
        caveat: "**close(2) does not fire here** -- on 7.1.5 close(2) calls `filp_flush` directly " \
                "(measured with ftrace: filp_flush<-__arm64_sys_close 30 times, filp_close 0 times)" },
      "fexit/filp_close"                   => { form: :file,   guard: false, measured: "loads; observation only",
        fire: :observe, by: "fd teardown at process exit (put_files_struct), O_CLOEXEC teardown " \
                            "at exec (do_close_on_exec), dup2(2)",
        fired: "per-hook probe in the firing sweep",
        caveat: "**close(2) does not fire here** (same as fentry/filp_close)" },
      "fentry/vfs_fallocate"               => { form: :file,   guard: false, measured: "loads; observation only",
        fire: :observe, by: "fallocate(2)",                           fired: "per-hook probe in the firing sweep" },
      "fexit/vfs_fallocate"                => { form: :file,   guard: false, measured: "loads; observation only",
        fire: :observe, by: "fallocate(2)",                           fired: "per-hook probe in the firing sweep" },
      "fentry/vfs_truncate"                => { form: :path,   guard: false, measured: "loads; observation only",
        fire: :observe, by: "truncate(2) (the path-based form)",      fired: "per-hook probe in the firing sweep",
        caveat: "**ftruncate(2) and open(O_TRUNC) do not fire here** (the path-based form only)" },
      "fexit/vfs_truncate"                 => { form: :path,   guard: false, measured: "loads; observation only",
        fire: :observe, by: "truncate(2) (the path-based form)",      fired: "per-hook probe in the firing sweep",
        caveat: "**ftruncate(2) and open(O_TRUNC) do not fire here** (the path-based form only)" },
      "fentry/dentry_open"                 => { form: :path,   guard: false, measured: "loads; observation only",
        fire: :observe, by: "kernel-internal callers such as overlayfs's `ovl_path_open` and fsmount(2)",
        fired: "per-hook probe in the firing sweep",
        caveat: "**open(2) does not fire here** (open goes through do_filp_open; measured 0 hits " \
                "with ftrace). And the path you get is rendered against overlayfs's INTERNAL " \
                "mount, not the path the caller used: the measurement saw `/f`, not " \
                "`/tmp/x/low/f`. **It cannot be told apart from a same-named file in another " \
                "directory**, so do not write a path selector here",
        no_select: "the path is readable but is rendered against overlayfs's internal mount " \
                   "(measured: `/f`), and the control file in a DIFFERENT directory rendered to " \
                   "the same `/f` -- selection cannot work. Recording it with `emit_path` still " \
                   "does. To select on open(2), write `def lsm__file_open` or " \
                   "`def fmod_ret__security_file_open`" },
      "fexit/dentry_open"                  => { form: :path,   guard: false, measured: "loads; observation only",
        fire: :observe, by: "kernel-internal callers such as overlayfs's `ovl_path_open` and fsmount(2)",
        fired: "per-hook probe in the firing sweep",
        caveat: "**open(2) does not fire here**, and the path is rendered against overlayfs's " \
                "internal mount (same as fentry/dentry_open)",
        no_select: "same as fentry/dentry_open (both sides rendered the path identically). To " \
                   "select on open(2), write `def lsm__file_open` or " \
                   "`def fmod_ret__security_file_open`" },
      "fentry/vfs_getattr"                 => { form: :path,   guard: false, measured: "loads; observation only",
        fire: :observe, by: "kernel-internal callers such as overlayfs copy-up (`ovl_copy_up_one`)",
        fired: "per-hook probe in the firing sweep",
        caveat: "**stat(2) does not fire here** -- stat calls `vfs_getattr_nosec` directly " \
                "(measured with ftrace: 79 hits on nosec against 0 on vfs_getattr). To watch " \
                "stat, use `lsm/inode_getattr` or `fmod_ret/security_inode_getattr`. The path is " \
                "also rendered against overlayfs's internal mount (`/f`) and cannot be told " \
                "apart from a same-named file elsewhere",
        no_select: "the path is readable but is rendered against overlayfs's internal mount " \
                   "(measured: `/f`), so selection cannot work. Recording it with `emit_path` " \
                   "still does. To select on stat(2), write `def lsm__inode_getattr` or " \
                   "`def fmod_ret__security_inode_getattr`" },
      "fexit/vfs_getattr"                  => { form: :path,   guard: false, measured: "loads; observation only",
        fire: :observe, by: "kernel-internal callers such as overlayfs copy-up (`ovl_copy_up_one`)",
        fired: "per-hook probe in the firing sweep",
        caveat: "**stat(2) does not fire here** (same as fentry/vfs_getattr; use " \
                "lsm/inode_getattr instead)",
        no_select: "same as fentry/vfs_getattr. To select on stat(2), write " \
                   "`def lsm__inode_getattr` or `def fmod_ret__security_inode_getattr`" },
    }.freeze

    # The SECs where path SELECTION is structurally impossible (the `no_select` above).
    # The C side (`CcDpathHook.no_select`) is what actually dies; this constant is what
    # the user is TOLD. The unit tests keep the two SETS equal (the prose differs per
    # language, and is not compared).
    DPATH_NO_SELECT_SECS = DPATH_HOOKS.select { |_, v| v[:no_select] }.keys.freeze

    # The builtins that are refused, and the ones that are still allowed on the very same
    # hook. Both halves are named, because the asymmetry IS the claim: with only one half
    # written down this would be indistinguishable from having withdrawn the hook.
    DPATH_SELECT_BUILTINS  = %w[path_eq path_starts_with path_contains].freeze
    DPATH_NONSELECT_BUILTINS = %w[emit_path emit_parent_path parent_path_eq].freeze

    # Hooks that were tried and **rejected**. They are not in the gate, but they are kept
    # here with the reason, because they are the evidence for the rule that nothing is
    # added by prediction: the same kernel function can be allowed under one attach kind
    # and refused under another.
    DPATH_MEASURED_REJECTED = {
      "lsm/file_permission"           => "helper call is not allowed in probe (a non-sleepable LSM hook)",
      "lsm/path_chroot"               => "helper call is not allowed in probe (a non-sleepable LSM hook)",
      "fmod_ret/security_mmap_file"   => "not on btf_allowlist_d_path (the LSM form lsm/mmap_file does load)",
      "fmod_ret/security_bprm_check"  => "not on btf_allowlist_d_path",
      "fmod_ret/security_path_unlink" => "not on btf_allowlist_d_path (the LSM form lsm/path_unlink does load)",
      "kprobe/*"                      => "program of this type cannot use helper bpf_d_path (impossible by construction)",
    }.freeze

    DPATH_OK_SECS = DPATH_HOOKS.keys.freeze

    # The domain registry. Each domain is {summary, builtins, attach_kinds}, with
    # builtin names left flat. attach_kinds records which attach kinds a domain's
    # builtins typically ride on; it is loose metadata, not a constraint.
    DOMAINS = {
      observability: {
        summary: "General observation: histograms, latency, stacks, profiles, emit and task storage -- the ground bcc's tools cover",
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
          kfield kptr emit_kfield_str kfield_str_eq
          attached_index attached_symbol_eq
          user_ringbuf_drain
        ].freeze,
        attach_kinds: %i[
          kprobe kprobe_multi kretprobe tracepoint raw_tp fentry fexit
          uprobe uretprobe usdt perf_event iter_task
        ].freeze,
      }.freeze,
      enforcement: {
        summary: "Blocking, auditing and lineage: deny by return value from an LSM or fmod_ret hook, with path and parent-path selectors",
        builtins: %w[
          emit_path emit_parent_path path_eq path_starts_with path_contains parent_path_eq ppid
          has_cap has_cap_permitted has_cap_inheritable cap_effective ns_id in_host_ns file_type
        ].freeze,
        attach_kinds: %i[lsm fmod_ret kprobe tracepoint].freeze,
      }.freeze,
      net: {
        summary: "The packet and socket datapath: packet access, XDP, TC, load balancing, NAT, connection tracking, qdiscs, congestion control and network spans",
        builtins: %w[
          pkt_len pkt_eth_proto pkt_l4_proto pkt_ip4_src pkt_ip4_dst
          pkt_l4_sport pkt_l4_dport pkt_tcp_flags pkt_l4_payload_len
          pkt_ip6_src_hi pkt_ip6_src_lo pkt_ip6_dst_hi pkt_ip6_dst_lo
          pkt_tcp_seq pkt_tcp_ack
          pkt_dynptr_byte_at
          tail_call_to
          tcp_syncookie_gen tcp_syncookie_check tcp_synack_cookie
          tcp_reply_header tcp_reply_synack tcp_reply_data payload_starts
          emit_connect sock_owner_set
          blocklist_match cidr_blocklist_match
          sock_addr_ip4 sock_addr_port
          sock_sport sock_dport sock_saddr sock_daddr sock_family sock_state sock_protocol
          sock_saddr6_hi sock_saddr6_lo sock_daddr6_hi sock_daddr6_lo
          udp_dport udp_daddr
          cpumap_redirect xsk_redirect dev_redirect
          fib_lookup fib_lookup6 sk_lookup_tcp sk_assign_tcp redirect
          skb_load_byte skb_load_u16 skb_load_u32
          skb_store_byte skb_store_u16 skb_store_u32
          l3_csum_replace l3_csum_replace_ip l4_csum_replace l4_csum_replace_ip l4_offset
          flow_get flow_set flow_del
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
          sock_ops_op sock_ops_state
          reuseport_hash worker_select
        ].freeze,
        attach_kinds: %i[
          xdp xdp_tail tc_ingress tc_egress
          sk_reuseport sk_msg sk_skb_verdict sk_skb_parser sock_ops
          cgroup_connect4 cgroup_bind4 sk_lookup socket_filter flow_dissector
          tcp_cc qdisc
        ].freeze,
      }.freeze,
      l7: {
        summary: "Application-protocol observation: HTTP, Redis, TLS plaintext and DNS spans, L7 latency, and correlation with off-CPU time",
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
        summary: "Domain-independent primitives: arithmetic, process identity, cgroup ids, the control channel, and the scheduler",
        builtins: %w[
          divu i32 pid tgid tid uid gid cpu_id cgroup_id field_exists
          scx_dispatch scx_consume scx_kick_cpu scx_pick_idle_cpu scx_create_dsq
        ].freeze,
        attach_kinds: %i[sched_ext].freeze,
      }.freeze,
    }.freeze

    # Context gates: these builtins are refused at compile time unless the attach
    # section is one of their valid ones. The refusal itself lives in the generator;
    # what lives here is the authority on which builtin requires which context.
    CONTEXT_GATES = {
      "emit_path"        => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "emit_parent_path" => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "path_eq"          => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "path_starts_with" => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "path_contains"    => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "parent_path_eq"   => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
    }.freeze

    # How the ready-made probes (--probe dns|file|l7|net) map onto these domains:
    # file auditing is enforcement, dns and l7 are both L7 (DNS being an L7
    # protocol), and net is networking.
    KREW_PROBE_DOMAINS = {
      "dns"  => :l7,
      "file" => :enforcement,
      "l7"   => :l7,
      "net"  => :net,
    }.freeze

    # ===================================================================
    # Publish the record contracts as part of the affordances.
    #
    # A packed-record emit builtin such as emit_dns is only one end of a contract:
    # how many bytes it writes into a ringbuf, and which OTLP attributes those bytes
    # eventually become. Both the physical layout and that meaning are data, and this
    # is where the meaning is read. The chain is:
    #
    #   src/codegen_c/record_schema.h   -- the one declaration: fields and egress
    #     -> the kernel's record struct   (read directly by the C generator)
    #     -> the userspace mirror and the SPNL_EGRESS_* macros (used by the runtime)
    #     -> record_schema_gen.json       (read by this Ruby)
    #
    # Offsets are *read* here, never computed. The alignment rules are implemented in
    # exactly one place, the layout function of the mirror generator; reimplementing
    # them in Ruby would be the third hand-written copy of the same rule, which is
    # how the offsets drifted in the first place. Regenerate with
    # `make -C src/codegen_c mirror`, which produces the header and the JSON
    # together.
    # ===================================================================

    RECORD_SCHEMA_JSON = File.expand_path("record_schema_gen.json", __dir__).freeze

    # ===================================================================
    # The record layouts also travel INSIDE the .bpf.o.
    #
    # Everything above is readable only by something that can run this Ruby. The
    # .bpf.o goes further than that -- it is a plain libbpf object, so it can be
    # handed to a loader in another language -- and it used to WRITE the records
    # without saying what they look like: a RINGBUF map declares no value type
    # and the struct is only ever a local pointer inside a `static` function, so
    # clang had no reason to put it in .BTF. The reader then copies the layout by
    # hand and is wrong silently.
    #
    # The fix is one pointer per channel that nothing reads, in a section libbpf
    # does not map. It makes clang emit the struct, and because all the witnesses
    # share one section the object also carries an INDEX of its record types
    # (DATASEC .spnl_records), so a generator on the other side does not have to
    # be told which types matter.
    #
    # `not_a_map` and `costs` are stated because the obvious spellings of the
    # same idea are not free, and a reader deciding whether to trust this needs
    # the difference: `__type(value, struct X)` on a ringbuf puts the type in BTF
    # and then FAILS TO LOAD under libbpf (the kernel refuses a ringbuf with
    # value_size != 0), and a witness with no section lands in .bss, where libbpf
    # creates an extra map.
    # ===================================================================
    RECORD_BTF = {
      section: ".spnl_records",
      var: "_spnl_rec_<struct_suffix>",
      emitted_for: "every packed-record channel the unit actually emits",
      index: "BTF DATASEC '.spnl_records' lists one Var per channel; each Var is a " \
             "pointer to that channel's record struct",
      reader_recipe: "bpf2go -type <unit>_<struct_suffix> (or ebpf-go's btf package: " \
                     "walk the .spnl_records datasec)",
      not_a_map: "libbpf skips the section (it prints 'elf: skipping unrecognized data " \
                 "section .spnl_records' at open) and creates nothing; the kernel-side " \
                 "map set is unchanged",
      costs: { text_bytes: 0, section_bytes_per_channel: 8, btf_bytes_per_channel: "~410-443",
               object_bytes_per_channel: "~576-616" },
      rejected_spellings: [
        { spelling: "__type(value, struct X) on the ringbuf map",
          in_btf: true, libbpf_loads: false,
          why: "libbpf sets value_size = sizeof(X); the kernel refuses a RINGBUF with " \
               "key_size or value_size != 0 (EINVAL). ebpf-go zeroes it instead " \
               "(MapType.canHaveValueSize), so this spelling looks correct if the only " \
               "loader tried is Go -- cilium/ebpf's own examples/ringbuffer object does " \
               "not load under libbpf either" },
        { spelling: "BTF_TYPE_EMIT(struct X)",
          in_btf: false, libbpf_loads: true,
          why: "((void)(type *)0) is the kernel's DWARF->pahole idiom. clang -target bpf " \
               "generates .BTF itself and only for types the program uses, so the cast is " \
               "optimised away and nothing is emitted" },
        { spelling: "a global witness with no SEC",
          in_btf: true, libbpf_loads: true,
          why: "lands in .bss, so libbpf creates an extra internal map (the skeleton grows " \
               "a `bss` member) -- a change to what the kernel loads, not just to metadata" },
        { spelling: "__attribute__((btf_decl_tag)) on the struct alone",
          in_btf: false, libbpf_loads: true,
          why: "a decl tag is emitted only for a type clang already emits; it cannot keep " \
               "an otherwise-unreferenced struct alive" },
      ],
    }.freeze

    # ===================================================================
    # The vocabulary of the userspace consumer DSL, in machine-readable form.
    #
    # Where the record contracts above say what can be read, this says how to write
    # it: `on_emit :<ch>`, `to_span`, `send_otlp`, `consume_records` -- and the rule
    # by which `to_span` resolves. That rule ("`to_span` resolves inside an
    # `on_emit :<ch>` block; where the handle crosses out of that scope, write
    # `<ch>_span(ev)`") is published as a context note rather than left in prose,
    # exactly as the context gates on other builtins are.
    #
    # These verbs are deliberately generic. What a span contains is owned by its
    # egress declaration, not by the probe, which is why `to_span` has no argument
    # for adding attributes. The freedom a probe has is whether to send, when, and
    # how often -- not what the span says.
    # ===================================================================

    # ===================================================================
    # Runtime parameters -- the DSL surface, not a probe's
    # parameters. `describe` lists what a GIVEN probe declares; this key answers
    # the prior question an AI has to answer first: "can this program be narrowed
    # without writing a new one?" Getting that wrong is expensive in exactly one
    # direction -- a model that does not know `param` exists will regenerate the
    # whole .rb to change a pid.
    #
    # `not_for` is load-bearing. The tempting misuse is a knob that changes while
    # the probe runs; .rodata is frozen at load, so that is a different mechanism
    # (a map-backed one) with a different price: no dead-code elimination, and a
    # higher kernel floor. Saying so here is cheaper than saying it in a bug report.
    # ===================================================================
    RUNTIME_PARAMS = {
      form: "param :<name>[, default: <int literal>]   # top level, before the handlers",
      read_as: "the bare name inside an eBPF handler, e.g. `if target_pid == 0 || pid == target_pid`",
      set_by: "environment: SPNL_PARAM_<NAME> (uppercased name). Read once, at load.",
      type: "__s64 only (spinel-ebpf has no other scalar in eBPF, so there is no type to get wrong)",
      # Literal, not `Param::IMPLICIT_DEFAULT`: this file deliberately requires
      # nothing (see the header). Drift is caught by a unit test instead.
      default_when_omitted: 0,
      lowering: "volatile const __s64 spnl_param_<name> in .rodata; the loader assigns " \
                "skel->rodata-><sym> between __open() and __load(), then the kernel freezes the map.",
      kernel_floor: "5.2 (read-only map + BPF_MAP_FREEZE) -- the same floor eBPF already needs, " \
                    "so declaring parameters does not narrow where a probe can run.",
      dead_code: "a parameter left at 0 is folded by the verifier, so a guard on it is absent from " \
                 "the loaded program rather than always-true. Adding a filter therefore costs nothing " \
                 "when it is not used (measured with `bpftool prog dump xlated`).",
      not_for: "changing a value while the probe runs -- .rodata is frozen at load. A live knob is a " \
               "a map, which cannot be constant-folded and needs a higher kernel floor.",
      refused: [
        "a declared parameter no handler reads (the switch would be wired to nothing)",
        "a name that a builtin already owns -- the builtin wins, so the parameter is unreachable",
        "`default:` that is not an integer literal (it is baked in at compile time)",
        "SPNL_PARAM_<X> set for an <X> this program never declared",
        "a value that does not parse completely as a 64-bit integer",
      ].freeze,
    }.freeze

    # ===================================================================
    # The in-kernel common filter.
    #
    # RUNTIME_PARAMS above answers "can this program be narrowed without being
    # rewritten". This key answers the one that comes before it, and that a model
    # asked to write a probe answers wrongly by default: **should it narrow at
    # all, and where does the narrowing go**. A probe that narrows in four of its
    # five handlers still reports everything, and no gate in this project can see
    # that: the channel balance report can say "nothing came out", never "the wrong
    # things came out". One declaration covering the whole unit is the
    # shape that has no fifth handler to forget.
    #
    # `covers` / `refuses` are load-bearing and deliberately not softened: the
    # declaration is refused, not partially applied, when a handler in the unit is
    # a hook where "skip this event" would be a security decision.
    # ===================================================================
    COMMON_FILTER = {
      form: "filter_by :<key>[, :<key>...]   # top level, one declaration for the whole unit",
      applies_to: "every attach handler in the unit -- injected by the codegen, not called by the handler",
      keys: {
        "pid"       => { env: "SPNL_FILTER_PID",       unset: 0,  means: "thread-group id (what userspace calls the pid)" },
        "tid"       => { env: "SPNL_FILTER_TID",       unset: 0,  means: "kernel thread id" },
        "uid"       => { env: "SPNL_FILTER_UID",       unset: -1, means: "effective uid; unset is -1 because uid 0 is root and must be selectable" },
        "gid"       => { env: "SPNL_FILTER_GID",       unset: -1, means: "effective gid; unset is -1 for the same reason" },
        "cgroup_id" => { env: "SPNL_FILTER_CGROUP_ID", unset: 0,  means: "cgroup id (= cgroup-dir inode) -- one container / pod" },
        "comm"      => { env: "SPNL_FILTER_COMM",      unset: "", means: "task comm, exact 16-byte match, at most 15 characters" },
      }.freeze,
      combining: "AND over the keys that are SET. An unset key does not constrain, so " \
                 "SPNL_FILTER_PID=1 SPNL_FILTER_COMM=curl keeps only events that are both.",
      set_by: "environment, read once at load (same .rodata mechanism as `param`).",
      dead_code: "a key left unset is folded away by the verifier together with the " \
                 "bpf_get_current_* call it would have needed, so declaring keys you do not " \
                 "set costs nothing at run time (measured with `bpftool prog dump xlated`).",
      covers: %w[kprobe kretprobe tracepoint raw_tp fentry fexit uprobe uretprobe usdt perf_event].freeze,
      refuses: [
        "a unit that also has a verdict hook (lsm / fmod_ret / xdp / tc / sk_* / cgroup-sock-addr): " \
        "there `return 0` is a decision, not a skip -- split the probe",
        "a unit with no handler the filter can cover (the declaration would be wired to nothing)",
        "an unknown key, a key listed twice, a second `filter_by`, a non-symbol key",
        "SPNL_FILTER_<X> set for a key this program did not declare",
        "SPNL_FILTER_COMM longer than 15 characters (it could never match a task comm)",
      ].freeze,
      hand_written_equivalent: "`param :target_pid` + `if target_pid == 0 || pid == target_pid` per handler. " \
                               "Same generated guard; the difference is that the declaration cannot be " \
                               "applied to only some of the handlers.",
      not_for: "per-handler narrowing, or anything probe-specific (a path, a port, a syscall number). " \
               "That is `param` -- the common filter only covers what every process-context hook has.",
    }.freeze

    # ===================================================================
    # The declarative USERSPACE consumer filter.
    #
    # COMMON_FILTER above answers "should this probe narrow, and where". This key
    # answers what is left over: the narrowings the kernel cannot do at all. The
    # two are not alternatives, and the question an AI gets wrong is which one it
    # is holding -- so `line` is the first thing here, and the refusal that
    # enforces it is `refuses`[0].
    #
    # `not_implemented` is deliberately in the machine-readable surface rather
    # than only in prose: sort / top-N look adjacent to a filter, `SPNL_MAX_EVENTS`
    # already occupies the neighbouring space with a DIFFERENT meaning, and the
    # cheapest way to stop a model inventing `keep_if :dns, top: 10` is to say
    # here that it does not exist and what does.
    # ===================================================================
    CONSUMER_FILTER = {
      form: "keep_if :<channel>, <property>: :<operator>[, ...]   # top level, one per channel",
      applies_to: "the records the channel's `on_emit :<channel> do |ev|` block turns into spans -- " \
                  "hoisted to the head of the generated handler, so it cannot be written too late",
      vocabulary: "the channel's published properties (channels[<id>].consumer.properties) -- the " \
                  "same names `ev.<name>` reads. An unknown name is a compile error listing the real set.",
      operators: {
        "eq"       => { types: %w[int str], means: "value == the environment's" },
        "ne"       => { types: %w[int str], means: "value != the environment's" },
        "ge"       => { types: %w[int],     means: "value >= the environment's (e.g. only the slow ones)" },
        "le"       => { types: %w[int],     means: "value <= the environment's" },
        "contains" => { types: %w[str],     means: "substring, case-sensitive" },
      }.freeze,
      set_by: "environment: SPNL_KEEP_<CHANNEL>_<PROPERTY>, read per record by the generated " \
              "consumer. Unset does not constrain; an explicitly empty value is refused.",
      combining: "AND over the predicates that are SET -- the same rule as the in-kernel filter, " \
                 "so there is one rule to learn rather than two.",
      # The line D1 draws, stated as the property it actually is.
      line: "a `keep_if` predicate may only name a narrowing the in-kernel filter cannot do. " \
            "`:eq` on a property whose declaration carries a `kfilter` (channels[<id>].consumer." \
            "properties[].kfilter) is refused and redirected to `filter_by :<key>`, which drops the " \
            "record before it is created and so saves the ringbuf and the drain as well as the send.",
      why_userspace: {
        "derived"       => "the value does not exist until userspace computes it (dns qname, http " \
                           "method/path/status, conn peer/direction). The in-kernel QNAME " \
                           "walk blows up verifier state, which is why it is a derivation at all",
        "no_kernel_key" => "the kernel wrote the field, but the common filter's vocabulary is fixed " \
                           "(pid tid uid gid cgroup_id comm) and has no key for a port or a duration",
        "cross_task"    => "the field is not the current task's value: conn/l7/http fill pid/comm/cgid " \
                           "from an entry stashed in an earlier task by sock_owner_set, so the " \
                           "kernel key would select a different set -- that is why `kfilter` is " \
                           "declared per field and not per name",
        "operator"      => "the in-kernel filter is equality-AND only: negation, thresholds and " \
                           "substrings have no in-kernel form",
      }.freeze,
      cost: "measured: a record dropped here costs 0.41 us, a record sent costs 8.83 us, so " \
            "dropping 3.2% pays for the filter. It does NOT save the ringbuf or the drain -- those " \
            "are already spent by the time the predicate runs.",
      span_unchanged: "a record that passes produces exactly the span the egress declaration says " \
                      "-- the egress declaration is the authority. The filter changes whether a span is sent, never its contents; " \
                      "there is no way to add, drop or rewrite an attribute from Ruby.",
      refuses: [
        "`:eq` on a property with a kernel equivalent -- use `filter_by :<key>` (it drops earlier)",
        "a property the channel does not publish (the message lists the real set)",
        "an operator the property's type does not accept (`qname: :ge`, `pid: :contains`)",
        "a channel with no typed consumer, or one this program does not consume",
        "a second `keep_if` for the same channel, or the same property twice",
        "SPNL_KEEP_<X> set for a predicate this program did not declare (loader sweep)",
        "an integer predicate whose value does not parse completely, or any empty value",
      ].freeze,
      hand_written_equivalent: "`next unless ev.<prop>.include?(ENV[...])` as the first statement of " \
                               "the block. Same generated Ruby; what the declaration adds is that it " \
                               "cannot be the second statement, cannot name an env var the loader " \
                               "does not know, and can be told apart from a narrowing the kernel " \
                               "could have done.",
      not_implemented: {
        "sort / top-N" => "not implemented. Ranking needs the stream stopped and a window declared, " \
                          "which is a different mechanism from a per-record predicate. Note that " \
                          "SPNL_MAX_EVENTS is NOT it: that is the FIRST K events, and then the probe exits.",
        "--fields"     => "not offered, and not an omission: choosing which attributes leave the " \
                          "process is exactly what the layering rules out -- the egress declaration " \
                          "owns the span's contents.",
        "-o json"      => "already exists as OTEL_EXPORTER_OTLP_PROTOCOL=http/json. A second " \
                          "JSON would be a second name for the same thing.",
      }.freeze,
      not_for: "narrowing that the kernel can do (that is `filter_by`), or per-handler narrowing of " \
               "kernel-side work (that is `param`). This filter runs after the record has already " \
               "crossed into userspace.",
    }.freeze

    CONSUMER_DSL = [
      { name: "on_emit :<channel>",
        form: "on_emit :<channel> do |ev| ... end",
        layer: 1,
        summary: "A typed record consumer. The block runs once per record, and `ev` is an " \
                 "opaque handle into that drain. Which `ev.<prop>` names exist comes from the " \
                 "channel's own declaration (channels[<id>].consumer.properties).",
        context_note: "<channel> must be the id of a channel that publishes a typed consumer. " \
                      "An id that does not is treated as a named event instead, which is what " \
                      "existing programs expect. A same-named `emit :<channel>, v` in the same " \
                      "program is a compile error.",
        gotcha: "`ev` is valid only within the current drain cycle. To keep a value beyond it, " \
                "copy the property into a Ruby variable." }.freeze,
      { name: "to_span",
        form: "to_span(ev)",
        layer: 1,
        summary: "Build one record into the span its egress declaration describes " \
                 "(channels[<id>].egress is the authority). Returns a span handle; 0 means this " \
                 "record does not become a span.",
        context_note: "It resolves when written inside an `on_emit :<channel>` block and applied " \
                      "to that block's own parameter. In a program consuming several channels, " \
                      "applying it outside the block, or to a handle copied into another " \
                      "variable, is a compile error -- use the explicit `<channel>_span(ev)` " \
                      "there. A program with a single typed channel resolves it anywhere.",
        gotcha: "There is no way to add to a span from Ruby: the egress declaration decides what " \
                "it contains. What a probe controls is whether to send, when, and how often." }.freeze,
      { name: "<channel>_span",
        form: "dns_span(ev)",
        layer: 1,
        summary: "The explicit form of `to_span`, naming its channel. For the cases the scope " \
                 "rule cannot reach.",
        context_note: "An escape hatch, not the usual way: normally write `to_span(ev)` inside an " \
                      "`on_emit :<channel>` block. Naming a channel the program does not consume " \
                      "is a compile error." }.freeze,
      { name: "send_otlp",
        form: "send_otlp(to_span(ev), endpoint)",
        layer: 1,
        summary: "Add a span to the send batch. Handle 0 is a no-op, so a probe need not branch " \
                 "on it.",
        context_note: "The endpoint is taken from the first call of the cycle. The generated " \
                      "driver flushes once at the end of it, so consuming several channels still " \
                      "produces a single batched POST." }.freeze,
      { name: "consume_records",
        form: "st = consume_records(timeout_ms)",
        layer: 1,
        summary: "Drain, dispatch each record to its on_emit block, then flush the send batch. " \
                 "Returns the HTTP status of the last POST.",
        context_note: "Without it the handler never runs at all -- the program compiles, the " \
                      "verifier is happy, and no span comes out. Call it periodically from a " \
                      "loop. One call drains every channel the program consumes." }.freeze,
    ].freeze

    def self.deep_freeze(o)
      case o
      when Hash  then o.each_value { |v| deep_freeze(v) }; o.freeze
      when Array then o.each { |v| deep_freeze(v) }; o.freeze
      else o.freeze
      end
    end
    private_class_method :deep_freeze

    # The generated JSON contract, read lazily and memoised. A missing file is a loud
    # failure: returning an empty document silently would make "this probe has no
    # contract" indistinguishable from "somebody forgot to regenerate".
    def record_schema_doc
      @record_schema_doc ||= begin
        require "json"
        unless File.exist?(RECORD_SCHEMA_JSON)
          raise "record schema artifact missing: #{RECORD_SCHEMA_JSON} " \
                "(regenerate with `make -C src/codegen_c mirror`)"
        end
        deep_freeze(JSON.parse(File.read(RECORD_SCHEMA_JSON), symbolize_names: true))
      end
    end

    def record_channels
      @record_channels ||= deep_freeze(record_schema_doc[:channels] || [])
    end

    # Every declared metric, flattened across channels. Each entry keeps its channel id,
    # so a reader can get back to the records the metric aggregates.
    def record_metrics
      record_channels.flat_map { |c| Array(c[:metrics]).map { |m| m.merge(channel: c[:id]) } }
    end

    def record_bounds_sets
      Array(record_schema_doc[:bounds_sets])
    end

    # The declared value maps -- the authority behind every type-driven derived name.
    # Each maps a **closed** set of values to names, records where those names come
    # from (`authority`), and carries the BTF coordinates (`btf_*`) that let a machine
    # check the mapping against the running kernel. This is the only surface on which
    # the candidate values of an attribute can be learned without running a probe and
    # looking at one sample, so both `describe` and `capabilities --json` publish it.
    def record_value_maps
      @record_value_maps ||= deep_freeze(record_schema_doc[:value_maps] || [])
    end

    # A value map id to its hash, or nil.
    def record_value_map(id)
      record_value_maps.find { |m| m[:id] == id.to_s }
    end

    # A channel id such as "dns" to its hash, or nil.
    def record_channel(id)
      record_channels.find { |c| c[:id] == id.to_s }
    end

    # Only the channels that publish a typed consumer -- the ones carrying a
    # `consumer` block. A channel can be fully declarative without changing what
    # `on_emit :<id>` means; for those it must keep meaning a named event, or an
    # existing program would quietly become a different program. "Has a declaration"
    # and "has a Ruby-side receiver" are separate facts, so they get separate sets.
    def typed_record_channels
      record_channels.select { |c| c[:consumer] }
    end

    # The channel ids with a typed consumer: the set for which `on_emit :<id>` means
    # a typed record.
    def typed_record_channel_ids
      typed_record_channels.map { |c| c[:id] }
    end

    # An emit builtin to the channel it writes, or nil when it is not a producer.
    def record_channel_for(builtin)
      record_channels.find { |c| Array(c[:producers]).include?(builtin) }
    end

    # Every builtin that writes a packed record, sorted.
    def record_producers
      record_channels.flat_map { |c| Array(c[:producers]) }.sort.freeze
    end

    # A channel id to the properties its typed consumer can read.
    # ([{name:, kind:, expose:, ffi:, ffi_ret:, source:, note:}])。
    # This is the authority on which `ev.<name>` exist, and the consumer transform
    # rejects any name absent from it at compile time.
    def record_properties(id)
      c = record_channel(id)
      Array(c && c.dig(:consumer, :properties))
    end

    # --- the query API used by introspection ---

    # Every classified builtin, sorted.
    def all_builtins
      DOMAINS.values.flat_map { |d| d[:builtins] }.sort.freeze
    end

    # A builtin name to its domain symbol, or nil when it is unclassified.
    def domain_of(name)
      DOMAINS.each { |dom, spec| return dom if spec[:builtins].include?(name) }
      nil
    end

    def builtins_for(domain)
      DOMAINS.dig(domain, :builtins) || []
    end

    # A gated builtin to {domain:, valid_secs:}, or nil when it is not gated.
    def gate_for(name)
      CONTEXT_GATES[name]
    end

    # Has this SEC been measured all the way to FIRING? nil when it is not in the gate.
    def dpath_fire(sec)
      DPATH_HOOKS[sec]
    end

    # An `lsm/*` program attaches and then SAYS NOTHING unless `bpf` is among the active
    # LSMs (measured: the same probe counted 605 hits on a kernel booted with it, 0
    # without). fmod_ret / fentry / fexit are tracing programs and do not depend on it.
    # It is a property of the KIND, not of an individual hook.
    def lsm_active_required?(sec)
      sec.to_s.start_with?("lsm/")
    end

    # One hook on one line: what reaches it, whether a verdict is honoured, and the trap.
    def dpath_fire_line(sec)
      h = DPATH_HOOKS[sec] or return nil
      tier = { deny: "fires, and the denial was observed",
               observe: "fires, but **the return value is ignored**",
               load_only: "**only the load was ever confirmed**" }[h[:fire]] || h[:fire].to_s
      s = format("%s -- %s / reached by: %s [%s]", sec, tier, h[:by], h[:fired])
      s += "\n      ! #{h[:caveat]}" if h[:caveat]
      # Stated as a FACT, not a warning: a probe that selects on a path here does not
      # compile at all, so a reader of `describe` cannot confuse "you cannot write this"
      # with "you wrote it and it does nothing".
      s += "\n      x path selection (#{DPATH_SELECT_BUILTINS.join(' / ')}) **fails at compile " \
           "time** -- #{h[:no_select]} / recording (#{DPATH_NONSELECT_BUILTINS.join(' / ')}) is fine" if h[:no_select]
      s += "\n      ! unless `bpf` is among the active LSMs this attaches and then **says " \
           "nothing** (the counter simply stays 0)" if lsm_active_required?(sec)
      s
    end

    # Given a set of builtin names, return {domain => [names]} for the domains they
    # touch, with the names sorted.
    def domains_used(names)
      seen = names.to_a.uniq
      DOMAINS.each_key.filter_map do |dom|
        hit = builtins_for(dom) & seen
        [dom, hit.sort] unless hit.empty?
      end.to_h
    end

    # A human-readable dump of the packed-record channels: what writing a given
    # builtin puts into a ringbuf, and which span attributes those bytes become.
    def record_channels_report
      out = +"record channels (the bytes on the ringbuf, the typed consumer, and the span):\n"
      record_channels.each do |c|
        out << format("  %-6s %s (%d B) <- %s\n",
                      c[:id], c[:record_struct], c[:record_bytes], Array(c[:producers]).join(" / "))
        c[:fields].each do |f|
          type = f[:count].to_i > 0 ? "#{f[:ctype]}[#{f[:count]}]" : f[:ctype]
          out << format("    @%-4d %-14s %-22s %s\n", f[:offset], f[:name], type, f[:note])
        end
        cons = c[:consumer]
        if cons
          # The typed consumer: the same record, received in Ruby so a probe's own
          # logic can sit in front of it. properties is the authority on which
          # `ev.<name>` exist; anything else is a compile error.
          out << format("    consumer: %s   (drain %s / to_span %s / send %s)\n",
                        cons[:form], cons[:drain_fn], cons[:to_span_fn], cons[:send_fn])
          Array(cons[:properties]).each do |p|
            # For a derived string property the output capacity is part of the
            # declaration too, so the accessor and the span builder are handed the
            # same width. Since the declared capacity is at least the longest value
            # it can return, "how many bytes can this be" is readable from here. A
            # property that comes straight from a field reads the record's bytes, so
            # its width is the field's own, shown on the line above.
            # What is printed is the largest value in bytes, one less than the
            # declared capacity, which includes the terminator.
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
        out << format("      + enrichers (environment-gated, no probe change): %s\n", Array(e[:enrichers]).join(", ")) unless Array(e[:enrichers]).empty?
      end
      record_channels.each do |c|
        next if Array(c[:metrics]).empty?
        out << record_metric_lines(c)
      end
      out << "\n"
      out << consumer_dsl_report
      out
    end

    # A human-readable dump of channel -> metric.
    #
    # The reason this function exists is to **put a number on label safety**. What a
    # metric costs is not its value but its labels, that cost cannot be read off the
    # probe, and getting it wrong still exits 0 -- it shows up on the backend's invoice.
    # So the series ceiling (the product of the label bounds) is always printed next to
    # where each bound comes from:
    #
    #   declared_set  the permitted set is declared here, and anything outside it is
    #                 emitted as the fallback. The span keeps the exact value, so this
    #                 is a coarsening that was declared, not one that happened.
    #   value_map     the underlying property is already closed, so no coarsening occurs.
    def record_metric_lines(c)
      out = +""
      out << format("  %-6s metrics:\n", c[:id])
      Array(c[:metrics]).each do |m|
        val = m[:value_from].to_s.empty? ? "records" :
              format("%s [%s -> %s]", m[:value_from], m[:value_unit], m[:unit])
        out << format("    %s  %s  unit=%s  value=%s\n", m[:name], m[:kind], m[:unit], val)
        out << format("      series <= %d  (= %s)\n", m[:series_bound],
                      Array(m[:labels]).empty? ? "1, no labels" :
                        Array(m[:labels]).map { |l| l[:bound] }.join(" x "))
        Array(m[:labels]).each do |l|
          how = l[:bound_from] == "declared_set" ?
                format("declared set of %d + fallback %s (values outside it are NOT a new series; " \
                       "the span keeps the exact value)", Array(l[:values]).length, l[:fallback].inspect) :
                format("closed value map `%s` (nothing else can occur)", l[:value_map])
          out << format("      label %-28s <- ev.%-12s bound %-4d %s\n",
                        l[:key], l[:from], l[:bound], how)
        end
        out << format("      buckets: %s (%s)\n", Array(m[:boundaries]).join(", "), m[:bounds]) if m[:kind] == "histogram"
      end
      out
    end

    # A human-readable dump of the map vocabulary: one screen answering "if I write this
    # surface, which maps come into being, how large are they, and what happens when one
    # fills up".
    def maps_report
      out = +"maps (what writing a surface creates, with capacity and overflow behaviour):\n"
      MAPS.group_by { |m| m[:declared_as] }.each do |form, entries|
        out << format("  [%s] %d\n", form, entries.size)
        entries.each do |m|
          cap = m[:max_entries] ? "max_entries=#{m[:max_entries]}" : "no max_entries"
          out << format("    %-26s %-14s %-22s %s\n", m[:map], m[:type], cap,
                        m[:per_cpu] ? "per-CPU (userspace sums across CPUs)" : "")
          out << format("      <- %s\n", m[:created_by].join(" "))
          out << format("      %s\n", m[:role])
          out << format("      when full: %s\n", m[:when_full])
        end
      end
      out << format("  %d maps across %d types. Types withdrawn with their surface: %s\n\n",
                    MAPS.size, MAPS.map { |m| m[:type] }.uniq.size, WITHDRAWN_MAPS.keys.join(" "))
      out
    end

    # The set of surface names in use -> the map entries they create.
    def maps_created_by(names)
      used = names.to_a.map(&:to_s)
      MAPS.select { |m| !(m[:created_by] & used).empty? }
    end

    # A human-readable dump of the consumer DSL's vocabulary and the rule by which
    # `to_span` resolves.
    def consumer_dsl_report
      ids = typed_record_channel_ids
      out = +"userspace consumer DSL (receiving a ringbuf in Ruby):\n"
      out << format("  typed channels (ids for which `on_emit :<id>` is a typed record): %s\n",
                    ids.empty? ? "(none)" : ids.join(", "))
      out << "  any other id keeps meaning a named event\n"
      CONSUMER_DSL.each do |v|
        out << format("  %-22s %s\n", v[:name], v[:form])
        out << format("      %s\n", v[:summary])
        out << format("      context: %s\n", v[:context_note])
        out << format("      note: %s\n", v[:gotcha]) if v[:gotcha]
      end
      out << "\n"
      out << consumer_filter_report
      out
    end

    # The vocabulary of `keep_if`, and **where the line runs between it and the
    # kernel-side filter**. That line is printed first, because which of the two holds a
    # given decision is the thing a reader gets wrong first.
    def consumer_filter_report
      f = CONSUMER_FILTER
      out = +"userspace consumer filter (drops after the drain, before sending):\n"
      out << "  #{f[:form]}\n"
      out << "  values:    #{f[:set_by]}\n"
      out << "  combining: #{f[:combining]}\n"
      out << "  operators:\n"
      f[:operators].each { |n, o| out << format("    %-9s %-8s %s\n", ":#{n}", o[:types].join("/"), o[:means]) }
      out << "  where the line runs (against the kernel-side filter_by):\n"
      out << "    #{f[:line]}\n"
      f[:why_userspace].each { |k, v| out << format("    %-14s %s\n", k, v) }
      out << "  cost: #{f[:cost]}\n"
      out << "  span: #{f[:span_unchanged]}\n"
      out << "  not implemented (and not dropped silently):\n"
      f[:not_implemented].each { |k, v| out << format("    %-14s %s\n", k, v) }
      out << "\n"
      out
    end

    # The human-readable dump of the whole registry, behind `spinel-ebpf capabilities`.
    def catalog_report
      out = +"spinel-ebpf capabilities -- the probe DSL, by domain\n\n"
      DOMAINS.each do |dom, spec|
        out << format("%-14s (%d builtins)\n", dom, spec[:builtins].length)
        out << "  #{spec[:summary]}\n"
        out << "  attach: #{spec[:attach_kinds].join(', ')}\n" unless spec[:attach_kinds].empty?
        out << "  builtins: #{spec[:builtins].sort.join(' ')}\n\n"
      end
      unless CONTEXT_GATES.empty?
        out << "context gates (refused at compile time outside these hooks):\n"
        # Builtins that share an allowlist are printed once, together: the d_path gate
        # is 6 builtins across 30-odd hooks, and listing it per builtin is unreadable.
        CONTEXT_GATES.group_by { |_, g| g[:valid_secs] }.each do |secs, entries|
          names = entries.map(&:first)
          out << format("  %s [%s]\n", names.join(" / "), entries.first.last[:domain])
          if secs.equal?(DPATH_OK_SECS)
            # Which argument carries the path differs per hook, and that is what a
            # reader is choosing between, so group the hooks by argument shape.
            { file: "argument is a struct file *  ", path: "argument is a struct path *  ",
              binprm: "argument is a linux_binprm *" }.each do |form, label|
              hooks = DPATH_HOOKS.select { |_, v| v[:form] == form }.keys
              out << format("    %s: %s\n", label, hooks.join(" | "))
            end
            # The gate only ever guaranteed "this loads". Report the firing tiers.
            # **Do not print all 32 as a wall** -- what a reader needs is which ones can
            # deny, and which ones the obvious operation does not reach.
            by_fire = DPATH_HOOKS.group_by { |_, v| v[:fire] }
            out << format("    firing, as measured: %s\n",
                          %i[deny observe load_only].map { |t|
                            format("%s=%d", t, (by_fire[t] || []).length)
                          }.join(" / "))
            out << "      deny    = fires and the denial was observed (you can write policy)\n"
            out << "      observe = fires, but **the return value is ignored** (auditing only)\n"
            caveats = DPATH_HOOKS.select { |_, v| v[:caveat] }
            unless caveats.empty?
              out << "    ! hooks the obvious operation does not reach, or whose path is not " \
                     "the one you expect (#{caveats.length}/#{DPATH_HOOKS.length}, measured):\n"
              caveats.each { |sec, v| out << format("      %-34s %s\n", sec, v[:caveat]) }
            end
            # Four of those caveats said "do not write a path selector here"; they are now
            # compile-time failures. Print BOTH halves -- refused and still allowed --
            # because without the second half this reads as having withdrawn the hook.
            unless DPATH_NO_SELECT_SECS.empty?
              out << "    x path SELECTION structurally impossible = fails at compile time " \
                     "(#{DPATH_NO_SELECT_SECS.length}/#{DPATH_HOOKS.length}):\n"
              out << "      refused: #{DPATH_SELECT_BUILTINS.join(' / ')}   " \
                     "allowed: #{DPATH_NONSELECT_BUILTINS.join(' / ')} (recording, and paths " \
                     "that come from the task chain)\n"
              DPATH_NO_SELECT_SECS.each do |sec|
                out << format("      %-34s %s\n", sec, DPATH_HOOKS[sec][:no_select])
              end
            end
            n_lsm = DPATH_HOOKS.keys.count { |s| lsm_active_required?(s) }
            out << "    ! the `lsm/*` hooks (#{n_lsm} of them) attach and then say nothing " \
                   "unless `bpf` is among the active LSMs\n"
            out << "    tried and rejected (kept out of the gate -- the same function can " \
                   "be allowed under one attach kind and refused under another):\n"
            DPATH_MEASURED_REJECTED.each { |sec, why| out << format("      %-32s %s\n", sec, why) }
          else
            out << format("    valid: %s\n", secs.join(" | "))
          end
        end
        out << "\n"
      end
      out << "required sets (calls that produce no span on their own; enforced at compile time):\n"
      REQUIRED_SETS.each do |rule|
        if rule[:mode] == :all
          out << format("  %s (all-or-none)\n", rule[:members].join(" + "))
        else
          out << format("  %s requires %s\n", rule[:trigger], rule[:requires].join(", "))
        end
      end
      out << "\n"
      out << "builtin groups (related builtins -- pairs and families -- with call examples):\n"
      BUILTIN_GROUPS.each do |g|
        forms = g[:members].map { |m| example_for(m) || m }
        out << format("  %s\n", g[:name])
        out << "    #{forms.join('  ')}\n"
        out << "    #{g[:note]}\n"
      end
      out << "\n"
      out << maps_report
      out << record_channels_report
      out << "ready-made probe -> domain:\n"
      KREW_PROBE_DOMAINS.each { |p, d| out << format("  --probe %-5s -> %s\n", p, d) }
      out << "\nattach kinds (#{ATTACH_KINDS.length}) -- `spinel-ebpf capabilities --json` lists them with their conventions:\n"
      out << "  #{ATTACH_KINDS.map { |a| a[:kind] }.join(' ')}\n"
      out << "\nmachine-readable authoring contract: spinel-ebpf capabilities --json\n"
      out
    end

    # ===================================================================
    # The machine-readable authoring contract: publish what can be done.
    #
    # Builtin signatures (arity and parameter names), the conventions of each attach
    # kind, what the Ruby subset does and does not accept, and the enrichers are all
    # held here as plain data and emitted as one JSON document by
    # `capabilities --json`. An author -- often a program -- can then read the legal
    # moves rather than guess at them.
    #
    # That this is complete -- every builtin and attach kind appears -- and that its
    # arities have not drifted from the generator's is enforced by the unit tests.
    #
    # The authority on a signature is the generator's own `expects N` and
    # `expect_no_args` checks. This module cannot require the generator -- the
    # generator reads the gate allowlist from here, so it would be circular -- so the
    # arities are mirrored, and a test parses the generator's source to detect drift.
    # A builtin whose parameter names cannot be extracted mechanically is marked
    # opaque rather than guessed at.
    # ===================================================================

    # Structural groups, holding the same name sets the generator does; a test keeps
    # them from drifting apart.
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

    # The explicit signature table. Each value is [arity, params or nil, summary];
    # a nil params means the builtin is opaque.
    #   arity  : Integer | :variadic
    #   params : the argument names, taken from the generator's own checks; nil when opaque
    # The generator is the single authority for arity and parameter names, and a test
    # detects drift. The pkt_* and tcp_sock_* families are generated below.
    SIG_TABLE = {
      # --- observability: emit / hist / latency / task / stack / etc. ---
      "spnl_emit"        => [1, %w[value],            "emit one __s64 into the ringbuf, behind the 16-byte header"],
      "spnl_emit_str"    => [1, %w[ptr],              "read a string from a user pointer and emit it into the string ringbuf"],
      "spnl_emit_pair"   => [2, %w[a b],              "emit two values as one event"],
      "spnl_emit3"       => [3, %w[a b c],            "emit three values as one event"],
      "spnl_emit4"       => [4, %w[a b c d],          "emit four values as one event"],
      "emit_argv"        => [1, %w[argv],             "walk an execve argv[] and emit each entry into the string ringbuf"],
      "emit_comm"        => [0, [],                   "emit the current process's comm into the string ringbuf"],
      "comm_hash"        => [0, [],                   "return the first 8 bytes of comm as an __s64, for grouping"],
      "hist_observe"     => [1, %w[value],            "add one sample to a log2 histogram"],
      "hist_observe_by"  => [2, %w[key value],        "add one sample to a keyed log2 histogram"],
      "hist_observe_linear" => [1, %w[slot],          "add to a linear histogram; the caller has already chosen the bucket"],
      "ktime_ns"         => [0, [],                   "bpf_ktime_get_ns()"],
      "latency_start"    => [0, [],                   "begin: record the entry time, keyed by thread id"],
      "latency_end"      => [0, [],                   "end: return the elapsed nanoseconds and drop the entry"],
      "lat_start"        => [1, %w[key],              "begin a latency measurement under any key"],
      "lat_end"          => [1, %w[key],              "end a latency measurement under any key, returning the elapsed time"],
      "task_load"        => [0, [],                   "read this task's storage"],
      "task_store"       => [1, %w[value],            "write this task's storage"],
      "task_incr"        => [1, %w[delta],            "add to this task's storage in a single read-modify-write"],
      "task_swap"        => [1, %w[value],            "swap this task's storage, a general read-modify-write"],
      "stack_id"         => [0, [],                   "kernel stack id (STACK_TRACE map)"],
      "user_stack_id"    => [0, [],                   "user stack id (STACK_TRACE map)"],
      "off_cpu_start"    => [1, %w[pid],              "start an off-CPU measurement, stashing the time and stack by pid"],
      "off_cpu_observe"  => [1, %w[pid],              "on return, bin the elapsed off-CPU time into a keyed histogram"],
      "leak_record"      => [3, %w[ptr size stack_id],"record an allocation, for leak tracking"],
      "leak_forget"      => [1, %w[ptr],              "drop the record on free, for leak tracking"],
      "lock_edge"        => [2, %w[a b],              "record a lock-ordering edge, for deadlock detection"],
      "mim_inc"          => [2, %w[group key],        "map-in-map: add to inner[key]"],
      "mim_get"          => [2, %w[group key],        "map-in-map: read inner[key]"],
      "fifo_push"        => [1, %w[value],            "push onto a queue map"],
      "fifo_pop"         => [0, [],                   "pop from a queue map"],
      "lifo_push"        => [1, %w[value],            "push onto a stack map"],
      "lifo_pop"         => [0, [],                   "pop from a stack map"],
      "depth_inc"        => [1, %w[key],              "increment the recursion-depth counter"],
      "depth_dec"        => [1, %w[key],              "decrement the recursion-depth counter"],
      "path_counter_inc" => [1, %w[key],              "atomically increment a general keyed counter"],
      "kfield"           => [:variadic, %w[ptr struct field], "read a kernel struct field safely through CO-RE, following any number of hops"],
      "kptr"             => [2, %w[ptr struct],       "bind a local to a struct type, so that .field accessors work on it"],
      "emit_kfield_str"  => [:variadic, %w[ptr struct field], "emit a **string** field of a kernel struct into the string ringbuf -- the string counterpart of kfield's scalar, following any number of hops. A comma is a pointer hop, a dot an embedded member, exactly as in kfield. Whether the last hop is a char[N] (the bytes themselves) or a char * (what it points at) is decided at compile time from the C type, so there is nothing to spell differently; getting it wrong fails a static assertion. Not gated: bpf_probe_read_kernel_str was observed to load under every program type"],
      "kfield_str_eq"    => [:variadic, %w[ptr struct field literal], "a use-neutral predicate: whether a **string** field of a kernel struct equals a literal. An expression, not gated; the handler's return value decides what happens. The **last string argument is the value compared against** and everything before it is the field path. Unlike bpf_d_path this works under kprobe too: a hook where d_path is impossible by construction can still read file->f_path.dentry->d_name.name"],
      # --- enforcement: audit / lineage / deny selector ---
      "emit_path"        => [1, %w[file],             "emit a file's full path into the string ringbuf; gated to certain hooks"],
      "emit_parent_path" => [0, [],                   "emit the parent executable's full path; gated to certain hooks"],
      "path_eq"          => [2, %w[file path_literal], "a use-neutral predicate: whether a file's full path equals a literal. It is an expression and is gated to certain hooks. It only decides -- what happens next is the handler's return value"],
      "path_starts_with" => [2, %w[file path_literal_prefix], "a use-neutral predicate: whether a file's full path starts with a literal prefix. An expression, gated to certain hooks; the handler's return value decides what happens. It uses per-CPU scratch space, so it compares correctly up to the full path length"],
      "path_contains"    => [2, %w[file path_literal_substr], "a use-neutral predicate: whether a literal appears anywhere in a file's full path, at any offset. An expression, gated to certain hooks; the handler's return value decides what happens. It sweeps the whole path with a sliding window, so no offset slips past it"],
      "parent_path_eq"   => [1, %w[path_literal],     "a use-neutral predicate: whether the parent executable's path equals a literal. An expression, gated to certain hooks; the handler's return value decides what happens"],
      "ppid"             => [0, [],                   "the parent thread-group id, as numbered in the init namespace"],
      # capability / namespace / file type. All three are reachable with kfield already
      # -- cred, nsproxy and i_mode are ordinary CO-RE chains. What a name buys here is
      # not reach but **how the value has to be compared**, and all three are of the kind
      # that cannot be compared raw: a bit set, an inode number that means nothing on its
      # own, and a mode word in which type and permissions share the same field.
      #
      # The first six read the **current** task, so the generator refuses them outside a
      # process-context hook. Measured: the same call placed in an XDP program returns,
      # without any error, the capabilities of whichever CPU burner happened to be
      # running when a packet arrived from another machine. Only file_type reads a
      # pointer the hook handed it, so like kfield it is not gated.
      "has_cap"          => [1, %w[cap],              "a predicate: whether the current task holds one **effective** capability, as 0 or 1. Written `has_cap(CAP::SYS_ADMIN)`. **Trying the raw value yourself is wrong**: CAP_SYS_ADMIN is bit number 21, not a mask, so `cap_effective & CAP_SYS_ADMIN` inspects bits 0, 2 and 4 and answers the same whether or not the task holds 21. Because this is compiled ahead of time it is two instructions in the xlated program, a mask and a branch"],
      "has_cap_permitted"   => [1, %w[cap],           "a predicate: whether the capability is in the current task's **permitted** set. Effective is what the task may use now; permitted is the ceiling it may raise effective to"],
      "has_cap_inheritable" => [1, %w[cap],           "a predicate: whether the capability is in the current task's **inheritable** set -- the set that survives an exec"],
      "cap_effective"    => [0, [],                   "the current task's effective capability set **itself**, as a 64-bit bit set. For **reporting**: to decide, use has_cap, because `& CAP_*` is always wrong (see above). Meant for emitting to userspace and decoding there"],
      "ns_id"            => [1, %w[key],              "the inode number of one of the current task's namespaces. The key is a symbol literal (:mnt :net :uts :ipc :cgroup :time :user :pid). **:pid follows thread_pid**: nsproxy->pid_ns_for_children is the namespace a *child* would enter, and for a task that unshared without forking the two differ -- measured, and both look like perfectly ordinary inode numbers. The value is for correlation; to ask whether this is the host, use in_host_ns"],
      "in_host_ns"       => [1, %w[key],              "whether the current task is in the **initial (host) namespace** of that kind, as 0 or 1. The key is the same symbol as ns_id. The initial namespace's inode is read from an untyped ksym (init_nsproxy / init_user_ns, which libbpf resolves from kallsyms at load time). **Reading /proc/1/ns instead is wrong inside a container**, where it names the container's own init -- measured as a different inode from the real one. A typed ksym does not work here because BTF carries no VAR for the init_* symbols"],
      "file_type"        => [1, %w[file],             "the **file type** of a `struct file *`'s inode, already masked with S_IFMT. Compare it as `file_type(f) == FileType::REG`. **Returning it masked is the point**: in a raw i_mode the type and the permission bits share one word, so `i_mode == S_IFREG` is false for every regular file, and `i_mode & S_IFDIR` is **true for a socket**. The types are FileType::REG / DIR / LNK / SOCK / BLK / CHR / FIFO. Not gated -- like kfield it only reads a pointer the hook passed in"],
      # --- L7: HTTP, TLS and DNS spans, L7 latency, and off-CPU correlation ---
      "http_req_start"   => [2, %w[sk msg],           "read the send buffer and, if it is an HTTP request, record it by socket"],
      "http_resp_stash"  => [2, %w[sk msg],           "stash the receive buffer by thread id"],
      "http_emit"        => [1, %w[ret],              "read the stash, correlate by socket, and emit one HTTP span"],
      "redis_req_start"  => [3, %w[sk msg size],      "read the first size bytes of the send buffer and, if it is a RESP command, record it by socket"],
      "redis_resp_stash" => [2, %w[sk msg],           "stash the receive buffer by thread id, for Redis"],
      "redis_emit"       => [1, %w[ret],              "read the stash, correlate by socket, and emit one Redis span with its command, error and duration"],
      "ssl_req_start"    => [2, %w[ssl buf],          "read the plaintext handed to SSL_write and, if it is HTTP, record it by SSL handle"],
      "ssl_resp_stash"   => [2, %w[ssl buf],          "stash the buffer by thread id on entry to SSL_read"],
      "ssl_emit"         => [1, %w[ret],              "correlate the decrypted buffer by SSL handle and emit a span for the plaintext"],
      "go_tls_write"     => [3, %w[conn ptr len],     "read the plaintext slice handed to Go's TLS write and emit an HTTP request span. There is no socket here, so the scheme is https"],
      "go_tls_req"       => [3, %w[conn ptr len],     "read that plaintext within its length bound and stash it by connection -- the request half of a full RED measurement"],
      "go_tls_resp_stash"=> [2, %w[conn ptr],         "stash the receive buffer on entry to Go's TLS read, keyed by goroutine rather than thread: a blocking read can move between threads"],
      "go_tls_emit"      => [1, %w[ret],              "on return from that read, find the stash by goroutine, correlate it with the request by connection, and emit a full RED span"],
      "dns_req_start"    => [2, %w[sk msg],           "begin correlating a DNS query"],
      "dns_resp_stash"   => [2, %w[sk msg],           "stash the DNS response buffer"],
      "dns_emit"         => [1, %w[ret],              "DNS span emit"],
      "emit_dns"         => [1, %w[msg],              "emit a DNS query seen on a udp_sendmsg as a packed record. **Independent of the resolver's implementation language AND of how it sends**: connected or not, one iovec or several, the same bytes are read. What cannot be read is a send whose bytes are not in user memory at all (splice/vmsplice, an ITER_BVEC iterator); such a record carries an empty `raw` and the drain reports it as `unreadable_payload` rather than turning it into a zero-filled span. Filter the destination with udp_dport(sk, msg) -- sock_dport is 0 for an unconnected sender"],
      "emit_tcp_payload" => [1, %w[msg],              "emit the first 128 bytes of a send buffer as a string, for protocol-independent parsing in userspace"],
      "emit_tcp_stream"  => [3, %w[sk msg size],      "emit a send buffer as a packed record keyed by socket, so userspace can accumulate per connection and reassemble a stream across many of them"],
      "req_start"        => [1, %w[sk],               "record the start of an L7 round trip in tcp_sendmsg"],
      "emit_l7"          => [1, %w[sk],               "emit an L7 round-trip latency span once the data has reached the application"],
      "offcpu_recv_stash"=> [2, %w[sk msg],           "open an off-CPU window for this thread on an HTTP request"],
      "offcpu_begin"     => [1, %w[ret],              "open the off-CPU window, on return"],
      "offcpu_account"   => [3, %w[prev_pid prev_state next_pid], "accumulate the voluntary off-CPU stacks seen within the window"],
      "offcpu_emit"      => [2, %w[sk msg],           "close the window and emit a span carrying the off-CPU breakdown"],
      # --- net: connect / L4 / datapath / conntrack / arena / tcp slice ---
      "emit_connect"     => [7, %w[skaddr daddr dport family oldstate daddr6_hi daddr6_lo], "emit a connection as one packed record, carrying the process, the peer and the round-trip time together"],
      "sock_owner_set"   => [1, %w[sk],               "record socket to {pid, comm} at connect time, so the process can be recovered in softirq context"],
      "blocklist_match"  => [1, %w[ip],               "a use-neutral predicate: whether an address is in an exact-match set, in host order. A match means deny for a blocklist or allow for an allowlist; the return value decides. Seed the set from userspace by declaring `ffi_func :sp_bpf_blocklist_add, [:uint32], :int` in a `module` (a class will not do) and calling `M.sp_bpf_blocklist_add(0x0a000001)` at top level with an integer literal"],
      "cidr_blocklist_match" => [1, %w[ip],           "a use-neutral predicate: whether an address falls in a set of CIDRs, by longest-prefix match, in host order. It is likewise use-neutral -- a match means deny for a blocklist or allow for an allowlist; the return value decides. Seed the set from userspace by declaring `ffi_func :sp_bpf_cidr_blocklist_add, [:uint32,:uint32], :int` in a `module` (a class will not do) and calling `M.sp_bpf_cidr_blocklist_add(0x7f000000, 8)` at top level with an integer address and prefix length. Calling it again at run time updates the set, and `_del` works the same way"],
"pkt_dynptr_byte_at" => [1, %w[off],            "read one byte of the XDP frame at a **runtime offset** (0-255, or -1 when the offset is out of range or the context is not XDP). It is built on bpf_dynptr_from_xdp plus bpf_dynptr_slice: the dynptr carries the bounds check, so the caller does not write `data + off > data_end` (the pkt_* readers do not need one either, because their offsets are fixed). The TC equivalent is skb_load_byte(off)"],
"tail_call_to"     => [1, %w[slot],             "**transfer control** to the program in this unit's PROG_ARRAY at `slot` (bpf_tail_call: it does not return, so the caller never resumes). Slots follow the **declaration order** of `def xdp_tail__<name>` -- 0, 1, ... -- and the loader writes each program's fd into the matching slot. WARNING: **failure is not loud**. A jump into an empty slot returns no error; it silently falls through and the next statement runs, which is why the idiom is to put `XDP_PASS` after the call. An integer literal outside the range of declared targets **dies at compile time**, but a computed slot (`tail_call_to(n)`) cannot be checked. The kernel allows 33 levels of nesting. The reason to split at all is that the 1M-instruction budget is **per program**"],
"user_ringbuf_drain" => [0, [],                 "pick up commands sent **host -> kernel**. Drains every record queued in this unit's `bpf_user_cmds` ring (USER_RINGBUF, 256 KB) in **FIFO order**, calling this unit's `def user_ringbuf__<name>(value)` once per record. It may be called **anywhere** (measured LOAD_OK in all 12 program types), so there is no context gate. WARNING: **you choose where to drain** -- which hook picks the commands up is what sets command latency, so it is never synthesised (in `def xdp__<name>` that is once per packet; in `def kprobe__<func>`, once per call). A callback with no drain, a drain with no callback, and two callbacks all **die at compile time**. WARNING: **the record is a fixed 8 bytes**, and the sender is the glue's `sp_bpf_user_cmd_push(value)` (declare `ffi_func :sp_bpf_user_cmd_push, [:int64], :int` in a `module M`). A hand-rolled pusher sending fewer than 8 bytes makes **the callback fire and the count rise while the value stays 0** -- bpf_dynptr_read returns -E2BIG and gives up silently (measured). WARNING: **kernel floor 6.1**, so unlike `param` (.rodata, 5.2) it raises the portability contract. Against `param`: `param` is set once before load and then frozen; this one carries values **any number of times while running**, in order, in batches"],
      "cpumap_redirect"  => [1, %w[cpu],              "redirect into a CPU map"],
# The pure-XDP TCP slice builtins. All seven are XDP-only (the helpers
# rewrite and RESIZE the frame through `struct xdp_md`), and all seven
# return __s64 so `< 0` is the error check every example uses.
"tcp_syncookie_gen"   => [0, [],                 "build a **stateless SYN cookie** for this SYN (bpf_tcp_raw_gen_syncookie_ipv4). A non-negative result carries the **cookie in its low 32 bits (the SYN-ACK sequence number) and the MSS above that**; an error or a non-TCP packet gives a negative one. WARNING: **it grows the frame to a 60-byte TCP header before returning**, because the kfunc requires that 60 bytes be readable regardless of the real header length. The grow is not an optimisation, it is the precondition for calling at all: without it the program **does not load** (`invalid access to packet, off=34 size=60`) -- which is the shape the retired Ruby generator emitted, so that form had never loaded either. The widened frame is shrunk back to 14+20+24 by its only consumer, `tcp_reply_synack(cookie)`. **To do both steps in one call, use `tcp_synack_cookie`**, which never exposes the intermediate state"],
"tcp_syncookie_check" => [0, [],                 "**validate the cookie** carried back by the handshake ACK (bpf_tcp_raw_check_syncookie_ipv4). Non-negative means genuine -- this is the third packet of a handshake whose SYN-ACK you sent -- and negative means forged. WARNING: **it does not touch the frame**: the kfunc does not require TCP_MAXLEN, so no grow is needed and the ACK passes through intact (that is the asymmetry with `gen`). WARNING: once validated, that ACK must **not** be handed to the kernel: there is no listen socket, so the stack answers with an RST and the connection dies. Consume it with `XDP::DROP`"],
"tcp_reply_header"    => [3, %w[seq ack flags],  "turn the current packet into a **TCP reply with no payload** (swap MAC/IP/ports, set the sequence, acknowledgement and flag byte, doff=5, recompute both checksums, resize to 14+20+20). `seq` and `ack` are numbers in **host order**; `flags` is the TCP flag byte (`TCP::Flag::FIN | TCP::Flag::ACK` and so on). Returns 0 or -1, and the caller returns `XDP::TX`. This is for FIN-ACKs and bare ACKs -- to answer with a body, use `tcp_reply_data`"],
"tcp_reply_synack"    => [1, %w[cookie],         "turn the current SYN into a **SYN-ACK carrying an MSS option** (pass the return value of `tcp_syncookie_gen` straight in: the sequence comes from its low half and the MSS from its high half). The acknowledgement is the received sequence plus one, doff=6 (a 24-byte header), and the frame is resized to 14+20+24 at the end. Returns 0 or -1, and the caller returns `XDP::TX`. WARNING: this call is what shrinks the frame `tcp_syncookie_gen` widened, so **once you call gen you must call this**, or a frame with a 60-byte header goes out on the wire"],
"tcp_synack_cookie"   => [0, [],                 "do the whole SYN -> SYN-ACK step in **one call** (grow to 60, generate the cookie, build the SYN-ACK with its MSS, shrink). Same result as `tcp_syncookie_gen` plus `tcp_reply_synack`, **without the widened intermediate frame ever being visible**. Returns 0 or -1, and the caller returns `XDP::TX`. This is the one the public example uses"],
"tcp_reply_data"      => [3, %w[seq ack payload], "turn the current packet into a **reply with a body** (swap, set sequence and acknowledgement, FIN|PSH|ACK, doff=5, write the body, checksum, resize to 14+20+20+len). `payload` must be a **compile-time string literal** -- it is burned in as a const byte array whose length fixes every size in the generated header -- and is capped at 1024 bytes. Returns 0 or -1, and the caller returns `XDP::TX`. WARNING: **the body has to fit in the received frame**, since the frame is shrunk at the end, so a reply longer than the request line cannot be written. Repeating the same literal still emits one helper (up to 8 distinct ones per unit)"],
"payload_starts"      => [1, %w[prefix],         "whether the current packet's **TCP payload begins with a literal** (1 or 0). `prefix` must be a **compile-time string literal** of at most 64 bytes, and is **unrolled into one comparison per byte** -- no loop and no bounded read, so it is cheap for the verifier, which is the ahead-of-time compiler paying off directly. WARNING: **it does not touch the frame**. Repeating the same literal still emits one helper (up to 8 distinct ones per unit)"],
      "xsk_redirect"     => [1, %w[qid],              "redirect into an AF_XDP socket map"],
      "dev_redirect"     => [1, %w[idx],              "redirect into a device map"],
      "sock_ops_op"      => [0, [],                   "ctx->op (sock_ops)"],
      "sock_ops_state"   => [0, [],                   "ctx->args[1] (sock_ops state)"],
# SO_REUSEPORT worker selection. The pair is one feature -- reading the
# hash without steering is a filter, steering without the hash is a pin;
# both are legitimate, which is why they are separate builtins.
"reuseport_hash"   => [0, [],                   "**the kernel's own 5-tuple hash** of this SYN (sk_reuseport_md->hash). This is the input a consistent hash is built from: the same 4-tuple always hashes the same, so `reuseport_hash % N` pins a connection to one worker (cache locality across keep-alive). **The result is non-negative** (the field is a __u32), so `% N` lowers to the unsigned form and passes the verifier for a literal N (`% 4` becomes `&3`, `% 3` an unsigned BPF_MOD). WARNING: **when N is a runtime value (a map, or a `param`) clang fails with `unsupported signed division`** -- that message comes from clang, not from spinel-ebpf"],
"worker_select"    => [1, %w[idx],              "**steer** this connection to the socket in slot `idx` of the REUSEPORT_SOCKARRAY (bpf_sk_select_reuseport). What lands in a slot is **decided by userspace**: each worker calls `sp_bpf_reuseport_register(listen_fd, idx)`, and one of them calls `sp_bpf_reuseport_attach(listen_fd, \"sk_reuseport__<name>\")` to attach the program to the group (both are existing FFI entry points). WARNING: **selecting an empty slot does not fail**. The helper returns -ENOENT, the code generator discards it, and the kernel **quietly falls back to its own 5-tuple spread** -- so \"the program picked this worker\" and \"the program picked nothing\" are indistinguishable in anything the probe emits. Keeping the number of registered workers in step with your own `% N` is the author's job (`spinel-ebpf describe` prints how many slots your arithmetic reaches)"],
      "sock_addr_ip4"    => [0, [],                   "the destination IPv4 address of a connect or bind, in host order"],
      "sock_addr_port"   => [0, [],                   "the destination port of a connect or bind, in host order"],
      # Reading a `struct sock *` by name, from any context. Every value is in **host
      # order**, the same rule the pkt_* and sock_addr_* builtins follow. Byte order
      # varies field by field inside struct sock_common (skc_dport is __be16 while
      # skc_num is __u16), so the conversion is baked into each accessor: a caller who
      # applies one uniform rule is guaranteed to get one of the two silently wrong.
      "sock_sport"       => [1, %w[sk],               "source port, in host order. It reads skc_num, which is **already** in host order, so unlike dport it is not converted. Raw, that field reads as 60404 and dport reads as 47903 -- both look like ports, which is why applying ntohs everywhere and applying it nowhere are both wrong"],
      "sock_dport"       => [1, %w[sk],               "the port **this socket is connected to**, in host order. It reads skc_dport, which is a __be16, so ntohs is applied; the raw value is what a port looks like byte-swapped. **Do not use it to filter UDP sends**: a sender that passes the destination on every send (dnsmasq does) leaves skc_dport at 0, so `== 53` is always false and the probe reports nothing rather than reporting it wrong. The destination of a datagram is udp_dport(sk, msg)"],
      "sock_saddr"       => [1, %w[sk],               "source IPv4 address, in host order (skc_rcv_saddr, converted). **Only meaningful when sock_family is AF_INET**: on an AF_INET6 socket it still returns a plausible-looking number such as 0 or 127.0.0.6"],
      "sock_daddr"       => [1, %w[sk],               "the IPv4 address **this socket is connected to**, in host order (skc_daddr, converted). **Only meaningful when sock_family is AF_INET**, and it has the same trap as sock_dport on a UDP send: 0 when the socket was never connected. The destination of a datagram is udp_daddr(sk, msg)"],
      "sock_family"      => [1, %w[sk],               "AF_INET (2) or AF_INET6 (10), in host order. Branch on this before reading any address accessor"],
      "sock_state"       => [1, %w[sk],               "TCP state, such as TCP_STATE_ESTABLISHED, in host order"],
      "sock_protocol"    => [1, %w[sk],               "IPPROTO_TCP, IPPROTO_UDP and so on, in host order"],
      "sock_saddr6_hi"   => [1, %w[sk],               "the upper 64 bits of the source IPv6 address, in the same hi/lo split the packet accessors use, host order per 32-bit word (::1 is hi=0, lo=1). **Only meaningful when sock_family is AF_INET6**"],
      "sock_saddr6_lo"   => [1, %w[sk],               "the lower 64 bits of the source IPv6 address, same convention. **Only meaningful when sock_family is AF_INET6**"],
      "sock_daddr6_hi"   => [1, %w[sk],               "the upper 64 bits of the destination IPv6 address, same convention. **Only meaningful when sock_family is AF_INET6**"],
      "sock_daddr6_lo"   => [1, %w[sk],               "the lower 64 bits of the destination IPv6 address, same convention. **Only meaningful when sock_family is AF_INET6**"],
      # "Where is this datagram going". The sock_* accessors answer for the socket,
      # and for UDP the two coincide only when the socket is connected -- otherwise
      # the destination is in msg_name. udp_sendmsg's own rule (msg_name wins, else
      # the connected peer) is folded in here, so the author neither has to know it
      # nor can apply half of it.
      "udp_dport"        => [2, %w[sk msg],           "the destination port **of this send**, in host order. Pass the first two arguments of `def kprobe__udp_sendmsg(sk, msg, len)` straight through. **Correct for an unconnected socket too**: the port from msg_name when there is one, otherwise the connected peer's -- which is the order udp_sendmsg itself decides in. That is the only difference from sock_dport(sk), and it is the difference between reporting a send and reporting nothing (measured: dnsmasq forwards upstream with a bare sendto, and a sock_dport probe saw none of it). Handles both AF_INET and AF_INET6. **Send hooks only**: on udp_recvmsg, msg_name is an OUTPUT the kernel is about to write the sender's address into, so reading it at entry interprets uninitialised bytes as a port. The receive side has no equivalent question, so there sock_dport -- limited to connected sockets -- really is the honest ceiling"],
      "udp_daddr"        => [2, %w[sk msg],           "the destination IPv4 address **of this send**, in host order. Same rule as udp_dport (msg_name wins, else the connected peer) and the same limit (**send hooks only**). Returns 0 when the destination is IPv6; that is sock_daddr6_*'s territory"],
      "iter_task"        => [0, [],                   "the current task_struct pointer while iterating tasks"],
      "fib_lookup"       => [1, %w[dst],              "an IPv4 route lookup, yielding the egress interface index"],
      "fib_lookup6"      => [2, %w[dst_hi dst_lo],    "an IPv6 route lookup"],
      "sk_lookup_tcp"    => [4, %w[saddr daddr sport dport], "look up a TCP socket by 4-tuple"],
      "sk_assign_tcp"    => [4, %w[saddr daddr sport dport], "look a socket up and steer the packet to it"],
      "redirect"         => [1, %w[ifindex],          "bpf_redirect (L3 forwarding)"],
      "skb_load_byte"    => [1, %w[offset],           "read one byte from the packet"],
      "skb_load_u16"     => [1, %w[offset],           "read a 16-bit value from the packet"],
      "skb_load_u32"     => [1, %w[offset],           "read a 32-bit value from the packet"],
      "skb_store_byte"   => [2, %w[offset value],     "write one byte into the packet"],
      "skb_store_u16"    => [2, %w[offset value],     "write a 16-bit value into the packet"],
      "skb_store_u32"    => [2, %w[offset value],     "write a 32-bit value into the packet"],
      "l3_csum_replace"  => [3, %w[offset from to],   "patch the L3 checksum for a 16-bit change"],
      "l3_csum_replace_ip" => [3, %w[offset from to], "patch the L3 checksum for a 32-bit address change"],
      "l4_csum_replace"  => [3, %w[offset from to],   "patch the L4 checksum for a 16-bit change"],
      "l4_csum_replace_ip" => [3, %w[offset from to], "patch the L4 checksum for a 32-bit change, including the pseudo-header"],
      "l4_offset"        => [0, [],                   "the offset where L4 begins, accounting for IP options"],
      "flow_get"         => [2, %w[map_name field],   "connection tracking: read a field of the current flow; the field is named by a symbol"],
      "flow_set"         => [3, %w[map_name field value], "connection tracking: write a field of the current flow; the field is named by a symbol"],
      "flow_del"         => [1, %w[map_name],         "connection tracking: delete the current flow's entry"],
      "queue_push"       => [2, %w[skb to_free],      "enqueue a packet onto a BPF list"],
      "queue_pop"        => [0, [],                   "dequeue a packet from a BPF list"],
      "arena_set"        => [2, %w[index value],      "write to a flat array in the arena"],
      "arena_get"        => [1, %w[index],            "read from a flat array in the arena"],
      "arena_hash_set"   => [2, %w[key value],        "write to a hash table in the arena"],
      "arena_hash_get"   => [1, %w[key],              "read from a hash table in the arena"],
      "arena_hash_del"   => [1, %w[key],              "delete from a hash table in the arena"],
      "arena_list_push"  => [1, %w[value],            "push onto a linked list in the arena"],
      "arena_list_sum"   => [0, [],                   "sum a linked list in the arena"],
      # --- core: identity / cgroup / control channel ---
      "divu"             => [2, %w[a b],              "unsigned 64-bit division, which the verifier accepts where signed division is refused"],
      "i32"              => [1, %w[x],                "truncate a 32-bit kernel argument and sign-extend it, since the upper half holds garbage on arm64"],
      "pid"              => [0, [],                   "the pid as userspace means it: the upper half of the pid/tgid pair"],
      "tgid"             => [0, [],                   "thread group id"],
      "tid"              => [0, [],                   "kernel thread id"],
      "uid"              => [0, [],                   "the effective uid: the lower half of the pair bpf_get_current_uid_gid returns"],
      "gid"              => [0, [],                   "the effective gid: the upper half of the pair bpf_get_current_uid_gid returns"],
      "cpu_id"           => [0, [],                   "bpf_get_smp_processor_id()"],
      "cgroup_id"        => [0, [],                   "the current cgroup id, which is the cgroup directory's inode and the key to Kubernetes pod attribution"],
      # One body attached to several symbols needs **one spelling** for "which symbol am
      # I on right now". Both lowerings produce the same shape -- a literal when the
      # definition is expanded, bpf_get_attach_cookie when it rides kprobe_multi -- so a
      # list can grow and the generator can switch mechanisms without the body changing.
      "attached_index"      => [0, [],                "in a multi-symbol handler, this handler's index in the declared list"],
      "attached_symbol_eq"  => [1, %w[symbol],        "in a multi-symbol handler, whether this handler is on \"<symbol>\". The argument is a literal, resolved to an index at compile time"],
      "field_exists"     => [3, %w[ptr struct field], "whether BTF says this struct has this field"],
    }.freeze

    # ===================================================================
    # **Withdrawn** builtins: names that used to be advertised in SIG_TABLE, and were
    # then measured not to exist in the production C generator at all.
    #
    # Why keep a table rather than simply delete the names:
    #
    #   1. **Record.** Pretending they never existed is the same act as deleting them
    #      quietly. Each of these was really measured working once; what was lost is the
    #      implementation, not the observation.
    #   2. **A permanent negative control for the gate.** tools/affordance_gate.rb
    #      measures *both* directions on every run: every advertised affordance really
    #      compiles to what it advertises, and every withdrawn one really fails. With
    #      only one direction, a gate that degenerates into "always ok" stays green --
    #      a text-comparison gate says nothing when the broken output is stable. Checking
    #      both directions makes a degenerate gate fail on itself.
    #   3. **Detecting a re-port.** If an implementation comes back while the name is
    #      still listed here, the gate fails, which catches "implemented it but forgot to
    #      put it back in the affordance".
    #
    # `ctx` is the attach form a minimal probe needs, which is what the gate builds from.
    # `why` says why demotion was chosen over porting, and `instead` says **what to
    # write in its place**. The withdrawn attach kinds have carried `instead` for a
    # while; the builtins used to bury the same thing inside the `why` prose, which is
    # half the information for a consumer reading only the JSON.
    # ===================================================================
    WITHDRAWN = {
# `reuseport_hash` and `worker_select` were withdrawn here and have since
# been ported, together with the REUSEPORT_SOCKARRAY they index. The glue
# half (sp_bpf_reuseport_register / sp_bpf_reuseport_attach) had in fact
# never been lost, which is the part the stated reason got wrong.
# `tail_call_to` was withdrawn here and has since been ported together with
# the two halves it needs: the `xdp_tail__` attach kind and the PROG_ARRAY.
      "xdp_match_health" => { ctx: :xdp, arity: 0,
                              why: "Part of the XDP_TX static-response path, a large piece including compile-time checksum precomputation. It was also measured to top out around 35-50% reliability for structural reasons, and was superseded by the pure-XDP TCP slice",
                              instead: "`def xdp__tcp_slice__health; XDP_PASS; end` -- the successor that answers the same /health without the kernel's TCP stack owning the connection. The generator emits the handshake, the retransmits and the FIN, so the structural 35-50% ceiling these two had is simply absent (the slice was measured at 100% sequentially)" },
      "xdp_reply_health" => { ctx: :xdp, arity: 0,
                              why: "As above: the XDP_TX static-response path, superseded by the TCP slice",
                              instead: "as above -- `def xdp__tcp_slice__health`. The two builtins were only ever used as a pair, so the replacement is the same single attach kind" },
# `pkt_dynptr_byte_at` was withdrawn here and has since been ported, along
# with its chain spelling `pkt.byte_at(off)`. The stated reason was that
# the pkt_* and skb_load_* readers already cover the same read; what they
# do not cover is a runtime offset, which is what this one is for.
# The seven TCP-slice builtins (tcp_syncookie_gen and _check,
# tcp_reply_header and _synack, tcp_synack_cookie, tcp_reply_data,
# payload_starts) were withdrawn here as a set, because the
# `xdp__tcp_slice__` attach kind they belong with was withdrawn. They have
# since been ported as a set, together with that attach kind.
# `user_ringbuf_drain` was withdrawn here and has since been ported with
# the two halves it needs -- the USER_RINGBUF map and the SEC-less
# `user_ringbuf__` callback -- plus the loader half that had never existed
# at all, `sp_bpf_user_cmd_push`.
    }.freeze

    # ===================================================================
    # **Withdrawn attach kinds.** Same role as WITHDRAWN above, kept in its own table
    # because the silence has a different quality.
    #
    #   An unported **builtin** dies loudly: "CallNode not yet ported".
    #   An unported **attach kind** does not die. The method name simply matches nothing,
    #   so the generator treats it as an ordinary method, wraps it in SEC("syscall"), and
    #   exits 0 having produced a program that **loads, attaches to nothing, and never
    #   fires once**. Measured: the output is byte-identical to that of a method with no
    #   attach prefix at all.
    #
    # So taking a kind out of the affordance is only **half** the fix. The other half is
    # CC_WITHDRAWN_ATTACH in the C generator, which refuses these method names **at
    # compile time**. The table and the refusal are one-to-one, and
    # tools/affordance_gate.rb reconciles both directions on every run: an advertised
    # kind must emit the SEC it advertises, and a withdrawn kind must always fail --
    # which is also how the gate keeps proving it can still tell the two apart.
    #
    # `probe` is the surface a gate or an audit writes to build a minimal probe: either
    # a method name or the reactor form.
    # ===================================================================
    WITHDRAWN_ATTACH = {
# EMPTY, and that is the finished state, not a gap.
#
# Four kinds passed through here: :timer, :xdp_tail, :user_ringbuf and --
# last of them -- :xdp_tcp_slice. Every attach kind this code generator
# advertises is now implemented, which is the claim that could not be made
# about any of them when the audit found them silently dead.
#
# Nothing is invented to keep the record non-empty. The gate no longer
# aborts when this table is empty, and the withdrawn-sugar and
# withdrawn-map inventories emptied the same way, without a replacement.
# Keeping an inventory armed by leaving something broken in the shipped
# product is precisely the pressure that split the negative control off it:
# the controls that used to live off this table are synthesised now
# (tools/affordance_gate.rb --section attach self-check).
    }.freeze

    # Assemble every builtin's signature, from the explicit table plus the generated families.
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
      # An opaque kfunc: its arity is known from the generator's table, but the Ruby
      # parameter names come from a struct_ops member signature and cannot be
      # extracted mechanically. Marked opaque rather than guessed at.
      { "scx_dispatch" => 4, "scx_consume" => 1, "scx_kick_cpu" => 2,
        "scx_pick_idle_cpu" => 2, "scx_create_dsq" => 2,
        "qdisc_skb_drop" => 2, "qdisc_init_prologue" => 2,
        "qdisc_reset_destroy_epilogue" => 1, "qdisc_watchdog_schedule" => 3,
        "qdisc_bstats_update" => 2 }.each do |name, arity|
        sigs[name] = { arity: arity, params: nil, opaque: true,
                       summary: "a kfunc passthrough: hands a kernel struct pointer through from a struct_ops member" }.freeze
      end
      sigs.freeze
    end

    # A builtin to the context it requires -- the hooks the generator enforces at
    # compile time.
    #   { secs: [SEC...] }   d_path gate
    #   { kinds: [attach kind...] }  attach-kind gate
    # A builtin absent from this table is not enforced; it gets a best-effort note
    # instead.
    CONTEXT_REQUIREMENTS = begin
      reqs = {
        "emit_path"        => { secs: DPATH_OK_SECS },
        "emit_parent_path" => { secs: DPATH_OK_SECS },
        "path_eq"          => { secs: DPATH_OK_SECS },
        "path_starts_with" => { secs: DPATH_OK_SECS },
        "path_contains"    => { secs: DPATH_OK_SECS },
        "parent_path_eq"   => { secs: DPATH_OK_SECS },
        "cpumap_redirect"  => { kinds: %i[xdp] },
        "xsk_redirect"     => { kinds: %i[xdp] },
        # The helper's first parameter is a `struct xdp_md *`
        # (bpf_dynptr_from_xdp). TC has bpf_dynptr_from_skb, but that side was never
        # shipped and TC already reads bytes with skb_load_byte, so
        # the gate is XDP-only -- the same mask the C codegen enforces.
        "pkt_dynptr_byte_at" => { kinds: %i[xdp] },
        # A tail call lands in a program of the CALLER's own type, and
        # `spnl_prog_array` only ever holds this unit's `def xdp_tail__<name>` --
        # XDP programs. `xdp_tail` is itself an XDP kind here (a target may jump
        # onward, up to the kernel's 33-deep limit), so the one mask covers both
        # spellings of a dispatcher.
        "tail_call_to"     => { kinds: %i[xdp xdp_tail] },
        "dev_redirect"     => { kinds: %i[xdp] },
        # The seven TCP-slice builtins. XDP-only because they
        # rewrite and RESIZE the raw frame (bpf_xdp_adjust_tail) through
        # `struct xdp_md`, and the two syncookie ones bottom out in kfuncs whose
        # first parameter is an XDP packet pointer. `xdp_tcp_slice` is NOT in the
        # mask: that kind's body is discarded, so a builtin written in it would
        # be silently dropped -- which is the one context where "allowed" would
        # be a lie. (The load status of each builtin per program type was measured.)
        "tcp_syncookie_gen"   => { kinds: %i[xdp] },
        "tcp_syncookie_check" => { kinds: %i[xdp] },
        "tcp_reply_header"    => { kinds: %i[xdp] },
        "tcp_reply_synack"    => { kinds: %i[xdp] },
        "tcp_synack_cookie"   => { kinds: %i[xdp] },
        "tcp_reply_data"      => { kinds: %i[xdp] },
        "payload_starts"      => { kinds: %i[xdp] },
        "sock_addr_ip4"    => { kinds: %i[cgroup_connect4 cgroup_bind4] },
        "sock_addr_port"   => { kinds: %i[cgroup_connect4 cgroup_bind4] },
        "sock_ops_op"      => { kinds: %i[sock_ops] },
        "sock_ops_state"   => { kinds: %i[sock_ops] },
        # `struct sk_reuseport_md` and bpf_sk_select_reuseport exist for
        # exactly one program type. The gate is on the kind NAME rather than the
        # C codegen's AttachKind because sk_reuseport shares AK_SK_VERDICT with
        # six other hooks, each with a different ctx struct.
        "reuseport_hash"   => { kinds: %i[sk_reuseport] },
        "worker_select"    => { kinds: %i[sk_reuseport] },
        "iter_task"        => { kinds: %i[iter_task] },
        # Only a multi-symbol handler HAS a "which symbol" question. In a
        # 1-to-1 handler the attach point is the method name, so the codegen
        # refuses these rather than emitting a constant.
        "attached_index"     => { kinds: %i[kprobe_multi] },
        "attached_symbol_eq" => { kinds: %i[kprobe_multi] },
        "flow_get"         => { kinds: %i[xdp tc_ingress tc_egress] },
        "flow_set"         => { kinds: %i[xdp tc_ingress tc_egress] },
        "flow_del"         => { kinds: %i[xdp tc_ingress tc_egress] },
      }
      # The packet-context gate (cc_require_pkt_ctx). The generator has refused
      # these outside a packet program for some time, but the affordance never said
      # so: `capabilities` reported them `gated: false` while the compiler died.
      # That is the same drift as the withdrawn builtins, pointing the other way (the
      # affordance understating a constraint instead of overstating a capability),
      # so it is recorded here rather than left for a reader to discover by
      # hitting it. Masks mirror the C exactly.
      %w[redirect sk_lookup_tcp fib_lookup fib_lookup6]      # CC_CTX_PKT
        .each { |b| reqs[b] = { kinds: %i[xdp tc_ingress tc_egress] } }
      # CC_CTX_TC: they read/write `struct __sk_buff`, which XDP does not have.
      %w[skb_load_byte skb_load_u16 skb_load_u32
         skb_store_byte skb_store_u16 skb_store_u32
         l3_csum_replace l3_csum_replace_ip l4_csum_replace l4_csum_replace_ip
         l4_offset].each { |b| reqs[b] = { kinds: %i[tc_ingress tc_egress] } }
      reqs["sk_assign_tcp"] = { kinds: %i[tc_ingress] }     # CC_CTX_TC_INGRESS
      # The process-context gate (cc_require_task_ctx). These read the CURRENT
      # TASK, so outside a hook where the current task caused the event they are
      # not wrong-ish, they are about a different process -- measured:
      # an XDP program answered has_cap(CAP::SYS_ADMIN) TRUE about a CPU burner
      # for packets sent by another machine, while the real actor answered FALSE
      # in a kprobe in the same run. The kinds mirror cc_task_ctx_kind_ok exactly.
      # (file_type is deliberately NOT here: it reads the hook's own pointer, so
      # it is ungated like kfield.)
      %w[has_cap has_cap_permitted has_cap_inheritable cap_effective ns_id in_host_ns]
        .each { |b| reqs[b] = { kinds: %i[kprobe kretprobe tracepoint raw_tp fentry fexit
                                          uprobe uretprobe usdt perf_event lsm fmod_ret
                                          cgroup_connect4 cgroup_bind4] } }
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

    # Best-effort context notes for the ungated builtins. These are advisory: the
    # generator does not enforce them.
    DOMAIN_CONTEXT_NOTE = {
      observability: "process-context probe (kprobe/kretprobe/tracepoint/fentry/fexit/perf_event/uprobe/usdt); not enforced by the generator",
      enforcement:   "process-context security hook; not enforced by the generator",
      net:           "packet/socket datapath prog (xdp/tc/sk_*); not enforced by the generator",
      l7:            "a process-context kprobe or uprobe on the tcp_* or SSL_* entry points; not enforced by the generator",
      core:          "any eBPF method; not enforced by the generator",
    }.freeze

    # Per-builtin overrides, for where the domain's note would be wrong for a family.
    # The DNS builtins belong to the L7 domain, but their transport is UDP on port
    # 53, so their hooks are udp_sendmsg and udp_recvmsg. The domain note's mention
    # of the TCP and TLS entry points is not merely vague for DNS, it actively points
    # the wrong way. These notes name the hooks each family was designed around --
    # not the whole kernel catalogue, just the intended ones.
    CONTEXT_NOTE_OVERRIDES = {
      "dns_req_start"  => "kprobe/udp_sendmsg -- begin correlating when a port 53 query is sent; process-context; not enforced by the generator",
      "dns_resp_stash" => "kprobe/udp_recvmsg on entry -- stash the response buffer; the copied bytes are read on return; process-context; not enforced by the generator",
      "dns_emit"       => "kretprobe/udp_recvmsg -- correlate the response and emit the span; process-context; not enforced by the generator",
      "emit_dns"       => "kprobe/udp_sendmsg -- emit a DNS query as a packed record (test the destination with udp_dport(sk, msg)); process-context; not enforced by the generator",
    }.freeze

    # ===================================================================
    # Call examples, and the links between related builtins.
    #
    # A clean-room test -- giving a model nothing but these affordances -- showed the
    # catalogue was sufficient to write a working probe, but that two things were
    # being supplied from prior knowledge rather than from here:
    #   (1) no Ruby example anywhere: signatures, but never the calling syntax
    #   (2) no indication of how related builtins relate -- which of pid, tgid and
    #       tid is per-process, for instance
    # These two additions close exactly that, and nothing more.
    #
    # Where the line sits: affordances cover the bridge, the ABI and what is legal.
    # The logic is the author's.
    #   * an example is one line of syntax, not advice on use. How to pick a
    #     threshold, or which algorithm to run, is Ruby logic and belongs to whoever
    #     is writing the probe.
    #   * a note on related builtins states the one fact needed to choose between
    #     them -- granularity, whether they are a pair, whether they are a family --
    #     and does not say when to use them.
    # ===================================================================

    # Call examples. Most are generated below:
    #   * a builtin with known parameters becomes `name(p1, p2, ...)`, using the
    #     parameter names as placeholders
    #   * a zero-argument builtin becomes a bare `name`, which is the dominant idiom
    #     and shows that no parentheses are needed
    #   * an opaque builtin gets none, rather than an invented one
    # Only the builtins whose parameter names alone do not yield valid syntax are
    # written by hand: the ones taking a symbol, a compile-time string literal, or a
    # struct name as a string.
    EXAMPLE_OVERRIDES = {
      # connection tracking: the map and the field are passed as symbols
      "flow_get"       => "flow_get(:conn, :backend_ip)",
      "flow_set"       => "flow_set(:conn, :state, 1)",
      "flow_del"       => "flow_del(:conn)",
      # CO-RE: the struct and field names are passed as strings
      "kfield"         => 'kfield(sk, "sock", "sk_sndbuf")',
      "kptr"           => 'kptr(sk, "sock")',
      # The string forms. A comma is a pointer hop, a dot an embedded member.
      "emit_kfield_str" => 'emit_kfield_str(file, "file", "f_path.dentry", "d_name.name")',
      "kfield_str_eq"  => 'kfield_str_eq(file, "file", "f_path.dentry", "d_name.name", "secret.txt")',
      "field_exists"   => 'field_exists(sk, "tcp_sock", "bytes_acked")',
      # The symbol must be one of the handler's DECLARED names. An unknown one is a
      # compile error, not a comparison that is quietly always false.
      "attached_symbol_eq" => 'attached_symbol_eq("vfs_read")',
      # arguments that must be string literals, so the compiler can unroll the bytes
      "path_eq"        => 'path_eq(file, "/usr/bin/curl")',
      "path_starts_with" => 'path_starts_with(file, "/etc/secret/")',
      "path_contains"  => 'path_contains(file, "/.ssh/")',
      "parent_path_eq" => 'parent_path_eq("/usr/bin/curl")',
# The payload and the prefix are unrolled at compile time, so each has to be a
# literal -- a positional placeholder would be a call that does not compile.
"payload_starts" => 'payload_starts("GET /health ")',
"tcp_reply_data" => 'tcp_reply_data(seq, ack, "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nOK\n")',
      # A capability is passed as its bit number through a constant; the CAP:: path and
      # the flat CAP_ name are the same value. A namespace key is a symbol literal,
      # which selects a kernel struct member at compile time.
      "has_cap"             => "has_cap(CAP::SYS_ADMIN)",
      "has_cap_permitted"   => "has_cap_permitted(CAP::NET_ADMIN)",
      "has_cap_inheritable" => "has_cap_inheritable(CAP::SYS_PTRACE)",
      "ns_id"               => "ns_id(:mnt)",
      "in_host_ns"          => "in_host_ns(:mnt)",
      "file_type"           => "file_type(file)",
    }.freeze

    # **The unit and byte order of a return value.** This does for builtins what the
    # per-field notes in record_schema.h do for packed records. A value's meaning cannot
    # be read off its spelling -- a socket's smoothed round-trip time, for instance, is
    # in eighths of a microsecond, so the raw number and the meaningful number differ --
    # so there has to be a place where it is written down.
    #
    # The bar for appearing here is that **getting it wrong passes quietly**. Mistake the
    # unit or the byte order and neither the verifier nor the compiler says anything, and
    # the number that comes out still looks plausible. Values whose meaning is readable
    # from the name -- a pid, a counter -- are left out.
    VALUE_SEMANTICS = {
      "sock_sport"      => "source port, host order (the underlying skc_num is already host order, so nothing is converted)",
      "sock_dport"      => "destination port, host order (the underlying skc_dport is a __be16, so ntohs is applied)",
      "sock_saddr"      => "source IPv4, host order (converted). Only meaningful when sock_family == AF_INET",
      "sock_daddr"      => "destination IPv4, host order (converted). Only meaningful when sock_family == AF_INET",
      "sock_family"     => "AF_INET (2) or AF_INET6 (10)",
      "sock_state"      => "TCP_STATE_* (ESTABLISHED = 1, ...)",
      "sock_protocol"   => "IPPROTO_* (TCP = 6, UDP = 17)",
      "sock_saddr6_hi"  => "upper 64 bits of the source IPv6 address, hi/lo split, host order. Only meaningful when AF_INET6",
      "sock_saddr6_lo"  => "lower 64 bits of the source IPv6 address, hi/lo split, host order. Only meaningful when AF_INET6",
      "sock_daddr6_hi"  => "upper 64 bits of the destination IPv6 address, hi/lo split, host order. Only meaningful when AF_INET6",
      "sock_daddr6_lo"  => "lower 64 bits of the destination IPv6 address, hi/lo split, host order. Only meaningful when AF_INET6",
      # The value itself has the same shape as sock_dport's (a port in host order),
      # so what is written here is not the unit but WHICH QUESTION is being answered.
      # Confusing the two type-checks, returns the same number for every sender that
      # connects, and shows up only as silence for the ones that do not.
      "udp_dport"       => "the destination port **of this send**, host order (msg_name when there is one, otherwise the connected peer). sock_dport is the socket's peer, and it is 0 when the socket was never connected",
      "udp_daddr"       => "the destination IPv4 **of this send**, host order (same rule). 0 when the destination is IPv6",
      # All three below are textbook cases of "getting it wrong passes quietly": if the
      # shape of the value is not known, the comparison itself is written wrongly, and a
      # small plausible number comes back.
      "cap_effective"   => "a **64-bit bit set** of capabilities, not a number. CAP_X is a bit index, so `& CAP_X` is wrong -- to decide, use has_cap(CAP::X). This value is for reporting",
      "ns_id"           => "the **inode number** of a namespace, the same N as in proc's ns:[N]. It is comparable only within one kernel and means nothing on its own; to ask whether this is the host, use in_host_ns",
      "file_type"       => "a file type **already masked with S_IFMT**, to be compared with == against FileType::REG and friends. It is not a raw i_mode, so it carries no permission bits",
    }.freeze

    # The unit and byte order of a return value, or nil. Printed by describe and by
    # the capabilities report.
    def self.value_semantics_for(name)
      VALUE_SEMANTICS[name]
    end

    # Cross-links between related builtins. Each group is {name, members, note}, and
    # the per-builtin links are derived from here so there is one authority. A note
    # states the fact needed to choose -- granularity, pairing, family -- and not when
    # to use them. Multi-hook required sets live in their own table and are not
    # duplicated here; the L7 round trip is the exception, since it reads as a pair,
    # and it cross-references that table.
    BUILTIN_GROUPS = [
      { name: "process_thread_identity",
        members: %w[pid tgid tid],
        note: "pid() and tgid() are the same value and carry process granularity, taken from the upper half of the pid/tgid pair; tid() carries thread granularity, from the lower half. Choose by whether the grouping key should be a process or a thread." }.freeze,
      { name: "latency_tid_pair",
        members: %w[latency_start latency_end],
        note: "A begin/end pair keyed by thread. The first records the entry time in a kprobe; the second returns the elapsed nanoseconds and clears the entry, in a kretprobe. Use them together." }.freeze,
      { name: "latency_keyed_pair",
        members: %w[lat_start lat_end],
        note: "The same begin/end pair, under a key of your choosing." }.freeze,
      { name: "histogram",
        members: %w[hist_observe hist_observe_by hist_observe_linear],
        note: "Three forms of log2 histogram: hist_observe takes no key, hist_observe_by is keyed, and hist_observe_linear takes a slot the caller has already chosen." }.freeze,
      { name: "str_emit",
        members: %w[emit_comm emit_path emit_parent_path emit_argv spnl_emit_str emit_kfield_str],
        note: "Emitting into the string ringbuf: comm, a full path (gated), the parent executable path (gated), argv, a string behind any user pointer, or a string field of a kernel struct (not gated)." }.freeze,
      { name: "kernel_field_read",
        members: %w[kfield kptr emit_kfield_str kfield_str_eq],
        note: "Reading kernel struct fields through CO-RE, which is safe even on an untrusted pointer: kfield returns a scalar by value, kptr yields a handle for the .field dot accessors, emit_kfield_str sends a string into the string ringbuf, and kfield_str_eq compares a string with a literal as an expression. All four spell hops the same way -- a comma is a pointer hop, a dot an embedded member. To read a struct sock *, prefer the named sock_* accessors over raw kfield: they have the byte order already applied." }.freeze,
      { name: "datagram_destination",
        members: %w[udp_dport udp_daddr sock_dport sock_daddr],
        note: "Two ways of asking where something is being sent. udp_dport(sk, msg) / udp_daddr(sk, msg) answer for **this datagram** and stay correct for an unconnected socket -- one that passes the address on every send. sock_dport(sk) / sock_daddr(sk) answer for **the socket's connected peer**, and are 0 when there is none. Both return the same number for any sender that connects, so mixing them up never produces a wrong value: it produces silence, in which unconnected senders alone go unreported. On a UDP send hook, use the udp_* pair." }.freeze,
      { name: "sock_accessor",
        members: %w[sock_sport sock_dport sock_saddr sock_daddr sock_family sock_state sock_protocol
                    sock_saddr6_hi sock_saddr6_lo sock_daddr6_hi sock_daddr6_lo],
        note: "Reading a `struct sock *` by name from any context, such as a kprobe. Underneath it is the same CO-RE read as kfield, but **every return value is in host order**: byte order varies field by field inside struct sock_common, every raw value still looks like a plausible port or address, and so a caller applying one uniform rule is guaranteed to get one of them silently wrong. Branch on sock_family before reading any address accessor. These are not the tcp_sock_* accessors, which read a trusted socket inside a congestion-control context by direct dereference; these read an untrusted one through CO-RE." }.freeze,
      { name: "file_selector",
        members: %w[path_eq path_starts_with path_contains file_type],
        note: "Predicates over the `struct file *` a hook passes in; being expressions, they can drive an if. The path_* three compare the full path against a literal by equality, prefix or substring, and are backed by bpf_d_path, so the **kernel gates them** to a limited set of hooks. file_type gives the kind (reg, dir, lnk, sock, blk, chr, fifo) and is **not gated**: it reads i_mode through CO-RE rather than calling bpf_d_path, so it works wherever kfield does. A kprobe cannot get the full path, but it can get the type. For the file name alone, use kfield_str_eq." }.freeze,
      { name: "task_capability",
        members: %w[has_cap has_cap_permitted has_cap_inheritable cap_effective],
        note: "The current task's capabilities. The has_cap* predicates are **bit tests** taking CAP::X; cap_effective is the 64-bit bit set **itself**, for reporting. Effective is what may be used now, permitted the ceiling it may be raised to, inheritable what survives an exec. **`cap_effective & CAP_X` is always wrong**: CAP_X is a bit index -- SYS_ADMIN is 21 -- not a mask, so it returns the same answer whether or not the task holds it. Process-context hooks only." }.freeze,
      { name: "task_namespace",
        members: %w[ns_id in_host_ns],
        note: "The current task's namespaces. ns_id(:mnt) is an inode number, useful for correlation and meaningless on its own; in_host_ns(:mnt) says whether this is the initial namespace, as 0 or 1. The keys are :mnt :net :uts :ipc :cgroup :time :user :pid. :pid follows thread_pid, because nsproxy->pid_ns_for_children is the namespace a *child* would enter and can differ. The initial namespace's inode is read from an untyped ksym; reading /proc/1/ns instead does not work inside a container, where it names the container's own init. If all you want is container attribution, cgroup_id leads more directly to Kubernetes. Process-context hooks only." }.freeze,
      { name: "scalar_emit",
        members: %w[spnl_emit spnl_emit_pair spnl_emit3 spnl_emit4],
        note: "Scalar ringbuf emits: one, two, three or four values per event, behind the common 16-byte header." }.freeze,
      { name: "stack_trace",
        members: %w[stack_id user_stack_id],
        note: "Ids into the stack-trace map: stack_id for the kernel stack, user_stack_id for the userspace one." }.freeze,
      { name: "off_cpu_profile",
        members: %w[off_cpu_start off_cpu_observe],
        note: "An off-CPU profiling pair: the first stashes the time and stack when the scheduler switches away, the second bins the elapsed time into a keyed histogram on return. Distinct from the multi-hook offcpu_* span builtins." }.freeze,
      { name: "task_storage",
        members: %w[task_load task_store task_incr task_swap],
        note: "Per-task storage: load, store, increment as a read-modify-write, or swap. It is freed when the task exits, and needs no explicit key." }.freeze,
      { name: "l7_roundtrip",
        members: %w[req_start emit_l7],
        note: "The L7 round-trip pair: the first records the start on send, the second emits the round-trip span once the data has reached the application. See required_sets.l7_latency." }.freeze,
      { name: "pkt_fields",
members: (PKT_FIELD_BUILTINS + %w[pkt_dynptr_byte_at]),
note: "Packet field accessors for XDP and TC: no arguments, host order. The pkt.* chain accessors, such as pkt.l4.proto, yield the same values. " \
      "**pkt_dynptr_byte_at(off) is the odd one out**: it takes one argument, its offset is a runtime value, it is XDP-only, and it returns a byte (0-255) or -1. " \
      "Read a fixed place in a header with the fixed-offset readers; read an arbitrary place with the dynptr." }.freeze,
      { name: "tcp_sock_accessors",
        members: (TCP_SOCK_READER_BUILTINS + TCP_SOCK_WRITER_BUILTINS + TCP_SOCK_ADDER_BUILTINS),
        note: "tcp_sock fields inside a congestion-control context: a reader takes the socket, a writer takes a socket and a value, an adder a socket and a delta. The dot accessors, such as sk.snd_cwnd, yield the same values." }.freeze,
      { name: "arena",
        members: %w[arena_set arena_get arena_hash_set arena_hash_get arena_hash_del arena_list_push arena_list_sum],
        note: "Data structures in the shared arena: a flat array, a hash table, and a linked list. The arena is shared with userspace through mmap." }.freeze,
      { name: "skb_rewrite",
        members: %w[skb_load_byte skb_load_u16 skb_load_u32 skb_store_byte skb_store_u16 skb_store_u32 l3_csum_replace l3_csum_replace_ip l4_csum_replace l4_csum_replace_ip l4_offset],
        note: "Reading and writing packets in TC, and repairing the checksums: byte, 16-bit and 32-bit loads and stores, the L3 and L4 checksum patches, and the offset where L4 begins (accounting for IP options). These are the pieces NAT is built from." }.freeze,
    ].freeze

    # The threshold at which `on :kprobe, %w[...]` stops expanding into N programs and
    # becomes a single SEC("kprobe.multi") link.
    #
    # THE NUMBER LIVES IN TWO LANGUAGES AND THAT IS A HAZARD, so it is gated: the unit
    # test reads `#define CC_MULTI_AUTO_THRESHOLD` out of the C generator and asserts it
    # equals this. It was measured, not chosen: 16 is the smallest N at which the multi
    # lowering won on load-and-attach time in every repetition. Below it, expansion is
    # both faster AND has the lower kernel floor, so `auto` never raises a probe's floor
    # for a mechanism that is not yet paying for itself.
    ATTACH_MULTI_THRESHOLD = 16

    # The conventions of each attach kind, one for one with the generator's own attach
    # patterns; a test enforces that the two sets match. args_convention says which
    # ABI the declared parameters are extracted from in the attach context.
    ATTACH_KINDS = [
      { kind: :kprobe,        method_prefix: "kprobe__<func>",           sec: "kprobe/<func>",         ctx_type: "struct pt_regs *", args_convention: "PT_REGS_PARM<N>(ctx) -- the kernel function's arguments, named through BTF", context_note: "the entry of a kernel function" },
      { kind: :kprobe_multi,  method_prefix: "on :kprobe, %w[<func> <func> ...] (reactor form only)", sec: "kprobe.multi", ctx_type: "struct pt_regs *", args_convention: "PT_REGS_PARM<N>(ctx), as for kprobe. In addition, attached_symbol_eq(\"<func>\") and attached_index answer \"which symbol am I on\" -- in **one spelling**, which lowers to a literal when the definition was expanded and to bpf_get_attach_cookie when it rides kprobe.multi", context_note: "One definition, several attachments. **There are two lowerings and the generator picks one**: below ATTACH_MULTI_THRESHOLD symbols it expands into N separate SEC(\"kprobe/<func>\") programs, at or above it emits one SEC(\"kprobe.multi\") program with a per-symbol cookie and lets the glue attach the symbol array. `via: :expand` and `via: :multi` name one explicitly -- a deployment choice rather than a code one, since kprobe.multi raises the kernel floor to 5.18. Note there is no flat `def` form: a method name cannot hold a list, and `%w[].each { define_method }` does not work because partitioning walks the AST" },
      { kind: :kretprobe,     method_prefix: "kretprobe__<func>",        sec: "kretprobe/<func>",      ctx_type: "struct pt_regs *", args_convention: "a single parameter, the return value (PT_REGS_RC)", context_note: "the return of a kernel function" },
      { kind: :uprobe,        method_prefix: "uprobe__<func>",           sec: "uprobe",                ctx_type: "struct pt_regs *", args_convention: "PT_REGS_PARM<N>(ctx); the target binary and pid come from the environment (SPNL_UPROBE_*)", context_note: "the entry of a userspace function" },
      { kind: :uretprobe,     method_prefix: "uretprobe__<func>",        sec: "uretprobe",             ctx_type: "struct pt_regs *", args_convention: "a return parameter; the target comes from the environment (SPNL_UPROBE_*)", context_note: "the return of a userspace function" },
      { kind: :usdt,          method_prefix: "usdt__<provider>__<probe>", sec: "usdt",                 ctx_type: "struct pt_regs *", args_convention: "bpf_usdt_arg(ctx, i, &v); the target comes from the environment (SPNL_USDT_*)", context_note: "A USDT static probe. Measured: including the USDT header brings in **three more maps** (a spec table, an ip-to-spec-id table, and the kconfig section), none of which appear as declarations in the generated C" },
      { kind: :tracepoint,    method_prefix: "tracepoint__<cat>__<event>", sec: "tracepoint/<cat>/<event>", ctx_type: "void *", args_convention: "for the syscall tracepoints, positional arguments in ctx->args[i]; for a named-field tracepoint, the parameter name selects the struct field", context_note: "kernel tracepoint" },
      { kind: :fentry,        method_prefix: "fentry__<func>",           sec: "fentry/<func>",         ctx_type: "__u64 *", args_convention: "ctx[i] holds the function's arguments, named through BTF", context_note: "BPF trampoline entry (~50ns)" },
      { kind: :fexit,         method_prefix: "fexit__<func>",            sec: "fexit/<func>",          ctx_type: "__u64 *", args_convention: "ctx[i] holds the function's arguments; the last parameter is the return value", context_note: "BPF trampoline exit" },
      { kind: :lsm,           method_prefix: "lsm__<hook>",              sec: "lsm/<hook>",            ctx_type: "__u64 *", args_convention: "ctx[i] holds the hook's arguments; the last parameter is the verdict so far", context_note: "An LSM security hook. To deny, return a negative errno; to allow, return the last parameter, which carries the prior verdict, rather than a literal 0. Note that an LSM hook only fires when the kernel was booted with BPF LSM enabled (lsm=...,bpf on the command line) -- otherwise it attaches and is a silent no-op, which is why fmod_ret on the matching security_* function is the portable way to enforce." },
      { kind: :fmod_ret,      method_prefix: "fmod_ret__<func>",         sec: "fmod_ret/<func>",       ctx_type: "__u64 *", args_convention: "ctx[i] holds the function's arguments and the last parameter is the return value, so a handler takes one more argument than the hook does. security_file_open takes one argument, hence `def fmod_ret__security_file_open(file, ret)`", context_note: "BPF_MODIFY_RETURN: replaces the target function's return value. Return a negative errno to deny, or return the last parameter unchanged to allow. Attaching to a security_* function gives a portable denial that does not depend on the kernel's boot-time LSM configuration -- an LSM hook that was never enabled is a silent no-op -- which is why this is the default way to enforce" },
      { kind: :sock_ops,      method_prefix: "sock_ops__<name>",         sec: "sockops",               ctx_type: "struct bpf_sock_ops *", args_convention: "no declared parameters; read the context with sock_ops_op and sock_ops_state", context_note: "Observing TCP state, attached to a cgroup ($SPNL_CGROUP_PATH) by the generated glue. The return value is not a verdict; the wrapper returns 0" },
      { kind: :cgroup_connect4, method_prefix: "cgroup__connect4__<name>", sec: "cgroup/connect4",     ctx_type: "struct bpf_sock_addr *", args_convention: "no declared parameters; read the context with sock_addr_ip4 and sock_addr_port", context_note: "controls outbound connect; return 1 to allow, 0 to deny" },
      { kind: :cgroup_bind4,  method_prefix: "cgroup__bind4__<name>",    sec: "cgroup/bind4",          ctx_type: "struct bpf_sock_addr *", args_convention: "no declared parameters; read the context with the sock_addr_* builtins", context_note: "controls bind; return 1 to allow, 0 to deny" },
      { kind: :xdp_tail,      method_prefix: "xdp_tail__<name>",         sec: "xdp",                   ctx_type: "struct xdp_md *", args_convention: "no declared parameters (a tail call carries none); read the packet with the pkt_* builtins", context_note: "a tail-call TARGET. The emitted program is an ordinary SEC(\"xdp\") one; what differs is **only how the loader treats it** -- it is not attached to an interface, its fd is written into `spnl_prog_array` at the **slot matching its declaration order** (0, 1, ...) by `_spnl_prog_array_populate`. The caller uses `tail_call_to(slot)`, from a plain `def xdp__<name>` or from another `def xdp_tail__<name>` (the kernel allows 33 levels). **The motive is that the one-million instruction budget is per program**, which makes this the only way to split an XDP program. WARNING: **failure is silent** -- a jump into an empty slot just falls through, so if the slot numbers and the declaration order drift apart the result is not \"it jumped to the wrong program\" but \"it did not jump and execution continued\". An integer literal slot is range-checked at compile time; a computed one is not. `spinel-ebpf describe` prints the slot-to-method table. WARNING: a unit that declares targets nobody jumps to is **legal** (the map is emitted and the loader populates it), so that \"I have not written the dispatcher yet\" is not refused. WARNING: **the kernel floor is not \"4.2\"** -- bpf_tail_call and PROG_ARRAY themselves are 4.2, but the generated dispatcher makes its tail call from inside `<name>_inner`, a BPF-to-BPF **subprogram** (confirmed in the kernel's own translated dump). A tail call from a subprogram is a later, separate capability that each architecture's JIT has to support, and **its floor was not measured**, so the portability contract reports 4.2 as the feature's floor and declares the shape's floor unknown on its own line (it does work on 7.1.5/aarch64). The effective floor is at least SEC(\"xdp\")'s **5.9**" },
      { kind: :xdp_tcp_slice, method_prefix: "xdp__tcp_slice__<name>",  sec: "xdp", ctx_type: "struct xdp_md *", args_convention: "**no declared parameters, and the body is not used either** -- the method body is a marker the code generator replaces wholesale", body: :discarded, emits: "spnl_tcp_slice_main", context_note: "**an HTTP reply that never touches the kernel TCP stack**: no listening socket is created on port 8080, and the SYN, the handshake ACK, the GET and the FIN are all completed in XDP. `bpf_tcp_raw_gen_syncookie_ipv4` establishes the three-way handshake statelessly, a 4-tuple-keyed `bpf_conntab` (LRU_HASH) holds ESTABLISHED / RESP_SENT / CLOSED, and `GET /health ` is answered with `HTTP/1.0 200 OK` over XDP_TX. Retransmission handling is included (a repeated GET in RESP_SENT resends the response; a repeated FIN in CLOSED resends the FIN-ACK), as is a per-state time-to-live `bpf_timer`. WARNING: **the body is discarded** -- the `XDP_PASS` in `def xdp__tcp_slice__health; XDP_PASS; end` appears nowhere in the generated C. Writing logic there **does nothing and produces no diagnostic** (since a marker's definition does not depend on its spelling, refusing non-markers was judged to produce more false positives). WARNING: **port 8080 and `/health` are fixed**. WARNING: **one slice per unit** -- the generated symbol names are fixed, so a second one dies at compile time. WARNING: there is no `on :xdp_tcp_slice` reactor form (there would be no body to synthesise). WARNING: **its `bpf_timer` is a different mechanism from `on :timer`**: that one arms a single timer in an array slot once at load time; this one arms a **per-connection timer embedded in the LRU_HASH value** from BPF, and the callback deletes its own entry. All they share is `struct bpf_timer` and the 5.15 floor" },
      { kind: :timer,         method_prefix: "on :timer, every: N.<unit> (reactor form only; the synthesised name is spnl_timer__main)", sec: "syscall", ctx_type: "__u64 * (the arming program only; the callback takes (void *map, int *key, struct spnl_timer_value *v))", args_convention: "no declared parameters. **The interval is a compile-time constant** -- an integer literal with a unit, such as `every: 5.seconds`, `500.ms` or `1000.ns`; neither an expression nor a `param` will do, because the value is folded into bpf_timer_start", context_note: "three things are emitted: `spnl_timer_map` (an ARRAY with one slot), a SEC-less callback `spnl_timer_cb_main` (the handler body plus a re-arm of itself), and `SEC(\"syscall\") spnl_timer_arm_main`, which the glue fires exactly once at load time through `bpf_prog_test_run`. WARNING: **one timer per unit** (the callback name is fixed, so a second one dies at compile time). WARNING: **the return value is ignored** -- the verifier requires a literal `return 0` in the callback. WARNING: it is **not process context**, so reading the current task (`has_cap`, `pid` and the like) is refused and it cannot coexist with `filter_by`: both would end up pointing at whichever task happens to be on the CPU. Kernel floor **5.15** (bpf_timer)" },
      { kind: :user_ringbuf,  method_prefix: "user_ringbuf__<name>(value) / on :user_cmd do |cmd| ... end", sec: nil,
        emits: "static long spnl_user_ringbuf_cb_<name>(struct bpf_dynptr *dynptr, void *_uctx)",
        ctx_type: "struct bpf_dynptr * (the record) + void * (unused)",
        args_convention: "**exactly one** declared parameter -- the value the host pushed. The first 8 bytes of the record are read with `bpf_dynptr_read`",
        context_note: "the host-to-kernel command channel, and **the only attach kind that emits no program at all**: what comes out is a `static` callback with no SEC, no context and no userspace-visible name, which `bpf_user_ringbuf_drain` calls once per pending record. It is therefore **not attached to anything** -- it runs only when some handler in the same unit calls `user_ringbuf_drain`, and where that call sits is what sets command latency, so it is never synthesised. WARNING: a callback with no drain, a drain with no callback, and two callbacks in one unit all **die at compile time**. WARNING: **a record is a fixed 8 bytes**; send with the glue's `sp_bpf_user_cmd_push(value)`, because a hand-rolled pusher sending fewer makes the callback fire and the count rise while only the value stays 0. Kernel floor **6.1** (USER_RINGBUF), which is higher than the 5.2 base -- `param` travels further when nothing needs to change while the probe runs" },
      { kind: :iter_task,     method_prefix: "iter__task__<name>",       sec: "iter/task",             ctx_type: "struct bpf_iter__task *", args_convention: "no declared parameters; iter_task() yields the task pointer", context_note: "enumerating tasks, driven from userspace by the generated glue" },
      { kind: :raw_tp,        method_prefix: "raw_tp__<event>",          sec: "raw_tp/<event>",        ctx_type: "struct bpf_raw_tracepoint_args *", args_convention: "ctx->args[i]", context_note: "a raw tracepoint, with lower overhead" },
      { kind: :socket_filter, method_prefix: "socket_filter__<name>",    sec: "socket",                ctx_type: "struct __sk_buff *", args_convention: "no declared parameters", context_note: "the classic SO_ATTACH_BPF filter; the return value is how many bytes to keep" },
      { kind: :flow_dissector, method_prefix: "flow_dissector__<name>",  sec: "flow_dissector",        ctx_type: "struct __sk_buff *", args_convention: "no declared parameters", context_note: "returns BPF_OK or BPF_DROP" },
      { kind: :sk_lookup,     method_prefix: "sk_lookup__<name>",        sec: "sk_lookup",             ctx_type: "struct bpf_sk_lookup *", args_convention: "no declared parameters", context_note: "selects a listener. The section name takes no sub-name. Returns SK_PASS or SK_DROP" },
      { kind: :tcp_cc,        method_prefix: "class <N> < BPF::TcpCC (def <member>)", sec: "struct_ops/<member>",   ctx_type: nil, args_convention: "A struct_ops implementation is written as a class -- `class N < BPF::TcpCC` with `def init(sk)`, `def cong_avoid(sk, ack, acked)` and so on -- which is the idiomatic Ruby form. The flat `def tcp_cc__<member>` also registers. Member arguments are declared positionally.", context_note: "a tcp_congestion_ops member. The class form is preferred; the flat form also works" },
      { kind: :sched_ext,     method_prefix: "class <N> < BPF::SchedExt (def <member>)", sec: "struct_ops/<member>", ctx_type: nil, args_convention: "A struct_ops implementation is written as a class -- `class N < BPF::SchedExt` with a `def` per member. The flat `def sched_ext__<member>` also registers. Member arguments, such as the task, are declared positionally.", context_note: "a sched_ext_ops member -- a CPU scheduler. The class form is preferred; the flat form also works" },
      { kind: :qdisc,         method_prefix: "class <N> < BPF::Qdisc (def <member>)", sec: "struct_ops/<member>",   ctx_type: nil, args_convention: "A struct_ops implementation is written as a class -- `class N < BPF::Qdisc` with a `def` per member. The flat `def qdisc__<member>` also registers. The required members and their signatures are init(sch, opt, extack), enqueue(skb, sch, to_free), dequeue(sch), reset(sch) and destroy(sch). Note that enqueue MUST release the skb reference: call qdisc_skb_drop(skb, to_free) to drop it, or queue_push(skb, to_free) to forward it. Without that the verifier rejects the program for leaking a reference.", context_note: "a Qdisc_ops member, attached through tc as spnl_qdisc. The class form is preferred; the flat form also works" },
      { kind: :xdp,           method_prefix: "xdp__<name>",              sec: "xdp",                   ctx_type: "struct xdp_md *", args_convention: "no declared parameters; use the pkt_* builtins or the pkt.* accessors", context_note: "returns XDP_PASS, XDP_DROP, XDP_TX or XDP_REDIRECT; the interface comes from SPNL_XDP_IFACE" },
      { kind: :tc_ingress,    method_prefix: "tc__ingress__<name>",      sec: "tcx/ingress",           ctx_type: "struct __sk_buff *", args_convention: "no declared parameters; use the pkt_* and skb_* builtins", context_note: "returns one of the TC_ACT_* values; the interface comes from SPNL_TCX_IFACE" },
      { kind: :tc_egress,     method_prefix: "tc__egress__<name>",       sec: "tcx/egress",            ctx_type: "struct __sk_buff *", args_convention: "no declared parameters; use the pkt_* and skb_* builtins", context_note: "returns one of the TC_ACT_* values; the interface comes from SPNL_TCX_IFACE" },
      { kind: :sk_reuseport,  method_prefix: "sk_reuseport__<name>",     sec: "sk_reuseport",          ctx_type: "struct sk_reuseport_md *", args_convention: "no declared parameters", context_note: "decides **which listening socket** a SYN arriving at an SO_REUSEPORT group is handed to. Returning `SK_PASS` accepts the decision (which, if `worker_select` was never called, is the **kernel's own 5-tuple spread**); `SK_DROP` drops the SYN. With `reuseport_hash` and `worker_select` implemented, a BPF program can name the worker itself. Attaching is setsockopt(SO_ATTACH_REUSEPORT_EBPF): the probe's own userspace half calls the glue's `sp_bpf_reuseport_attach(listen_fd, \"sk_reuseport__<name>\")`. It is not auto-attached, because the listening socket is the probe's to create and the loader knows nothing about it. WARNING: **a failed selection is silent** (see worker_select)" },
      { kind: :sk_msg,        method_prefix: "sk_msg__<name>",           sec: "sk_msg",                ctx_type: "struct sk_msg_md *", args_convention: "no declared parameters", context_note: "A sockmap program, attached with BPF_SK_MSG_VERDICT. Measured: **spinel-ebpf does not create the sockmap itself** -- neither SOCKMAP nor SOCKHASH appears anywhere in the generator -- so the map it attaches to must be provided by userspace" },
      { kind: :sk_skb_verdict, method_prefix: "sk_skb__verdict__<name>", sec: "sk_skb/stream_verdict", ctx_type: "struct __sk_buff *", args_convention: "no declared parameters", context_note: "A sockmap stream verdict. As above, the sockmap itself must be provided by userspace" },
      { kind: :sk_skb_parser, method_prefix: "sk_skb__parser__<name>",   sec: "sk_skb/stream_parser",  ctx_type: "struct __sk_buff *", args_convention: "no declared parameters", context_note: "A sockmap stream parser. As above, the sockmap itself must be provided by userspace" },
      { kind: :perf_event,    method_prefix: "perf_event__<name> / on :perf_event, hz: N", sec: "perf_event", ctx_type: "struct bpf_perf_event_data *", args_convention: "no declared parameters; pair it with stack_id()", context_note: "per-CPU sampling profiler" },
    ].freeze


    # =====================================================================
    # The map vocabulary. **Silence is an affordance defect too.**
    #
    # The audits of builtins, attach kinds and surface sugar were audits of lies:
    # things advertised that did not work. Maps are the opposite case. The
    # implementation was sound, and the capability registry **said not one word about
    # them** -- it held no map-related constant at all. Since the whole point of the
    # registry is that an agent reads it to decide what it may write, saying nothing
    # about maps leaves **capacity, key and value shapes, per-CPU semantics, and which
    # surface creates which map** unknowable by inspection. And capacity is not a
    # property one may safely not know: **a ring buffer that overflows drops silently**.
    #
    # **The unit of the audit is not the map type.** Nobody writes
    # `BPF_MAP_TYPE_HASH`; they write `@x += 1` or `hist_observe(v)`. So one entry is
    # the correspondence **"which surface creates which map, in what shape"**, and the
    # type is merely one of its attributes. (An exhaustive audit is always relative to
    # how the vocabulary was cut.)
    #
    # The contents were **derived mechanically from the output**, because a hand-written
    # table is where drift starts: for each surface, a minimal probe and a twin with that
    # surface removed were run through the production generator, and every declaration
    # that appeared in the difference was copied across with its attributes. Only the
    # prose -- role, when_full, note -- is a human addition; everything else is measured.
    #
    #   map          the symbol that is generated. <unit> is the unit name, and
    #                <ivar>, <class> and <N> are substituted likewise
    #   type         the type name with BPF_MAP_TYPE_ dropped
    #   declared_as  :maps          -- declared under `SEC(".maps")`, where the gate can
    #                                  check the attributes themselves
    #                :struct_ops    -- `SEC(".struct_ops[.link]")`
    #                :rodata        -- a `volatile const` global; libbpf creates the map
    #                :data_section  -- the `private(A)` macro, expanding to `SEC(".data.A")`
    #                :libbpf_header -- brought in by an included libbpf header
    #                Anything other than :maps is a **weaker tier**: the gate can only
    #                see a witness, so a test requires `measured` -- what was confirmed
    #                on the kernel side -- on every such entry
    #   created_by   every surface that creates this map (measured)
    #   probe        one representative from created_by, which the gate compiles
    #   when_full    **what happens when it overflows.** This is the point of the whole
    #                table: "drops silently", "evicts the oldest silently" and "tells you
    #                in the return value" are three different decisions for a caller
    # =====================================================================
    MAPS = [
      { id: :arena,
        map: "<unit>_arena",
        type: "ARENA",
        declared_as: :maps,
        max_entries: "1",
        flags: "BPF_F_MMAPABLE",
        created_by: %w[arena_get arena_hash_del arena_hash_get arena_hash_set arena_list_push arena_list_sum arena_set],
        probe: "arena_get",
        probe_kind: :builtin,
        role: "the bpf_arena shared memory, mapped into userspace",
        when_full: "**One page is 512 __u64 slots**. The index is masked with `& 511`, so an out-of-range index **silently wraps** and corrupts a different slot",
        note: "map_extra, the user mmap base, differs by architecture, so the gate does not compare it", }.freeze,
      { id: :hist,
        map: "bpf_hist",
        type: "ARRAY",
        declared_as: :maps,
        max_entries: "64",
        key: "__u32",
        value: "__u64",
        created_by: %w[hist_observe hist_observe_by off_cpu_observe off_cpu_start],
        probe: "hist_observe",
        probe_kind: :builtin,
        role: "a log2 histogram of 64 buckets",
        when_full: "An ARRAY cannot overflow. The log2 slot is clamped to 0..63, so very large values pile up in the top bucket", }.freeze,
      { id: :hist_linear,
        map: "bpf_hist_lin",
        type: "ARRAY",
        declared_as: :maps,
        max_entries: "256",
        key: "__u32",
        value: "__u64",
        created_by: %w[hist_observe_linear],
        probe: "hist_observe_linear",
        probe_kind: :builtin,
        role: "a linear histogram of 256 slots; the caller does the bucketing",
        when_full: "An ARRAY cannot overflow. A slot of 256 or more is clamped to 255", }.freeze,
      { id: :map_in_map_inner,
        map: "bpf_mim_inner<N>",
        type: "ARRAY",
        count: 4,
        declared_as: :maps,
        max_entries: "64",
        key: "__u32",
        value: "__s64",
        created_by: %w[mim_get mim_inc],
        probe: "mim_get",
        probe_kind: :builtin,
        role: "the inner maps of a map-in-map (**four of them**)",
        when_full: "An ARRAY cannot overflow", }.freeze,
      { id: :map_in_map_outer,
        map: "bpf_mim_outer",
        type: "ARRAY_OF_MAPS",
        declared_as: :maps,
        max_entries: "4",
        key: "__u32",
        values_of: "struct mim_inner_t",
        created_by: %w[mim_get mim_inc],
        probe: "mim_get",
        probe_kind: :builtin,
        role: "the outer map of a map-in-map; libbpf populates the inner maps at load time",
        when_full: "Fixed at four entries", }.freeze,
      { id: :cpumap,
        map: "spnl_cpumap",
        type: "CPUMAP",
        declared_as: :maps,
        max_entries: "64",
        key_size: "sizeof(__u32)",
        value_size: "sizeof(struct bpf_cpumap_val)",
        created_by: %w[cpumap_redirect],
        probe: "cpumap_redirect",
        probe_kind: :builtin,
        role: "the per-CPU fan-out target for XDP; userspace populates it",
        when_full: "A cpumap_redirect to an unregistered index returns **XDP_ABORTED**, because the generator passes flags=0", }.freeze,
      { id: :devmap,
        map: "bpf_devmap",
        type: "DEVMAP",
        declared_as: :maps,
        max_entries: "64",
        key_size: "sizeof(__u32)",
        value_size: "sizeof(__u32)",
        created_by: %w[dev_redirect],
        probe: "dev_redirect",
        probe_kind: :builtin,
        role: "the netdev targets of an XDP redirect; userspace populates it",
        when_full: "The kernel side only reads the index. A dev_redirect to an unregistered index returns **XDP_ABORTED**, because the generator passes flags=0", }.freeze,
      { id: :dns_recv_stash,
        map: "<unit>_dns_recv_stash",
        type: "HASH",
        declared_as: :maps,
        max_entries: "4096",
        key: "__u32",
        value: "struct <unit>_dns_recv_stash_st",
        created_by: %w[dns_emit dns_req_start dns_resp_stash],
        probe: "dns_emit",
        probe_kind: :builtin,
        role: "the DNS response buffer, stashed by thread id",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :go_recv_stash,
        map: "<unit>_go_recv_stash",
        type: "HASH",
        declared_as: :maps,
        max_entries: "4096",
        key: "__u64",
        value: "struct <unit>_http_stash_st",
        created_by: %w[go_tls_emit go_tls_resp_stash],
        probe: "go_tls_emit",
        probe_kind: :builtin,
        role: "the Go TLS receive stash, keyed by the goroutine's g pointer",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :http_pending,
        map: "<unit>_http_pending",
        type: "HASH",
        declared_as: :maps,
        max_entries: "65536",
        key: "__u64",
        value: "struct <unit>_http_pending_st",
        created_by: %w[go_tls_emit go_tls_req go_tls_resp_stash go_tls_write http_emit http_req_start http_resp_stash ssl_emit ssl_req_start ssl_resp_stash],
        probe: "go_tls_emit",
        probe_kind: :builtin,
        role: "HTTP request correlation state, keyed by socket",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :http_recv_stash,
        map: "<unit>_http_recv_stash",
        type: "HASH",
        declared_as: :maps,
        max_entries: "4096",
        key: "__u32",
        value: "struct <unit>_http_stash_st",
        created_by: %w[go_tls_emit go_tls_req go_tls_resp_stash go_tls_write http_emit http_req_start http_resp_stash ssl_emit ssl_req_start ssl_resp_stash],
        probe: "go_tls_emit",
        probe_kind: :builtin,
        role: "the receive buffer, stashed by thread id, because the response only exists after the copy",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :offcpu_stash,
        map: "<unit>_offcpu_stash",
        type: "HASH",
        declared_as: :maps,
        max_entries: "4096",
        key: "__u32",
        value: "struct <unit>_offcpu_stash_st",
        created_by: %w[offcpu_account offcpu_begin offcpu_emit offcpu_recv_stash],
        probe: "offcpu_account",
        probe_kind: :builtin,
        role: "the off-CPU receive buffer stash, keyed by thread id",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :offcpu_window,
        map: "<unit>_offcpu_win",
        type: "HASH",
        declared_as: :maps,
        max_entries: "4096",
        key: "__u32",
        value: "struct <unit>_offcpu_win",
        created_by: %w[offcpu_account offcpu_begin offcpu_emit offcpu_recv_stash],
        probe: "offcpu_account",
        probe_kind: :builtin,
        role: "the off-CPU window, keyed by thread id",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :redis_pending,
        map: "<unit>_redis_pending",
        type: "HASH",
        declared_as: :maps,
        max_entries: "65536",
        key: "__u64",
        value: "struct <unit>_redis_pending_st",
        created_by: %w[redis_emit redis_req_start redis_resp_stash],
        probe: "redis_emit",
        probe_kind: :builtin,
        role: "Redis request correlation state, keyed by socket",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :redis_recv_stash,
        map: "<unit>_redis_recv_stash",
        type: "HASH",
        declared_as: :maps,
        max_entries: "4096",
        key: "__u32",
        value: "struct <unit>_redis_stash_st",
        created_by: %w[redis_emit redis_req_start redis_resp_stash],
        probe: "redis_emit",
        probe_kind: :builtin,
        role: "the Redis receive buffer, stashed by thread id",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :req_state,
        map: "<unit>_req_start",
        type: "HASH",
        declared_as: :maps,
        max_entries: "65536",
        key: "__u64",
        value: "struct <unit>_req_state",
        created_by: %w[emit_l7 req_start],
        probe: "emit_l7",
        probe_kind: :builtin,
        role: "the start time for send-to-receive correlation, plus the multiplexing guard, keyed by socket",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :sock_owner,
        map: "<unit>_sock_owner",
        type: "HASH",
        declared_as: :maps,
        max_entries: "65536",
        key: "__u64",
        value: "struct <unit>_sock_owner_info",
        created_by: %w[sock_owner_set],
        probe: "sock_owner_set",
        probe_kind: :builtin,
        role: "socket to {pid, comm}, which recovers the process that softirq context loses",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :top_ivar,
        map: "<unit>_top_<ivar>",
        type: "HASH",
        declared_as: :maps,
        max_entries: "1",
        key: "__u32",
        value: "__s64",
        created_by: %w[top_ivar],
        probe: "top_ivar",
        probe_kind: :syntax,
        role: "one map per top-level instance variable",
        when_full: "A single fixed key, so it cannot overflow",
        note: "The map name follows the variable; <unit> is the unit name", }.freeze,
      { id: :leak_track,
        map: "bpf_allocs",
        type: "HASH",
        declared_as: :maps,
        max_entries: "262144",
        key: "__u64",
        value: "struct spnl_alloc_info",
        created_by: %w[leak_forget leak_record],
        probe: "leak_forget",
        probe_kind: :builtin,
        role: "tracking un-freed allocations: pointer to size and stack",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :blocklist,
        map: "bpf_blocklist",
        type: "HASH",
        declared_as: :maps,
        max_entries: "8192",
        key: "__u32",
        value: "__u8",
        created_by: %w[blocklist_match],
        probe: "blocklist_match",
        probe_kind: :builtin,
        role: "an exact-match address set; userspace adds and removes, the kernel only looks up",
        when_full: "The kernel side only looks up, so it cannot overflow there. When it is full, **the add from userspace fails**", }.freeze,
      { id: :depth,
        map: "bpf_depth",
        type: "HASH",
        declared_as: :maps,
        max_entries: "65536",
        key: "__u64",
        value: "__s64",
        created_by: %w[depth_dec depth_inc],
        probe: "depth_dec",
        probe_kind: :builtin,
        role: "recursion depth, for depth-collapsed instrumentation",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :hist_keyed,
        map: "bpf_hist_keyed",
        type: "HASH",
        declared_as: :maps,
        max_entries: "1024",
        key: "__u64",
        value: "struct spnl_hist_struct",
        created_by: %w[hist_observe_by off_cpu_observe off_cpu_start],
        probe: "hist_observe_by",
        probe_kind: :builtin,
        role: "a log2 histogram per key",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear. Here that means **the distribution of every new key past the 1024th is lost whole**", }.freeze,
      { id: :keyed_latency,
        map: "bpf_keyed_lat",
        type: "HASH",
        declared_as: :maps,
        max_entries: "65536",
        key: "__u64",
        value: "__u64",
        created_by: %w[lat_end lat_start],
        probe: "lat_end",
        probe_kind: :builtin,
        role: "the start time for lat_start and lat_end, under an arbitrary key",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :latency_starts,
        map: "bpf_lat_starts",
        type: "HASH",
        declared_as: :maps,
        max_entries: "10240",
        key: "__u32",
        value: "__u64",
        created_by: %w[latency_end latency_start],
        probe: "latency_end",
        probe_kind: :builtin,
        role: "the start time for latency_start and latency_end, keyed by thread id",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :lock_edges,
        map: "bpf_lock_edges",
        type: "HASH",
        declared_as: :maps,
        max_entries: "65536",
        key: "struct spnl_lock_edge",
        value: "__u64",
        created_by: %w[lock_edge],
        probe: "lock_edge",
        probe_kind: :builtin,
        role: "lock-ordering edges, for deadlock detection",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :off_cpu,
        map: "bpf_off_cpu",
        type: "HASH",
        declared_as: :maps,
        max_entries: "10240",
        key: "__u32",
        value: "struct spnl_off_cpu_entry",
        created_by: %w[off_cpu_observe off_cpu_start],
        probe: "off_cpu_observe",
        probe_kind: :builtin,
        role: "the off-CPU start time and stack id, keyed by pid",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear", }.freeze,
      { id: :path_counter,
        map: "bpf_path_counts",
        type: "HASH",
        declared_as: :maps,
        max_entries: "128",
        key: "__u32",
        value: "__s64",
        created_by: %w[path_counter_inc],
        probe: "path_counter_inc",
        probe_kind: :builtin,
        role: "key to count, for path_counter_inc",
        when_full: "When it is full the update returns -E2BIG, and the generator does not look at the return value at any of its update sites, so **that one record is silently not recorded**. Its counterpart later looks it up, does not find it, and one span simply does not appear. There are **only 128 keys**, so a wide key space such as a cgroup id fills it quickly", }.freeze,
      { id: :class_ivar,
        map: "<class>_at_<ivar>",
        type: "HASH",
        declared_as: :maps,
        max_entries: "1",
        key: "__u32",
        value: "__s64",
        created_by: %w[class_ivar],
        probe: "class_ivar",
        probe_kind: :syntax,
        role: "one map per instance variable of an eBPF class",
        when_full: "A single fixed key, so it cannot overflow",
        note: "The map name is <class>_at_<ivar>, with the class name lowercased", }.freeze,
      { id: :cidr_blocklist,
        map: "bpf_cidr_block",
        type: "LPM_TRIE",
        declared_as: :maps,
        max_entries: "8192",
        key: "struct spnl_cidr_key",
        value: "__u8",
        flags: "BPF_F_NO_PREALLOC",
        created_by: %w[cidr_blocklist_match],
        probe: "cidr_blocklist_match",
        probe_kind: :builtin,
        role: "a CIDR set, matched by longest prefix",
        when_full: "As above: the kernel side only looks up", }.freeze,
      { id: :dns_pending,
        map: "<unit>_dns_pending",
        type: "LRU_HASH",
        declared_as: :maps,
        max_entries: "65536",
        key: "__u64",
        value: "__u64",
        created_by: %w[dns_emit dns_req_start dns_resp_stash],
        probe: "dns_emit",
        probe_kind: :builtin,
        role: "DNS query correlation state, keyed by (socket << 16 | transaction id)",
        when_full: "It never fails when full -- it **evicts the least recently used entry** instead. Once live state exceeds the capacity, older in-flight correlation state quietly disappears", }.freeze,
      { id: :conntrack,
        map: "spnl_flow_<unit>_conn",
        type: "LRU_HASH",
        declared_as: :maps,
        max_entries: "65536",
        key: "struct spnl_flow_<unit>_conn_k",
        value: "struct spnl_flow_<unit>_conn_v",
        created_by: %w[flow_del flow_get flow_set],
        probe: "flow_del",
        probe_kind: :builtin,
        role: "four-tuple connection tracking, for stateful L4 load balancing",
        when_full: "It never fails when full -- it **evicts the least recently used entry** instead. Once live state exceeds the capacity, older in-flight correlation state quietly disappears", }.freeze,
      { id: :ringbuf_lost,
        map: "<unit>_lost",
        type: "PERCPU_ARRAY",
        declared_as: :maps,
        max_entries: "1",
        key_size: "sizeof(__u32)",
        value_size: "sizeof(__u64)",
        per_cpu: true,
        created_by: %w[dns_emit emit_argv emit_comm emit_connect emit_dns emit_kfield_str emit_l7 emit_parent_path emit_path emit_tcp_payload emit_tcp_stream go_tls_emit go_tls_req go_tls_resp_stash go_tls_write http_emit http_req_start http_resp_stash offcpu_account offcpu_begin offcpu_emit offcpu_recv_stash redis_emit redis_req_start redis_resp_stash spnl_emit spnl_emit3 spnl_emit4 spnl_emit_pair spnl_emit_str ssl_emit ssl_req_start ssl_resp_stash],
        probe: "dns_emit",
        probe_kind: :builtin,
        role: "how many records were dropped because a ring was full; one counter for the whole unit",
        when_full: "A single fixed slot",
        note: "**per-CPU**: userspace sums across all CPUs, which the runtime does. It is a unit total, not per channel", }.freeze,
      { id: :path_scratch,
        map: "<unit>_path_scratch",
        type: "PERCPU_ARRAY",
        declared_as: :maps,
        max_entries: "1",
        key: "__u32",
        value: "char[4096]",
        per_cpu: true,
        created_by: %w[path_contains path_starts_with],
        probe: "path_contains",
        probe_kind: :builtin,
        role: "4096 bytes of scratch for bpf_d_path, which does not fit on the BPF stack",
        when_full: "A single fixed slot",
        note: "per-CPU. The value is the helper's output buffer, read only by the same handler", }.freeze,
      { id: :hist_keyed_zero,
        map: "bpf_hist_keyed_zero",
        type: "PERCPU_ARRAY",
        declared_as: :maps,
        max_entries: "1",
        key: "__u32",
        value: "struct spnl_hist_struct",
        per_cpu: true,
        created_by: %w[hist_observe_by off_cpu_observe off_cpu_start],
        probe: "hist_observe_by",
        probe_kind: :builtin,
        role: "a 512-byte zero template for the keyed histogram, kept in a map because it does not fit on the BPF stack",
        when_full: "A single fixed slot",
        note: "per-CPU, but **the value is never read** -- it exists only as an initialisation template -- so there is nothing to aggregate", }.freeze,
      { id: :fifo,
        map: "bpf_fifo",
        type: "QUEUE",
        declared_as: :maps,
        max_entries: "1024",
        value: "__s64",
        created_by: %w[fifo_pop fifo_push],
        probe: "fifo_pop",
        probe_kind: :builtin,
        role: "a queue (FIFO)",
        when_full: "A push into a full queue **returns -E2BIG**, which is what fifo_push returns. A pop from an empty one returns 0, which is **indistinguishable from a stored 0**", }.freeze,
      { id: :conn_events,
        map: "<unit>_conn_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[emit_connect],
        probe: "emit_connect",
        probe_kind: :builtin,
        role: "the packed record channel for connections",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :dns_events,
        map: "<unit>_dns_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[dns_emit emit_dns],
        probe: "dns_emit",
        probe_kind: :builtin,
        role: "the packed record channel for DNS",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :emit3_events,
        map: "<unit>_emit3_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[spnl_emit3],
        probe: "spnl_emit3",
        probe_kind: :builtin,
        role: "the channel for spnl_emit3",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :emit4_events,
        map: "<unit>_emit4_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[spnl_emit4],
        probe: "spnl_emit4",
        probe_kind: :builtin,
        role: "the channel for spnl_emit4",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :emit_events,
        map: "<unit>_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[spnl_emit],
        probe: "spnl_emit",
        probe_kind: :builtin,
        role: "the integer channel for spnl_emit",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :http_events,
        map: "<unit>_http_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[go_tls_emit go_tls_req go_tls_resp_stash go_tls_write http_emit http_req_start http_resp_stash ssl_emit ssl_req_start ssl_resp_stash],
        probe: "go_tls_emit",
        probe_kind: :builtin,
        role: "the packed record channel for HTTP, shared by the plain TCP, SSL plaintext and Go TLS paths",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :l7_events,
        map: "<unit>_l7_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[emit_l7],
        probe: "emit_l7",
        probe_kind: :builtin,
        role: "the packed record channel for L7 round trips",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :l7stream_events,
        map: "<unit>_l7stream_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[emit_tcp_stream],
        probe: "emit_tcp_stream",
        probe_kind: :builtin,
        role: "the packed record channel for L7 round tripsstream",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :offcpu_events,
        map: "<unit>_offcpu_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[offcpu_account offcpu_begin offcpu_emit offcpu_recv_stash],
        probe: "offcpu_account",
        probe_kind: :builtin,
        role: "the packed record channel for off-CPU windows",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :emit_pair_events,
        map: "<unit>_pair_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[spnl_emit_pair],
        probe: "spnl_emit_pair",
        probe_kind: :builtin,
        role: "the channel for spnl_emit_pair",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :redis_events,
        map: "<unit>_redis_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[redis_emit redis_req_start redis_resp_stash],
        probe: "redis_emit",
        probe_kind: :builtin,
        role: "the packed record channel for Redis",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :emit_str_events,
        map: "<unit>_str_events",
        type: "RINGBUF",
        declared_as: :maps,
        max_entries: "256 * 1024",
        created_by: %w[emit_argv emit_comm emit_kfield_str emit_parent_path emit_path emit_tcp_payload spnl_emit_str],
        probe: "emit_argv",
        probe_kind: :builtin,
        role: "the string channel, shared by emit_comm, emit_path, emit_argv and the rest",
        when_full: "If the consumer falls behind, bpf_ringbuf_reserve returns NULL, **the record is dropped and <unit>_lost is incremented**. The runtime reports this at exit as the fourth line of the channel balance report (dropped by the kernel -- ring full)", }.freeze,
      { id: :lifo,
        map: "bpf_lifo",
        type: "STACK",
        declared_as: :maps,
        max_entries: "1024",
        value: "__s64",
        created_by: %w[lifo_pop lifo_push],
        probe: "lifo_pop",
        probe_kind: :builtin,
        role: "a stack (LIFO)",
        when_full: "A push onto a full stack **returns -E2BIG**. A pop from an empty one returns 0, which is **indistinguishable from a stored 0**", }.freeze,
      { id: :stacks,
        map: "bpf_stacks",
        type: "STACK_TRACE",
        declared_as: :maps,
        max_entries: "16384",
        key_size: "sizeof(__u32)",
        value_size: "127 * sizeof(__u64)",
        created_by: %w[off_cpu_observe off_cpu_start offcpu_account stack_id user_stack_id],
        probe: "off_cpu_observe",
        probe_kind: :builtin,
        role: "stack traces: 16384 of them, 127 frames each",
        when_full: "When it is full, or on a hash collision, bpf_get_stackid returns a **negative errno**. stack_id() and user_stack_id() hand that straight back to Ruby, so **a negative value means no stack was captured**", }.freeze,
      { id: :task_storage,
        map: "bpf_task_store",
        type: "TASK_STORAGE",
        declared_as: :maps,
        max_entries: nil,
        key: "int",
        value: "__s64",
        flags: "BPF_F_NO_PREALLOC",
        created_by: %w[task_incr task_load task_store task_swap],
        probe: "task_incr",
        probe_kind: :builtin,
        role: "one scalar per task",
        when_full: "It has no max_entries: storage is allocated per task and freed when the task exits. A failed allocation is null-checked and becomes a no-op", }.freeze,
{ id: :user_ringbuf,
  map: "bpf_user_cmds",
  type: "USER_RINGBUF",
  declared_as: :maps,
  max_entries: "262144",
  created_by: %w[user_ringbuf user_ringbuf_drain],
  probe: "user_ringbuf",
  probe_kind: :attach,
  role: "the **host -> kernel** command channel, and the only general-purpose one. Userspace writes (libbpf reserve/submit, or the glue's `sp_bpf_user_cmd_push`); `user_ringbuf_drain` reads, calling `def user_ringbuf__<name>(value)` once per record. **FIFO order is guaranteed**, which writing a HASH map directly does not give you",
  when_full: "**the push fails** -- `user_ring_buffer__reserve` returns NULL and the glue's `sp_bpf_user_cmd_push` **returns -5**. That is the opposite of a kernel ring buffer, which drops silently: here the overflow is visible to the sender. But **it is the calling Ruby that sees the return value**, so discarding the result of `M.sp_bpf_user_cmd_push(v)` restores the same silence. Note that max_entries is a **byte count** (a 256 KB ring), not a number of records. Note also that **one record is a fixed 8 bytes**: a hand-rolled pusher sending a shorter one makes the callback fire and the count rise while bpf_dynptr_read returns -E2BIG, so **only the value stays 0** (measured)",
  note: "neither of the two `created_by` surfaces compiles on its own -- a unit with only the callback dies with \"nothing drains it\", and a unit with only the drain dies with \"there is no callback to call\". So whenever this map exists, both halves are present. (The PROG_ARRAY is the deliberate opposite: there, either half alone is legal.)", }.freeze,
{ id: :tcp_slice_conntab,
  map: "bpf_conntab",
  type: "LRU_HASH",
  declared_as: :maps,
  max_entries: "65536",
  key: "struct spnl_tcp_slice_key",
  value: "struct spnl_tcp_slice_state",
  created_by: %w[xdp_tcp_slice],
  probe: "xdp_tcp_slice",
  probe_kind: :attach,
  role: "the pure-XDP TCP slice's **connection table**: per 4-tuple, the post-handshake sequence numbers and a state (1 = established, 2 = response sent, 3 = closed). **Userspace never touches it** -- it is written and cleared by the XDP program and by the per-connection `bpf_timer` embedded in the value",
  when_full: "**being an LRU, it does not fail** -- the oldest connection's entry is evicted silently. The next packet of an evicted connection is treated as having no state, so **a GET goes unanswered and a FIN gets no FIN-ACK**; the client retransmits and eventually times out. 65536 is therefore the ceiling on concurrent connections, and exceeding it shows up as a falling success rate rather than as an error",
  note: "key = the 4-tuple (source and destination address, source and destination port); value = server sequence, client sequence, MSS, state and an embedded `struct bpf_timer`. Time-to-live (30s established, 30s response-sent, 60s closed) clears entries automatically, so steady-state occupancy tracks concurrent connections, not cumulative ones", }.freeze,
{ id: :tcp_slice_counters,
  map: "bpf_ts_counters",
  type: "ARRAY",
  declared_as: :maps,
  max_entries: "17",
  key: "__u32",
  value: "__u64",
  created_by: %w[xdp_tcp_slice],
  probe: "xdp_tcp_slice",
  probe_kind: :attach,
  role: "the slice's **observation counters**, keyed by slot number: SYNs received, SYN-ACKs sent, cookies validated, data replies, FINs, RSTs, drops, passes, aborts, timer firings and so on. Read them with `bpftool map dump name bpf_ts_counters`",
  when_full: "**it cannot overflow**: a fixed 17-slot array indexed by literals the code generator emits. The counters themselves use `__sync_fetch_and_add`, so nothing is lost",
  note: "a probe that never calls spnl_emit* still has this map, so \"it is running but nobody is watching\" is observable from outside. Because it drains no ring buffer, it is outside the scope of the channel balance report", }.freeze,
{ id: :prog_array,
  map: "spnl_prog_array",
  type: "PROG_ARRAY",
  declared_as: :maps,
  max_entries: "32",
  key_size: "sizeof(__u32)",
  value_size: "sizeof(__u32)",
  created_by: %w[xdp_tail tail_call_to],
  probe: "xdp_tail",
  probe_kind: :attach,
  role: "the jump table for tail calls. Slot i is the i-th `def xdp_tail__<name>` in **declaration order**; the values are program fds, written by the loader (`_spnl_prog_array_populate`). Neither the probe nor any userspace code touches it",
  when_full: "**it cannot overflow** -- max_entries is the larger of the target count and 32, so everything declared fits. The danger runs the other way: **a `tail_call_to` into an empty slot returns no error and falls through silently**, and the caller carries on with the next statement. So the failure is not \"it jumped somewhere else\" but \"it did not jump\", and nothing observes that. An integer literal slot is range-checked at compile time; a computed one cannot be",
  note: "either of the two `created_by` surfaces alone still produces the map: a unit with only targets would leave them unreachable if the loader had nothing to populate, and a unit that only jumps needs the map to compile at all", }.freeze,
{ id: :reuseport_sockarray,
  map: "bpf_worker_socks",
  type: "REUSEPORT_SOCKARRAY",
  declared_as: :maps,
  max_entries: "64",
  key: "__u32",
  value: "__u64",
  created_by: %w[worker_select],
  probe: "worker_select",
  probe_kind: :builtin,
  role: "the SO_REUSEPORT worker table. Slot i is the listening socket of the worker that called `sp_bpf_reuseport_register(listen_fd, i)`. **The probe's own userspace half writes it** (the glue exposes the FFI that hands over the map fd); the code generator does not know how many workers there are",
  when_full: "**it cannot overflow** (a fixed 64 entries, and the indices an author uses are below that). The danger runs the other way: **a `worker_select` into an empty slot does not fail** -- the helper returns -ENOENT, that is discarded, and the kernel **quietly falls back to its own 5-tuple spread**, so \"the program chose\" and \"the program did not choose\" are indistinguishable in the probe's output. If fewer workers register than the N in your `% N`, that difference in SYNs silently takes the default",
  note: "a unit that uses only `reuseport_hash` does **not** get this map: a program that merely reads the hash (to drop SYNs by hash, say) never indexes the table, and building a table that is populated and never read would be worse than not having one", }.freeze,
      { id: :xskmap,
        map: "bpf_xskmap",
        type: "XSKMAP",
        declared_as: :maps,
        max_entries: "64",
        key_size: "sizeof(__u32)",
        value_size: "sizeof(__u32)",
        created_by: %w[xsk_redirect],
        probe: "xsk_redirect",
        probe_kind: :builtin,
        role: "AF_XDP sockets; userspace populates it",
        when_full: "An xsk_redirect to an unregistered index returns **XDP_PASS**, so the packet goes straight through. The generator passes that as the flags, which differs from the device and CPU maps", }.freeze,

{ id: :timer_slot,
  map: "spnl_timer_map",
  type: "ARRAY",
  declared_as: :maps,
  max_entries: "1",
  key: "__u32",
  value: "struct spnl_timer_value",
  created_by: %w[timer],
  probe: "timer",
  probe_kind: :attach,
  role: "the single bpf_timer behind `on :timer`: one array slot whose value is a `struct { struct bpf_timer t; }`",
  when_full: "**there is no room to overflow** -- one timer per unit means one slot, and a second `on :timer` dies at compile time. Two units in one program would each declare their own map under the same name, but this tree builds one unit per binary, so that does not arise",
  note: "**there is nothing useful to read here from userspace**: the contents are kernel timer state, and reading the value does not tell you the period. The period lives in the generated C, in the bpf_timer_start arguments, and `spinel-ebpf describe` prints it", }.freeze,

      # --- below this line: maps that never appear under `SEC(".maps")` ------
      # Reading the generated C, none of these look like maps, yet all of them exist in
      # the kernel -- they were read back out of libbpf's own post-load view.
      # An entry whose `declared_as` is anything other than :maps is a **weaker tier**:
      # the gate can only see whether a witness of that shape appeared, so the capacity
      # and value size come from `measured` instead. So that this cannot be weakened
      # quietly, a test requires `measured` on every non-:maps entry.
      { id: :struct_ops_tcp_cc,
        map: "spnl_tcp_cc_ops",
        type: "STRUCT_OPS",
        declared_as: :struct_ops,
        max_entries: nil,
        created_by: %w[tcp_cc],
        probe: "tcp_cc",
        probe_kind: :attach,
        role: "the map that registers a congestion-control algorithm written in Ruby with the kernel; one per program",
        when_full: "Capacity does not apply; there is exactly one",
        note: "Declared with `SEC(\".struct_ops\")`. Nothing in the look of the generated C says it is a map",
        measured: "read back from the kernel: a congestion-control probe yields exactly one BPF_MAP_TYPE_STRUCT_OPS map, with an fd" }.freeze,
      { id: :struct_ops_sched_ext,
        map: "spnl_sched_ext_ops",
        type: "STRUCT_OPS",
        declared_as: :struct_ops,
        max_entries: nil,
        created_by: %w[sched_ext],
        probe: "sched_ext",
        probe_kind: :attach,
        role: "the map that registers a CPU scheduler written in Ruby",
        when_full: "Capacity does not apply; there is exactly one",
        note: "Declared with `SEC(\".struct_ops.link\")`, the form in which the loader owns the lifetime",
        measured: "read back from the kernel: a scheduler probe yields exactly one STRUCT_OPS map" }.freeze,
      { id: :struct_ops_qdisc,
        map: "spnl_qdisc_ops",
        type: "STRUCT_OPS",
        declared_as: :struct_ops,
        max_entries: nil,
        created_by: %w[qdisc],
        probe: "qdisc",
        probe_kind: :attach,
        role: "the map that registers a qdisc written in Ruby",
        when_full: "Capacity does not apply; there is exactly one",
        note: "Declared with `SEC(\".struct_ops.link\")`. It is attached through tc as spnl_qdisc",
        measured: "read back from the kernel: a qdisc probe yields exactly one STRUCT_OPS map" }.freeze,
      { id: :rodata,
        map: ".rodata",
        type: "ARRAY",
        declared_as: :rodata,
        max_entries: "1",
        created_by: %w[param filter_by],
        probe: "param",
        probe_kind: :syntax,
        role: "the values behind param and filter_by. The loader writes them before load, and the kernel freezes them",
        when_full: "A single slot. The value size is the sum of the declared constants, so it is not a fixed number",
        note: "All the generated C contains is `volatile const __s64 spnl_param_<name>` -- **libbpf is what creates the map**. " \
              "So adding a `param` adds a map, while nothing anywhere in the code says the word map",
        measured: "read back from the kernel: the parameter and common-filter probes each carry a real " \
                  ".rodata ARRAY whose value size is the sum of the constants they declared" }.freeze,
      { id: :data_section,
        map: ".data.A",
        type: "ARRAY",
        declared_as: :data_section,
        max_entries: "1",
        created_by: %w[queue_push queue_pop],
        probe: "queue_push",
        probe_kind: :builtin,
        role: "the spin lock and list head of a BPF qdisc: a private global holding a bpf_list",
        when_full: "A single slot, holding the list head and the lock",
        note: "`private(A) ...` expands to `SEC(\".data.A\")`. **Being a macro, it is invisible to a text search of the " \
              "generated C** -- scanning the source missed this one entry, and only the kernel-side view found it",
        measured: "read back from the kernel: a qdisc probe carries a real .data.A ARRAY of 24 bytes" }.freeze,
      { id: :usdt_specs,
        map: "__bpf_usdt_specs",
        type: "ARRAY",
        declared_as: :libbpf_header,
        max_entries: "256",
        created_by: %w[usdt],
        probe: "usdt",
        probe_kind: :attach,
        role: "libbpf's USDT spec table, which says how to extract each argument. Including the USDT header brings it in",
        when_full: "256 USDT probes per program, which is libbpf's default",
        note: "**Writing one probe adds three maps**: the spec table, the ip-to-spec-id table and the kconfig section. None of them is declared in the generated C",
        measured: "read back from the kernel: every USDT probe carries a real 256-entry ARRAY of 208-byte values" }.freeze,
      { id: :usdt_ip_to_spec_id,
        map: "__bpf_usdt_ip_to_spec_id",
        type: "HASH",
        declared_as: :libbpf_header,
        max_entries: "1024",
        created_by: %w[usdt],
        probe: "usdt",
        probe_kind: :attach,
        role: "libbpf's map from USDT attach site to spec id",
        when_full: "1024 attach sites, which is libbpf's default",
        note: "As above: it comes from the USDT header",
        measured: "read back from the kernel: every USDT probe carries a real 1024-entry HASH" }.freeze,
      { id: :usdt_kconfig,
        map: ".kconfig",
        type: "ARRAY",
        declared_as: :libbpf_header,
        max_entries: "1",
        created_by: %w[usdt],
        probe: "usdt",
        probe_kind: :attach,
        role: "the kconfig externs the USDT header refers to, such as whether bpf_cookie is available",
        when_full: "A single slot",
        note: "As above: it comes from the USDT header",
        measured: "read back from the kernel: every USDT probe carries a real single-entry, single-byte ARRAY" }.freeze,
    ].freeze

    # The retired Ruby oracle declared 18 map types; the production C generator emits
    # 15. The three that differ **went with the surfaces that were withdrawn**, and
    # bringing one back on its own would leave nothing able to use it. The gate checks
    # on every run that none of the three appears anywhere in its sweep -- which is how
    # a half-finished revival, where the map returns but its counterpart does not, gets
    # caught.

    WITHDRAWN_MAPS = {
# EMPTY, and that is the finished state.
#
# PROG_ARRAY, USER_RINGBUF and REUSEPORT_SOCKARRAY each passed through
# here. None of them was ever missing as a map type: each was withdrawn
# because the surfaces that would create it -- the tail-call target and
# `tail_call_to`, the SEC-less callback and `user_ringbuf_drain`,
# `worker_select` -- had been withdrawn, leaving a map nothing could ask
# for. All three sets of surfaces have since been ported, so the reason is
# gone with them.
#
# Leaving something withdrawn to keep this table non-empty would be keeping
# the gate armed by keeping the product broken. Detecting an absent map is
# the synthesised self-check's job instead.
    }.freeze

    # What the Ruby subset does and does not accept. The rejected list mirrors the
    # loud failures partitioning raises, and the flag names match the ones it uses;
    # a test keeps them in step.
    RUBY_SUBSET = {
      # **These fourteen strings are a summary for a human reader, not the
      # authority.** The authority is `Capabilities::SYNTAX` (one claim = one
      # construct + `lowers_to` + a construct-free twin), which
      # tools/affordance_gate.rb --section syntax measures on every run.
      # While the prose WAS the authority, **two constructs stayed advertised
      # while dead** -- the "a literal count is unrolled" half of the n.times
      # line, and the "including as an expression" half of the if line, i.e.
      # `x = if ... end`. Both survived because only PART of a line was false,
      # and a check that compiles the line's representative example cannot
      # possibly catch that.
      supported: [
        "integer literals, arithmetic (+ - * / %), and comparison (== != < > <= >=)",
        "Underscores in integer literals (5_000_000 == 5000000): readability only, the value is unchanged",
        "if / elsif / else, including as an expression; short-circuit || and &&; bitwise & | ^ << >>; parentheses",
        "local variables; method definitions with arguments and return values; BPF-to-BPF calls",
        "n.times { |i| ... }, including closure capture. A literal count is unrolled; a dynamic one lowers to bpf_loop",
        "integer instance variables, including at top level, each backed by a per-unit hash map (@x += n, @x = n)",
        "attach handlers: def <prefix>__<name>, for any of the attach kinds listed above",
        "an attach handler may declare any number of arguments from none upwards: kernel arguments it does not use can simply be left out, and a kprobe taking none is perfectly legal. Whatever is declared maps positionally onto the calling convention for that kind",
        "class inheritance (class C < BPF::XDP), module inclusion (include BPF::TcpCC), and the reactor form (include BPF::EventLoop; on :kind). " \
        "Nine BPF DSL parents in both the class and the module spelling, and fourteen reactor kinds, all produce output byte-identical to the flat " \
        "def <prefix><member> form -- measured and gated. Before that gate existed, 15 of those 18 surfaces had silently degraded into SEC(\"syscall\")",
        "namespaced constants such as XDP::PASS and IP::Proto::TCP, resolved to their integer values",
        "calls to the builtins listed above, by their flat names",
        "comparison against a compile-time string literal, as in path_eq, payload_starts and tcp_reply_data",
        "reading kernel fields with kfield and kptr, and the dot accessors (sk.snd_cwnd; t = kptr(...); t.field)",
        "the pkt.* chain accessors (pkt.l4.proto, pkt.len and so on): the same fifteen readers as the flat pkt_* names. " \
        "These were measured to be dead in the production generator -- no fixture used the chain form, and a golden test that " \
        "never builds a comparison cannot fail one, so they stayed advertised for a year -- and have since been ported. " \
        "The one-argument form pkt.byte_at(off) forwards to pkt_dynptr_byte_at rather than to a reader: XDP-only, runtime offset. " \
        "It was withdrawn along with that builtin and has since been ported back; the two spellings are again gated as equivalent",
        "NOTE: every \"alternative spelling\" above appears in the surface-sugar table as a machine-readable **claim of equivalence**. " \
        "Their being prose and nothing else is exactly what let them drift. The affordance gate measures on every run whether the two " \
        "spellings really produce the same C",
        "binary-safe FFI (:binstr), which tolerates embedded NULs -- enough to write something like WebSocket framing in Ruby",
      ].freeze,
      # Each flag corresponds to one of the ineligibility flags partitioning raises,
      # every one of which is an immediate error.
      #
      # **"It corresponds" was a claim, not a measurement.** Putting all ten
      # constructs into an attach handler and running the product
      # (`bin/spinel-ebpf compile`) over them, **only `uses_bignum` exited 0** --
      # and the generated C had `9223372036854775807` baked into it, so the
      # thirty digits the author wrote had **silently become a different number**.
      # Two mistakes had lined up: partitioning looked for the string `"bignum"`
      # while **spinel's type name is `bigint`**, making the assignment site
      # unreachable; and only signatures were judged, so **nobody looked at the
      # type of a local at all**. On top of that, a literal wider than 64 bits is
      # clamped by spinel's own front end before it writes the AST, so **the
      # inferred type is the only surviving trace** of what was written. Both
      # halves are fixed (`refine_flags_from_locals` in partition.rb).
      #
      # The `probe` and `refusal` fields below are the **machine-readable
      # expectation the gate reads** -- the rule everywhere in this file is that
      # the affordance owns the expectation and the gate writes none. `probe`
      # places the construct inside an attach handler, because **an attach handler
      # has no native execution path**: only there does "kept native" become
      # indistinguishable from "refused loudly", which is what makes the
      # measurement mean anything.
      rejected: [
        { flag: :uses_float, construct: "floating-point arithmetic", reason: "no FPU in BPF",
          probe: "def kprobe__do_sys_openat2(a)\n  n = 1.5\n  0\nend\n",
          refusal: "uses Float arithmetic" },
        { flag: :uses_regex, construct: "regular expressions", reason: "no regex helper in BPF",
          probe: "def kprobe__do_sys_openat2(a)\n  n = (\"x\" =~ /y/)\n  0\nend\n",
          refusal: "uses regex" },
        { flag: :uses_io, construct: "any I/O", reason: "host side only",
          probe: "def kprobe__do_sys_openat2(a)\n  puts a\n  0\nend\n",
          refusal: "performs I/O" },
        { flag: :uses_thread, construct: "creating a thread",
          reason: "the kernel side cannot create threads",
          probe: "def kprobe__do_sys_openat2(a)\n  t = Thread.new { 1 }\n  0\nend\n",
          refusal: "creates Thread" },
        { flag: :uses_fiber, construct: "Fiber", reason: "BPF has no notion of a fiber",
          probe: "def kprobe__do_sys_openat2(a)\n  f = Fiber.new { 1 }\n  0\nend\n",
          refusal: "uses Fiber" },
        { flag: :uses_closure,
          construct: "a closure capturing an outer variable, other than the supported form",
          reason: "only n.times is supported",
          probe: "def kprobe__do_sys_openat2(a)\n  f = ->(x) { x }\n  0\nend\n",
          refusal: "uses closure",
          note: "**The spelling decides which layer refuses (measured)**: `->(x){}` is a LambdaNode " \
                "and raises this flag, but `lambda { |x| x }` is a **CallNode**, which partitioning " \
                "passes straight through and the generator then rejects with " \
                "`CallNode not yet ported (Stage 1): lambda`. Both are loud; only the first is " \
                "**this** flag" },
        { flag: :uses_recursion, construct: "recursion", reason: "a BPF call graph must be acyclic",
          probe: "def kprobe__do_sys_openat2(a)\n  n = rec(a)\n  0\nend\n\n" \
                 "def rec(x)\n  if x > 0\n    rec(x - 1)\n  else\n    0\n  end\nend\n",
          refusal: "recursiv" },
        { flag: :uses_bignum, construct: "bignum", reason: "BPF integers are 64 bits",
          probe: "def kprobe__do_sys_openat2(a)\n  n = 123456789012345678901234567890\n  0\nend\n",
          refusal: "uses bignum",
          note: "**The one flag that used to exit 0.** A literal wider than 64 bits is rounded to " \
                "INT64_MAX by spinel before the AST is written, so a different value was reaching " \
                "the generated C" },
        { flag: :uses_unbounded_loop, construct: "an unbounded loop",
          reason: "the verifier requires a bound",
          probe: "def kprobe__do_sys_openat2(a)\n  x = 0\n  while x < 3\n    x = x + 1\n  end\n  0\nend\n",
          refusal: "without static upper bound" },
        { flag: :uses_unsupported_type,
          construct: "a signature naming a non-integer type (string, array, hash, ...)",
          reason: "only integer types are eligible for eBPF",
          probe: "def kprobe__do_sys_openat2(a)\n  \"str\"\nend\n",
          refusal: "non-int type" },
      ].freeze,
      note: "A partitioning failure is an immediate error; there is no silent fallback. Ineligibility propagates to any method that calls an ineligible one.",
    }.freeze

    # =====================================================================
    # Surface sugar: the alternative spellings, and the flat form each is equivalent to.
    #
    # RUBY_SUBSET[:supported] is **fourteen strings of prose**, and prose cannot be put
    # through a gate. That is exactly why `pkt.l4.proto` went on being advertised as
    # supported for a year after it died in the move to the C generator. Builtins carried
    # their own machine-readable expectation in `example_for`, and attach kinds carried
    # theirs in `sec:`. Sugar carried none.
    #
    # Each entry here is a **claim of equivalence**: the two spellings must arrive at the
    # same C. Every one of these surfaces was originally introduced with the claim that
    # the generated .bpf.c was **byte-identical** to the flat form. That is a stronger and
    # more useful bar than "it compiles", because it also catches the silent failure where
    # **the sugar compiles but lowers to something else**.
    #
    #   form   :expr    both spellings are **expressions**. The harness writes each as
    #                   `n = <it>` inside a minimal handler of the right shape
    #          :stmt    ... **statements**, inserted as they stand
    #          :attach  ... **whole probe fragments** containing `<BODY>`, because the
    #                   class, module and reactor surfaces are shapes of a file rather
    #                   than expressions
    #   equiv  :identical  the two must produce byte-identical C
    #          :compiles   both need only compile. Used solely where the C legitimately
    #                      differs, and the reason **must** be written in the note; it is
    #                      never weakened silently
    #
    # The derived families -- the pkt.* chain, the constant paths, the DSL parents, the
    # reactor kinds -- are **generated from the same rule the implementation uses**. Add a
    # member to a family and the claim set grows, and what the gate demands grows with it.

    # `pkt.<a>[.<b>]` is the same reader as `pkt_<a>[_<b>]`. The list of flat names is
    # the authority, so a reader that only the chain form knows about cannot exist.
    SUGAR_PKT_CHAIN = %w[
      pkt.len pkt.eth.proto
      pkt.l4.proto pkt.l4.sport pkt.l4.dport pkt.l4.payload_len
      pkt.ip4.src pkt.ip4.dst
      pkt.ip6.src_hi pkt.ip6.src_lo pkt.ip6.dst_hi pkt.ip6.dst_lo
      pkt.tcp.flags pkt.tcp.seq pkt.tcp.ack
    ].freeze

    # Namespaced constants: eight path prefixes onto flat prefixes, the same table the
    # generator uses. One representative per prefix is listed. Auditing every individual
    # constant value is a separate job; what is guarded here is the **resolution rule**.
    SUGAR_CONST_PATHS = {
      "XDP::PASS"                => { flat: "XDP_PASS",                shape: :xdp },
      "IP::Proto::TCP"           => { flat: "IPPROTO_TCP",             shape: :xdp },
      "Eth::P::IP"               => { flat: "ETH_P_IP",                shape: :xdp },
      "TCP::Flag::RST"           => { flat: "TCP_FLAG_RST",            shape: :xdp },
      "TC::Act::SHOT"            => { flat: "TC_ACT_SHOT",             shape: :tc_ingress },
      "SK::PASS"                 => { flat: "SK_PASS",                 shape: :sk_reuseport },
      "TCP::State::ESTABLISHED"  => { flat: "TCP_STATE_ESTABLISHED",   shape: :kprobe },
      "BPF::SockOps::STATE_CB"   => { flat: "BPF_SOCK_OPS_STATE_CB",   shape: :sock_ops },
    }.freeze

    # Class inheritance and module inclusion. Both declare "every method of this class
    # or module belongs to this attach kind", and both are equivalent to the flat
    # `def <prefix><member>`. The three struct_ops parents follow the same rule.
    SUGAR_DSL_PARENTS = {
      "BPF::XDP"         => { prefix: "xdp__",          member: "probe",      params: [],                    ret: "XDP_PASS" },
      "BPF::SockOps"     => { prefix: "sock_ops__",     member: "probe",      params: [],                    ret: "0" },
      "BPF::TcIngress"   => { prefix: "tc__ingress__",  member: "probe",      params: [],                    ret: "TC_ACT_OK" },
      "BPF::TcEgress"    => { prefix: "tc__egress__",   member: "probe",      params: [],                    ret: "TC_ACT_OK" },
      "BPF::SkReuseport" => { prefix: "sk_reuseport__", member: "probe",      params: [],                    ret: "SK_PASS" },
      "BPF::SkMsg"       => { prefix: "sk_msg__",       member: "probe",      params: [],                    ret: "SK_PASS" },
      "BPF::TcpCC"       => { prefix: "tcp_cc__",       member: "cong_avoid", params: %w[sk ack acked],      ret: "0" },
      "BPF::SchedExt"    => { prefix: "sched_ext__",    member: "dispatch",   params: %w[cpu prev],          ret: "0" },
      "BPF::Qdisc"       => { prefix: "qdisc__",        member: "enqueue",    params: %w[skb sch to_free],   ret: "0" },
    }.freeze

    # The reactor form. `on :<kind>[, targets]` is equivalent to the flat
    # `def <prefix><target>` -- the synthesised method name is exactly that. For uprobe,
    # uretprobe, the Go return probe and USDT the target cannot go in a method name, so
    # `<prefix><N>` is synthesised in declaration order; writing that name flat is
    # equivalent. `:timer` is absent because it has no flat spelling at all: its
    # interval arrives as a keyword, so the reactor form is the only one.
    SUGAR_REACTOR = [
      { on: "on :xdp",                                          flat: "xdp__main",          params: [], ret: "XDP_PASS" },
      { on: "on :sock_ops",                                     flat: "sock_ops__main",     params: [], ret: "0" },
      { on: "on :tc_ingress",                                   flat: "tc__ingress__main",  params: [], ret: "TC_ACT_OK" },
      { on: "on :tc_egress",                                    flat: "tc__egress__main",   params: [], ret: "TC_ACT_OK" },
      { on: 'on :kprobe, "do_sys_openat2"',                     flat: "kprobe__do_sys_openat2",    params: [],       ret: "0" },
      { on: 'on :kretprobe, "do_sys_openat2"',                  flat: "kretprobe__do_sys_openat2", params: %w[ret],  ret: "0" },
      { on: 'on :fentry, "tcp_v4_rcv"',                         flat: "fentry__tcp_v4_rcv",        params: %w[skb],  ret: "0" },
      { on: 'on :fexit, "tcp_v4_rcv"',                          flat: "fexit__tcp_v4_rcv",         params: %w[skb ret], ret: "0" },
      { on: 'on :tracepoint, "syscalls", "sys_enter_openat"',   flat: "tracepoint__syscalls__sys_enter_openat", params: %w[dfd], ret: "0" },
      { on: 'on :uprobe, "/usr/bin/bash:readline"',             flat: "uprobe__react0",     params: [], ret: "0" },
      { on: 'on :uretprobe, "/usr/bin/bash:readline"',          flat: "uretprobe__react0",  params: %w[ret], ret: "0" },
      { on: 'on :go_uret, "/usr/bin/app:main.handle"',          flat: "uprobe__react0",     params: %w[ret], ret: "0" },
      { on: 'on :usdt, "/usr/lib/libfoo.so", "libfoo", "throw"', flat: "usdt__react__0",    params: %w[obj], ret: "0" },
      { on: "on :perf_event, hz: 99",                           flat: "perf_event__main",   params: [], ret: "0" },
      # The one reactor kind whose handler is NOT a program, so it
      # cannot stand alone -- a USER_RINGBUF callback with no `user_ringbuf_drain`
      # is refused at compile time (a `static` function with no caller; the host
      # could push forever with nothing on the other end). The companion below is
      # therefore part of the CLAIM, not scaffolding the gate invented: both
      # spellings carry the same drain site, and the two must still reach the same
      # C. It doubles as evidence that `on :xdp` and `def xdp__main` agree in the
      # same unit -- which is the equivalence the row above already asserts.
      { on: "on :user_cmd",                                     flat: "user_ringbuf__cmd_handler", params: %w[cmd], ret: "0",
        companion_sugar: "\n\n  on :xdp do\n    user_ringbuf_drain\n    XDP_PASS\n  end",
        companion_flat:  "\n\ndef xdp__main\n  user_ringbuf_drain\n  XDP_PASS\nend" },
    ].freeze

    # The one-off sugars that do not belong to any family above.
    SUGAR_SINGLES = [
      { id: :int_underscore, family: "underscores in integer literals",
        form: :expr, shape: :kprobe, equiv: :identical,
        sugar: "5_000_000", flat: "5000000",
        note: "Readability only. The whole claim is that neither the value nor the generated C changes" },
      { id: :dot_read, family: "receiver dot accessor (tcp_cc)",
        form: :expr, shape: :tcp_cc, equiv: :identical,
        sugar: "sk.snd_cwnd", flat: "tcp_sock_snd_cwnd(sk)",
        note: "A direct dereference of the trusted `sk` inside a congestion-control context. The gate keys off the method-name prefix and a fixed field table, and does not look at the receiver" },
      { id: :dot_write, family: "receiver dot accessor (tcp_cc)",
        form: :stmt, shape: :tcp_cc, equiv: :identical,
        sugar: "sk.snd_cwnd = 10", flat: "tcp_sock_snd_cwnd_set(sk, 10)" },
      { id: :dot_add, family: "receiver dot accessor (tcp_cc)",
        form: :stmt, shape: :tcp_cc, equiv: :identical,
        sugar: "sk.snd_cwnd += 1", flat: "tcp_sock_snd_cwnd_add(sk, 1)" },
# The one pkt.* chain member that is NOT in SUGAR_PKT_CHAIN, because that
# family is derived by replacing dots with underscores and this one's flat
# spelling is a different word (`pkt_dynptr_byte_at`, not `pkt_byte_at`)
# and takes an argument. It is still the same claim: two spellings, one C.
# It was the only withdrawn-sugar entry until the builtin came back.
{ id: :pkt_chain_pkt_byte_at, family: "pkt.* chain accessor",
  form: :expr, shape: :xdp, equiv: :identical,
  sugar: "pkt.byte_at(14)", flat: "pkt_dynptr_byte_at(14)",
  note: "the chain's only one-argument member. Its flat name is not `pkt_byte_at`, so it is " \
        "not covered by the machine derivation (dot to underscore) and is listed here on its own" },
      # Two alternative spellings of `if`, measured to produce C byte-identical to
      # the canonical block form. They are claimed HERE rather than in
      # Capabilities::SYNTAX on purpose: node-type coverage cannot tell them apart
      # from `if ... end` -- the parser gives all three the same IfNode -- so the
      # only statement worth making about them is the pair equivalence, which is
      # the sugar criterion and is the stronger one.
      { id: :ternary, family: "alternative spellings of if",
        form: :expr, shape: :kprobe_arg, equiv: :identical,
        sugar: "a > 1 ? 1 : 2", flat: "if a > 1\n    1\n  else\n    2\n  end",
        note: "a ternary is also an IfNode, so it came alive the moment the " \
              "EXPRESSION-position IfNode was ported -- until then it fell over " \
              "together with `x = if ... end`" },
      { id: :postfix_if, family: "alternative spellings of if",
        form: :stmt, shape: :kprobe_arg, equiv: :identical,
        sugar: "@h = @h + 1 if a > 1", flat: "if a > 1\n    @h = @h + 1\n  end" },
      { id: :kptr_dot, family: "kptr binding + dot accessor",
        form: :stmt, shape: :kprobe_sk, equiv: :compiles,
        sugar: "t = kptr(sk, \"sock\")\n  n = t.sk_sndbuf",
        flat: "n = kfield(sk, \"sock\", \"sk_sndbuf\")",
        note: "**Measured not to be identical**: the sugar form leaves behind a declaration of the " \
              "local `t` and an assignment `t = ((__s64)(sk))`. The binding is a compile-time thing, but " \
              "the local itself is real. The read expression proper is the same BPF_CORE_READ. So this is " \
              "the one entry where divergence cannot be detected -- all that can be said is that both compile" },
    ].freeze

    # Withdrawn sugar. This is also **the gate's negative control**, on the same reasoning
    # as the withdrawn builtins and attach kinds: a gate that only checks "everything
    # advertised works" stays green forever once it degenerates.
# Withdrawn sugar. EMPTY, and that is the finished state.
#
# The only entry was ever `pkt.byte_at(off)`, the one chain member that
# forwards to a builtin rather than to a reader; it came back when that
# builtin did. Emptying it exposed a structural coupling worth naming:
# **restoring things consumes negative controls**, because a gate that
# proves it can still detect absence by compiling something known-absent
# runs out of material exactly when the product gets healthy. The gate no
# longer reads this table for that purpose. Absence detection in the sugar
# section is synthesised instead (a chain member nobody implements must be
# refused; a deliberately mismatched pair must come back "diverged"), so an
# empty inventory is simply an empty inventory. The gate notes it in one
# line and exits 0.
WITHDRAWN_SUGAR = {}.freeze

    # Flatten the families and the one-offs into a single list. The gate and any audit
    # read only this.
    def surface_sugar
      out = []
      SUGAR_PKT_CHAIN.each do |s|
        out << { id: :"pkt_chain_#{s.tr('.', '_')}", family: "pkt.* chain accessor",
                 form: :expr, shape: :xdp, equiv: :identical, sugar: s, flat: s.tr(".", "_") }
      end
      SUGAR_CONST_PATHS.each do |path, info|
        out << { id: :"const_path_#{info[:flat].downcase}", family: "namespaced constants",
                 form: :expr, shape: info[:shape], equiv: :identical, sugar: path, flat: info[:flat] }
      end
      SUGAR_DSL_PARENTS.each do |parent, i|
        sig = i[:params].empty? ? "" : "(#{i[:params].join(', ')})"
        out << { id: :"attach_class_#{i[:prefix].chomp('__').tr('_', '')}",
                 family: "class inheritance", form: :attach, equiv: :identical,
                 sugar: "class ProbeK < #{parent}\n  def #{i[:member]}#{sig}\n<BODY>\n  end\nend",
                 flat:  "def #{i[:prefix]}#{i[:member]}#{sig}\n<BODY>\nend", ret: i[:ret] }
        out << { id: :"attach_module_#{i[:prefix].chomp('__').tr('_', '')}",
                 family: "module + include", form: :attach, equiv: :identical,
                 sugar: "module ProbeK\n  include #{parent}\n\n  def #{i[:member]}#{sig}\n<BODY>\n  end\nend",
                 flat:  "def #{i[:prefix]}#{i[:member]}#{sig}\n<BODY>\nend", ret: i[:ret] }
      end
      SUGAR_REACTOR.each do |r|
        blk = r[:params].empty? ? "" : " |#{r[:params].join(', ')}|"
        sig = r[:params].empty? ? "" : "(#{r[:params].join(', ')})"
        kind = r[:on][/on :([a-z_]+)/, 1]
        # `companion_*`: a handler that cannot legally stand alone brings its
        # partner along in BOTH spellings. Empty for every other kind.
        out << { id: :"reactor_#{kind}", family: "reactor DSL (on :kind)",
                 form: :attach, equiv: :identical,
                 sugar: "module ProbeK\n  include BPF::EventLoop\n\n  #{r[:on]} do#{blk}\n<BODY>\n  end#{r[:companion_sugar]}\nend",
                 flat:  "def #{r[:flat]}#{sig}\n<BODY>\nend#{r[:companion_flat]}", ret: r[:ret] }
      end
      (out + SUGAR_SINGLES).freeze
    end

    # =====================================================================
    # The syntax vocabulary -- the fifth. **`RUBY_SUBSET[:supported]` used to be
    # the authority, and it is fourteen strings of prose.**
    #
    # Prose was already diagnosed as the reason `pkt.*` could be advertised for a
    # year while dead, and the SUGAR half of it was made machine-readable then.
    # `RUBY_SUBSET[:supported]` itself stayed prose, and the "a literal count is
    # unrolled" half of its n.times line named a lowering the production generator
    # **did not have**, lost in the move from the Ruby generator to the C one.
    # Three lines above it, the "including as an expression" half -- `x = if ...
    # end` -- was dead for the same reason. Neither is a builtin, an attach kind,
    # a sugar pair or a map, so none of the four existing gates swept them.
    #
    # **One claim = one construct.** Not one claim per line of prose, and that
    # follows from what was measured: the n.times line covers three constructs and
    # exactly **one** of them was dead, so the line's representative example
    # (`n.times { |i| ... }`, with `n` a variable) travels the LIVE path and the
    # line passes. The if line was worse: one construct out of seven. **At line
    # granularity, "the line is true" and "every construct in it works" are
    # different statements.**
    #
    # **Passing takes two stages plus a twin:**
    #   1. the advertised spelling **compiles** (this is where the two dead ones fell)
    #   2. the declared `lowers_to` **appears in the generated C**, and does **not**
    #      appear in the construct-free twin (`without`)
    #
    # Stage 2 is needed because constructs have a silent failure mode of their own:
    # `3.times` (literal) and `a.times` (dynamic) **both compile and both are
    # advertised**, yet they must reach different machinery (`bpf_iter_num_*` vs
    # `bpf_loop`). Lose the open-coded path and a literal count quietly becomes a
    # bpf_loop -- exit 0, same semantics, different machinery, **different kernel
    # floor** (6.4 vs 5.17). Stage 1 cannot see any of that. The twin is what makes
    # the needle **load-bearing**: `%`, `else` and `if (` all occur in the
    # boilerplate, so a needle nobody requires to be ABSENT from the twin is
    # satisfied by scaffolding.
    #
    # `lowers_to` is also a **shippable, useful fact** in its own right: the
    # affordance now says out loud that `5_000_000` becomes `5000000`, that
    # `3.times` becomes `bpf_iter_num_new`, and that `@h` becomes a map lookup.
    # The gate holds no expectation of its own; it never has.
    #
    #   form  :expr / :stmt / :attach  ... **the same harness sugar uses**
    #                                      (SUGAR_SHAPES), which is one of the
    #                                      measured reasons the two live together
    #   shape for :expr and :stmt, the context the probe is written in
    #
    # **The alternative spellings (ternary, trailing if, `@x += 1`) belong in the
    # sugar table, not here** -- "two spellings reach the same C" is the stronger
    # claim of the two.
    SYNTAX = [
      # ---- integer literals and arithmetic -------------------------------
      { id: :int_literal, family: "integer literals",
        form: :expr, shape: :kprobe_arg, syntax: "7", without: "8", lowers_to: "= 7;" },
      { id: :op_add, family: "integer arithmetic", form: :expr, shape: :kprobe_arg,
        syntax: "a + 3", without: "a", lowers_to: "a + 3" },
      { id: :op_sub, family: "integer arithmetic", form: :expr, shape: :kprobe_arg,
        syntax: "a - 3", without: "a", lowers_to: "a - 3" },
      { id: :op_mul, family: "integer arithmetic", form: :expr, shape: :kprobe_arg,
        syntax: "a * 3", without: "a", lowers_to: "a * 3" },
      { id: :op_div, family: "integer arithmetic", form: :expr, shape: :kprobe_arg,
        syntax: "a / 3", without: "a", lowers_to: "a / 3",
        note: "the verifier can refuse a signed division. Use divu(a, b) when an unsigned one is meant" },
      { id: :op_mod, family: "integer arithmetic", form: :expr, shape: :kprobe_arg,
        syntax: "a % 3", without: "a", lowers_to: "a % 3" },
      # ---- comparison ----------------------------------------------------
      { id: :cmp_eq, family: "comparison", form: :expr, shape: :kprobe_arg,
        syntax: "(a == 3)", without: "a", lowers_to: "(a == 3)" },
      { id: :cmp_ne, family: "comparison", form: :expr, shape: :kprobe_arg,
        syntax: "(a != 3)", without: "a", lowers_to: "(a != 3)" },
      { id: :cmp_lt, family: "comparison", form: :expr, shape: :kprobe_arg,
        syntax: "(a < 3)", without: "a", lowers_to: "(a < 3)" },
      { id: :cmp_gt, family: "comparison", form: :expr, shape: :kprobe_arg,
        syntax: "(a > 3)", without: "a", lowers_to: "(a > 3)" },
      { id: :cmp_le, family: "comparison", form: :expr, shape: :kprobe_arg,
        syntax: "(a <= 3)", without: "a", lowers_to: "(a <= 3)" },
      { id: :cmp_ge, family: "comparison", form: :expr, shape: :kprobe_arg,
        syntax: "(a >= 3)", without: "a", lowers_to: "(a >= 3)" },
      # ---- bitwise -------------------------------------------------------
      { id: :bit_and, family: "bitwise", form: :expr, shape: :kprobe_arg,
        syntax: "(a & 3)", without: "a", lowers_to: "(a & 3)" },
      { id: :bit_or, family: "bitwise", form: :expr, shape: :kprobe_arg,
        syntax: "(a | 3)", without: "a", lowers_to: "(a | 3)" },
      { id: :bit_xor, family: "bitwise", form: :expr, shape: :kprobe_arg,
        syntax: "(a ^ 3)", without: "a", lowers_to: "(a ^ 3)" },
      { id: :bit_shl, family: "bitwise", form: :expr, shape: :kprobe_arg,
        syntax: "(a << 3)", without: "a", lowers_to: "(a << 3)" },
      { id: :bit_shr, family: "bitwise", form: :expr, shape: :kprobe_arg,
        syntax: "(a >> 3)", without: "a", lowers_to: "(a >> 3)" },
      # ---- short-circuit logic and parentheses ---------------------------
      { id: :bool_or, family: "short-circuit logic", form: :expr, shape: :kprobe_arg,
        syntax: "(a == 1 || a == 2)", without: "a", lowers_to: "(a == 1 || a == 2)" },
      { id: :bool_and, family: "short-circuit logic", form: :expr, shape: :kprobe_arg,
        syntax: "(a > 1 && a < 9)", without: "a", lowers_to: "(a > 1 && a < 9)" },
      { id: :paren, family: "explicit parentheses", form: :expr, shape: :kprobe_arg,
        syntax: "(a + 1) * 2", without: "a * 2", lowers_to: "(a + 1) * 2",
        note: "required against bitwise precedence -- `(flags & TCP_FLAG_RST) != 0`" },
      # ---- control flow ---------------------------------------------------
      { id: :if_then, family: "if / elsif / else", form: :stmt, shape: :kprobe_arg,
        syntax: "if a > 1\n    @h = @h + 1\n  end", without: "@h = @h + 1",
        lowers_to: "if (a > 1) {" },
      { id: :if_else, family: "if / elsif / else", form: :stmt, shape: :kprobe_arg,
        syntax: "if a > 1\n    @h = @h + 1\n  else\n    @h = @h + 2\n  end",
        without: "if a > 1\n    @h = @h + 1\n  end", lowers_to: "} else {" },
      { id: :if_elsif, family: "if / elsif / else", form: :stmt, shape: :kprobe_arg,
        syntax: "if a > 1\n    @h = @h + 1\n  elsif a > 0\n    @h = @h + 2\n  else\n    @h = @h + 3\n  end",
        without: "if a > 1\n    @h = @h + 1\n  else\n    @h = @h + 2\n  end",
        lowers_to: "if (a > 0) {",
        note: "an elsif expands to a nested if/else with a nested temp. Verbose, and clang -O2 folds it" },
      # The second thing the syntax sweep found. The temp-variable lowering was
      # built for exactly this shape, and the retired Ruby generator carried a
      # dedicated path for "an if in EXPRESSION position (`x = if ... end` and so
      # on)". The C port wired IfNode into the statement lowering only, so **only
      # the value form died** -- the statement form, the return-value form and the
      # parenthesised form (ParenthesesNode -> StatementsNode) all kept working,
      # which is why the prose line "if / elsif / else, including as an
      # expression" was six-sevenths true.
      { id: :if_value, family: "if / elsif / else", form: :expr, shape: :kprobe_arg,
        syntax: "if a > 1\n    1\n  else\n    2\n  end", without: "1",
        lowers_to: "_if1;",
        note: "an if in expression position: declare `__s64 _ifN`, assign it in both branches, " \
              "and yield _ifN as the value. `@x = if ... end` and an operand inside a larger " \
              "expression take the same path" },
      # ---- local variables and methods -----------------------------------
      { id: :local_var, family: "local variables", form: :stmt, shape: :kprobe_arg,
        syntax: "x = a + 1\n  n = x * 2", without: "n = a", lowers_to: "x = a + 1;",
        note: "locals are all declared together at the top of the function, as `__s64 x = 0;`" },
      { id: :bpf_to_bpf, family: "BPF-to-BPF call", form: :attach,
        syntax: "def helper(x)\n  x * 2\nend\n\ndef kprobe__do_sys_openat2(a)\n<BODY>\n  helper(a)\nend",
        without: "def helper(x)\n  x * 2\nend\n\ndef kprobe__do_sys_openat2(a)\n<BODY>\n  a\nend",
        ret: "0", lowers_to: "helper_inner(a)",
        note: "calls the `_inner` of another eBPF-eligible method in the same unit directly " \
              "(eBPF has no recursion)" },
      # ---- how many arguments an attach handler declares ------------------
      { id: :attach_args_0, family: "arguments declared by an attach handler", form: :attach,
        syntax: "def kprobe__do_sys_openat2\n<BODY>\nend", ret: "0",
        without: "def kprobe__do_sys_openat2(a)\n<BODY>\nend",
        lowers_to: "_inner();",
        note: "kernel arguments that go unused can simply be left out; a kprobe taking none is legal" },
      { id: :attach_args_n, family: "arguments declared by an attach handler", form: :attach,
        syntax: "def kprobe__do_sys_openat2(a, b)\n<BODY>\n  a + b\nend", ret: "0",
        without: "def kprobe__do_sys_openat2\n<BODY>\nend",
        lowers_to: "PT_REGS_PARM2(ctx)",
        note: "whatever is declared maps positionally onto that kind's calling convention " \
              "(PT_REGS_PARM<N> for a kprobe)" },
      # ---- instance variables ---------------------------------------------
      { id: :ivar_read, family: "instance variables", form: :expr, shape: :kprobe_arg,
        syntax: "@h", without: "a", lowers_to: "bpf_map_lookup_elem(&u_top_h" },
      { id: :ivar_write, family: "instance variables", form: :stmt, shape: :kprobe_arg,
        syntax: "@h = 7", without: "n = 7", lowers_to: "bpf_map_update_elem(&u_top_h" },
      { id: :ivar_opwrite, family: "instance variables", form: :stmt, shape: :kprobe_arg,
        syntax: "@h += 7", without: "n = 7", lowers_to: "bpf_map_update_elem(&u_top_h",
        note: "`@x += n` is a read-modify-write. It is **not** byte-identical to `@x = @x + n` " \
              "(measured: an extra pair of parentheses and a different temp number). The meaning " \
              "is the same" },
      { id: :top_ivar, family: "top-level instance variables", form: :attach,
        syntax: "@h = 0\n\ndef kprobe__do_sys_openat2(a)\n<BODY>\n  @h\nend",
        without: "def kprobe__do_sys_openat2(a)\n<BODY>\n  a\nend", ret: "0",
        lowers_to: "u_top_h SEC(\".maps\")",
        note: "one top-level ivar = one per-unit hash map, shared between the attach handlers" },
      { id: :class_ivar, family: "instance variables of a class", form: :attach,
        syntax: "class C\n  def incr(d)\n<BODY>\n    @x = @x + d\n    @x\n  end\nend",
        without: "class C\n  def incr(d)\n<BODY>\n    d\n  end\nend", ret: "0",
        lowers_to: "c_at_x SEC(\".maps\")",
        note: "one ivar = one hash map (a singleton keyed by __u32)" },
      # ---- loops ----------------------------------------------------------
      # These two are why stage 2 exists: **both compile and both are
      # advertised**, and they must reach different machinery. Lose the open-coded
      # path and a literal count quietly becomes a bpf_loop -- exit 0, the same
      # semantics, a different kernel floor.
      { id: :times_literal, family: "n.times", form: :stmt, shape: :kprobe_arg,
        syntax: "3.times do |i|\n    @h = @h + i\n  end", without: "@h = @h + 1",
        lowers_to: "bpf_iter_num_new",
        note: "a literal count becomes an open-coded iterator inlined into the caller, with no " \
              "callback and no capture struct. **The kernel floor is 6.4**" },
      { id: :times_dynamic, family: "n.times", form: :stmt, shape: :kprobe_arg,
        syntax: "a.times do |i|\n    @h = @h + i\n  end", without: "@h = @h + 1",
        lowers_to: "bpf_loop(",
        note: "a dynamic count becomes bpf_loop plus a generated callback. The kernel floor is 5.17" },
      { id: :times_capture, family: "n.times", form: :stmt, shape: :kprobe_arg,
        syntax: "t = 0\n  a.times do |i|\n    t = t + i\n  end\n  n = t", without: "n = a",
        lowers_to: "_caps",
        note: "a block capturing an outer local gets a per-loop caps struct, passed by pointer" },
      # ---- constants -------------------------------------------------------
      { id: :const_read, family: "constants", form: :expr, shape: :kprobe_arg,
        syntax: "IPPROTO_TCP", without: "0", lowers_to: "= 6;",
        note: "a known constant name resolves to an integer literal; nothing is looked up at run time" },
      { id: :const_path, family: "constants", form: :expr, shape: :kprobe_arg,
        syntax: "IP::Proto::TCP", without: "0", lowers_to: "= 6;",
        note: "the namespaced path resolves to the same integer (eight prefixes). That the two " \
              "spellings agree is a sugar claim" },
      # ---- fixed string literals -------------------------------------------
      { id: :string_literal, family: "fixed string literals", form: :expr,
        shape: :kprobe_sk, syntax: "kfield(sk, \"sock\", \"sk_sndbuf\")",
        without: "kfield(sk, \"sock\", \"sk_rcvbuf\")", lowers_to: "sk_sndbuf",
        note: "strings exist at compile time only (BPF has no string heap). Field names, paths " \
              "and comparison literals are all baked in ahead of time" },
      # ---- compound assignment through a receiver ---------------------------
      { id: :dot_op_assign, family: "receiver dot accessor", form: :stmt,
        shape: :tcp_cc, syntax: "sk.snd_cwnd += 1", without: "sk.snd_cwnd = 1",
        lowers_to: "->snd_cwnd += ",
        note: "a CallOperatorWriteNode. tcp_sock fields inside a congestion-control context only" },
    ].freeze

    # Withdrawn syntax. Empty is a true statement about the tree, not a hole:
    # this is an inventory, and the gate's detection power lives in its
    # synthesised self-checks.
    WITHDRAWN_SYNTAX = {}.freeze

    # **The authority for the check that runs the other way round.**
    #
    # A gate that only asks whether a CLAIM holds stays green while the affordance
    # says nothing at all -- which is how the map vocabulary failed. The syntax
    # equivalent of "what the implementation actually does" is **the node types
    # the production generator accepts**, and the authority for that is the two
    # lowering dispatchers in `src/codegen_c/spinel_ebpf_cc.c` (`cc_lower_expr` /
    # `cc_lower_stmt`) and their `strcmp(ty, "XxxNode")` arms. The gate reads them
    # out of the source and reports any node type **no claim's probe contains**
    # (start accepting `WhileNode` and it shows up the same day).
    #
    # **The granularity limit is stated on purpose** (measured): a node type is
    # coarser than a construct. The ternary `a > 1 ? 1 : 2` and `if ... else ...
    # end` are the **same IfNode**, so node-type coverage cannot separate them.
    # CallNode is worse still -- builtins, sugar and operators are all one type.
    # So the operator members of CallNode get a second authority,
    # `cc_is_binary_op()`'s table of sixteen, and are covered **per operator**;
    # the remaining CallNode members (builtins, sugar) are covered by name by the
    # builtin and sugar sections.
    SYNTAX_COVERAGE_AUTHORITIES = {
      node_types: { file: "src/codegen_c/spinel_ebpf_cc.c",
                    functions: %w[cc_lower_expr cc_lower_stmt],
                    what: "the AST node types it accepts (strcmp(ty, \"XxxNode\"))" },
      binary_ops: { file: "src/codegen_c/spinel_ebpf_cc.c",
                    functions: %w[cc_is_binary_op],
                    what: "the table of binary operators" },
    }.freeze

    # ===================================================================
    # Making the sugar spellings VISIBLE TO INTROSPECTION.
    #
    # `describe` and `capabilities <file>` work out a probe's capability domains by
    # scanning for flat builtin names, and the scan deliberately excludes anything
    # after a dot (so that the receiver in `sk.foo` is not read as a builtin). The
    # consequence was that the chain spelling `pkt.l4.proto` matched nothing at all:
    # **the spelling this project recommends was the one whose affordance came back
    # empty**. The generated C was identical throughout -- the equivalence claims are
    # measured on every gate run -- so the only thing that disagreed was the
    # introspection.
    #
    # No second table (that is the same design decision the equivalence claims made:
    # "a reader that only the chain side knows about cannot structurally exist"). The
    # entries are selected out of the one authority the gate already reads,
    # `surface_sugar`:
    #   * form is :expr or :stmt (an attach form's spelling is a method name)
    #   * the sugar is ONE dotted identifier chain -- optionally with a trailing
    #     `(...)` argument list, or ` = <value>` / ` += <value>`
    #   * the head identifier on the flat side is a REGISTERED builtin
    # so `XDP::PASS` (a constant, not a builtin), `5_000_000` (no dot) and the
    # two-statement `t = kptr(...)` (head identifier `t`) drop out on their own. When a
    # family gains a member, this and the gate gain it at the same time.
    # ===================================================================
    SUGAR_ALIAS_RE = /\A([a-z_]\w*(?:\.[a-z_]\w*)+)(?:\([^)]*\))?(?:\s*(\+?=)\s*\S+)?\z/.freeze

    def sugar_builtin_aliases
      bs = all_builtins
      surface_sugar.filter_map do |s|
        next unless %i[expr stmt].include?(s[:form])
        m = SUGAR_ALIAS_RE.match(s[:sugar].to_s.strip) or next
        flat = s[:flat].to_s[/\A[a-z_]\w*/]
        next unless flat && bs.include?(flat)
        { id: s[:id], sugar: s[:sugar], dotted: m[1], op: m[2], flat: flat }
      end
    end

    # The regexp that finds an alias in source text. The one non-obvious point is **not
    # confusing the read form with the write form**: `sk.snd_cwnd` (a reader) and
    # `sk.snd_cwnd = 10` (a writer) lower to different builtins, so the read form
    # excludes a following assignment with a negative lookahead. `==` is a comparison
    # and is not excluded (the inner lookahead is what draws that line).
    def sugar_alias_regexp(a)
      base = "(?<![\\w.])#{Regexp.escape(a[:dotted])}(?![\\w])"
      case a[:op]
      when "="  then /#{base}\s*=(?!=)/
      when "+=" then /#{base}\s*\+=/
      else           /#{base}(?!\s*\+?=(?!=))/
      end
    end

    # The flat builtin names (uniq) whose sugar spelling appears in comment-free source.
    def sugar_alias_hits(code)
      sugar_builtin_aliases.filter_map { |a| a[:flat] if code =~ sugar_alias_regexp(a) }.uniq
    end

    # The enrichers, for reference. Without changing the probe at all, they
    # add attributes at run time, gated by environment variables. This is where an
    # author can see that pod attribution comes from the environment, not the probe.
    ENRICHERS = [
      { name: "k8s", layer: 2, signal_scope: "all",
        attributes: %w[k8s.pod.name k8s.namespace.name k8s.pod.uid k8s.container.name],
        gate: "the cgroup_id() builtin, plus resolving the cgroup against kubepods",
        note: "pod attribution appears without changing the probe; unset, it does nothing" },
      { name: "cri", layer: 2, signal_scope: "all",
        attributes: %w[k8s.container.name],
        gate: "CRIMAP (env)",
        note: "replaces the container id with the real container name, last writer winning; unset, it does nothing" },
      { name: "peer", layer: 2, signal_scope: "conn",
        attributes: %w[peer.address peer.pod peer.service peer.external],
        gate: "resolving the destination address",
        note: "connection spans only -- the ones that have a destination" },
    ].freeze

    # ===================================================================
    # The required sets: calls that only mean something together.
    # the contract.
    #
    # Some builtins mean nothing on their own: they only produce a span together with
    # a counterpart, usually in a different attach section. Write one half and the
    # program is quietly broken -- records accumulate, nobody reads them, no span
    # appears, and it still exits 0. That is
    # A program missing one of them is the worst kind of failure -- quiet. The
    # contract is held here as plain data so that
    #   * the compile-time check reads it and rejects the program,
    #   * it appears in the affordances (`--json`, under `required_sets`), so an
    #     author can see what the other half is,
    # so both hold at once.
    #
    # mode:
    #   :all      -- using any member makes all of them required; they are mutually dependent.
    #   :requires -- using the trigger makes everything it requires mandatory, in one
    #                direction only: the others remain valid on their own.
    #
    # The contract is deliberately no tighter than reality:
    #   * emit_connect and emit_dns are valid alone, so they are not listed here.
    #   * sock_owner_set means nothing unless emit_connect reads what it records, so
    #     it requires that one, in one direction.
    #   Every complete probe under examples/observability/otlp satisfies this.
    #
    # There is another half to every span-producing set. The members above are the
    # kernel-side builtins, and they only accumulate records in a map; nothing is
    # exported until userspace declares the FFI and runs a drain loop.
    # That half used to be invisible here, and it showed: given only these
    # affordances, two different models wrote a correct kernel probe, omitted the
    # drain, and produced a program that compiled, verified, and emitted no spans --
    # exactly the kernel/userspace bridge bug this project exists to make
    # impossible. So each set now carries a `userspace_export` companion as data:
    # the FFI name of its counterpart, and one line of drain-loop syntax. The
    # interval is the author's decision; this shows the syntax, not the policy. The
    # push functions themselves are defined in bin/spinel-ebpf, and all take just an
    # endpoint.
    # Reading the endpoint from the OTLP_ENDPOINT environment variable is the
    # convention here: given a bare placeholder, an author tends to hard-code it,
    # get the port wrong, and see zero spans. Choosing the value is still theirs;
    # this is portability syntax, not advice.
    REQUIRED_SETS = [
      { name: "http_span", mode: :all,
        members: %w[http_req_start http_resp_stash http_emit],
        why: "The first records the request, the second stashes the receive buffer, and the third correlates them into a span. Omit any one and no span appears.",
        userspace_export: {
          fn: "spnl_otlp_http_span_push",
          ffi_decl: "ffi_func :spnl_otlp_http_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_http_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_http_span_push(ep) }",
          why: "The kernel-side builtins only accumulate span records in a map. Nothing is exported until userspace drains them through this FFI. Leave it out and the program compiles, the verifier is happy, and not one span comes out.",
        }.freeze }.freeze,
      { name: "redis_span", mode: :all,
        members: %w[redis_req_start redis_resp_stash redis_emit],
        why: "The first records the request, the second stashes the receive buffer, and the third correlates them into a span carrying the command, any error, and the duration. Omit any one and no span appears.",
        userspace_export: {
          fn: "spnl_otlp_redis_span_push",
          ffi_decl: "ffi_func :spnl_otlp_redis_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_redis_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_redis_span_push(ep) }",
          why: "The kernel-side builtins only accumulate span records in a map. Nothing is exported until userspace drains them through this FFI. Leave it out and the program compiles, the verifier is happy, and not one span comes out.",
        }.freeze }.freeze,
      { name: "ssl_span", mode: :all,
        members: %w[ssl_req_start ssl_resp_stash ssl_emit],
        why: "Three hooks over the TLS plaintext -- request, response, emit -- make one span. Omit one and no plaintext span appears.",
        userspace_export: {
          fn: "spnl_otlp_http_span_push",
          ffi_decl: "ffi_func :spnl_otlp_http_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_http_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_http_span_push(ep) }",
          why: "The TLS path reuses the HTTP push; there is no separate one for it. The kernel-side builtins only accumulate records in a map, and nothing is exported until userspace drains them through this FFI.",
        }.freeze }.freeze,
      { name: "dns_span", mode: :all,
        members: %w[dns_req_start dns_resp_stash dns_emit],
        why: "Three hooks -- request, response, emit -- make one DNS span, with its latency.",
        userspace_export: {
          fn: "spnl_otlp_dns_span_push",
          ffi_decl: "ffi_func :spnl_otlp_dns_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_dns_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_dns_span_push(ep) }",
          why: "The kernel-side builtins only accumulate span records in a map. Nothing is exported until userspace drains them through this FFI. Leave it out and the program compiles, the verifier is happy, and not one span comes out.",
        }.freeze }.freeze,
      { name: "l7_latency", mode: :all,
        members: %w[req_start emit_l7],
        why: "The first records the send time and the second reads the round trip and makes the span. With only one of them there is no duration.",
        userspace_export: {
          fn: "spnl_otlp_l7_span_push",
          ffi_decl: "ffi_func :spnl_otlp_l7_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_l7_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_l7_span_push(ep) }",
          why: "The kernel-side builtins only accumulate span records in a map. Nothing is exported until userspace drains them through this FFI. Leave it out and the program compiles, the verifier is happy, and not one span comes out.",
        }.freeze }.freeze,
      { name: "offcpu_span", mode: :all,
        members: %w[offcpu_recv_stash offcpu_begin offcpu_account offcpu_emit],
        why: "The first two open the off-CPU window, the third accumulates what was waited on, and the fourth closes the window and makes the span. Four hooks, one set.",
        userspace_export: {
          fn: "spnl_otlp_offcpu_span_push",
          ffi_decl: "ffi_func :spnl_otlp_offcpu_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_offcpu_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_offcpu_span_push(ep) }",
          why: "The kernel-side builtins only accumulate span records in a map. Nothing is exported until userspace drains them through this FFI. Leave it out and the program compiles, the verifier is happy, and not one span comes out.",
        }.freeze }.freeze,
      { name: "sock_owner_correlation", mode: :requires,
        trigger: "sock_owner_set", requires: %w[emit_connect],
        why: "sock_owner_set only records which process owns a socket; the correlation happens when emit_connect looks the same socket up.",
        userspace_export: {
          fn: "spnl_otlp_conn_span_push",
          ffi_decl: "ffi_func :spnl_otlp_conn_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_conn_span_push, [:str], :int\nend\n# ... kernel handlers (sock_owner_set + emit_connect) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_conn_span_push(ep) }",
          why: "This correlation is exported on the connection span emit_connect produces; there is no separate push for it. The kernel-side builtins only accumulate records in a map, and nothing is exported until userspace drains them through this FFI.",
        }.freeze }.freeze,
    ].freeze

    # --- the machine-readable affordance queries ---

    # builtin -> signature hash ({arity:, params:, opaque:, summary:})。
    def signature_for(name)
      SIGNATURES[name] || { arity: nil, params: nil, opaque: true, summary: nil }
    end

    # A builtin to its context requirement, or nil when the generator does not enforce one.
    def context_for(name)
      CONTEXT_REQUIREMENTS[name]
    end

    # A builtin to the list of contexts it is valid in, for the JSON output; nil when ungated.
    def context_strings(name)
      req = CONTEXT_REQUIREMENTS[name]
      return nil unless req
      return req[:secs] if req[:secs]
      req[:kinds].map(&:to_s)
    end

    # A builtin to a human-readable note about its context: enforced when gated,
    # best-effort otherwise.
    def context_note(name)
      return "enforced at compile time; using it outside these hooks is an error" if CONTEXT_REQUIREMENTS[name]
      CONTEXT_NOTE_OVERRIDES[name] || DOMAIN_CONTEXT_NOTE[domain_of(name)] || "not enforced by the generator"
    end

    # A builtin to one line of Ruby showing how it is called. An opaque builtin gets
    # nil: its parameters are unknown, and omitting the example is more honest than
    # inventing one.
    def example_for(name)
      sig = signature_for(name)
      return nil if sig[:opaque]              # deliberately absent: nil exactly when opaque
      ov = EXAMPLE_OVERRIDES[name]
      return ov if ov
      params = sig[:params]
      return name if params.nil? || params.empty?   # no arguments: a bare call, the usual idiom
      "#{name}(#{params.join(', ')})"
    end

    # A builtin to the others in its group, sorted; empty when it belongs to none.
    # The groups table is the single authority.
    def related_for(name)
      BUILTIN_GROUPS.each_with_object([]) do |g, acc|
        acc.concat(g[:members] - [name]) if g[:members].include?(name)
      end.uniq.sort
    end

    # The complete affordance entry for one builtin.
    def builtin_entry(name)
      sig = signature_for(name)
      chan = record_channel_for(name)   # non-nil only for a builtin that writes a packed record
      {
        name: name,
        domain: domain_of(name),
        arity: sig[:arity],
        params: sig[:params],
        opaque: sig[:opaque],
        example: example_for(name),   # one line of calling syntax; null when opaque
        related: related_for(name),   # the other builtins in its group
        gated: !CONTEXT_REQUIREMENTS[name].nil?,
        valid_contexts: context_strings(name),
        context_note: context_note(name),
        summary: sig[:summary],
        # The unit and byte order of the return value, non-nil only where mistaking it
        # would pass quietly. Kept apart from the prose summary because this is the
        # field a machine reads.
        value_semantics: value_semantics_for(name),
        # The record this builtin writes into a ringbuf, and the span those bytes
        # become. The fields and offsets come from the generator's layout; the
        # attributes from the egress declaration.
        record_channel: chan && chan[:id],
        record_schema: chan,
      }
    end

    # The whole affordance document as a Ruby hash; the CLI renders it as JSON.
    def affordance
      {
        schema: "spinel-ebpf.affordance/1",
        note: "The authoring contract, published for introspection. It does not affect " \
              "generated code. Builtin names stay flat; they are deliberately not " \
              "namespaced into dotted forms.",
        summary: {
          builtin_count: all_builtins.length,
          opaque_builtins: all_builtins.count { |b| signature_for(b)[:opaque] },
          attach_kind_count: ATTACH_KINDS.length,
          domains: DOMAINS.keys,
          record_channel_count: record_channels.length,
          record_value_map_count: record_value_maps.length,
          # How many metrics are declared, and the CEILING on the number of time
          # series they can ever produce. The second number is the one a reviewer
          # wants and no other artifact carries: it is computed from the label
          # declarations, so it holds for traffic nobody has measured.
          record_metric_count: record_metrics.length,
          record_metric_series_bound: record_metrics.sum { |m| m[:series_bound].to_i },
          map_count: MAPS.length,
          map_type_count: MAPS.map { |m| m[:type] }.uniq.length,
          # The fifth vocabulary. Until it existed, the Ruby subset was fourteen
          # strings of prose, and two of the constructs they advertised were dead.
          syntax_count: SYNTAX.length,
          syntax_rejected_count: RUBY_SUBSET[:rejected].length,
        },
        domains: DOMAINS.each_with_object({}) { |(d, s), h|
          h[d] = { summary: s[:summary], attach_kinds: s[:attach_kinds] }
        },
        builtins: all_builtins.map { |b| builtin_entry(b) },
        # Cross-links between related builtins -- pairings and families -- with the
        # facts needed to choose between them.
        builtin_groups: BUILTIN_GROUPS,
        # **Withdrawn builtins.** The Ruby constant has existed for a while and
        # tools/affordance_gate.rb reads it directly, but it was never published here
        # (unlike withdrawn_sugar and withdrawn_maps). To a consumer reading only the
        # JSON, "a name that was never advertised" and "a name whose advertisement was
        # taken back" were indistinguishable -- and the second kind is exactly what a
        # machine picks up from older prose and tries to write. Same silence the map
        # vocabulary had, so it gets the same opening: `why` (what was wrong with it)
        # and `instead` (what to write in its place) travel together.
        withdrawn: WITHDRAWN,
        attach_kinds: ATTACH_KINDS,
        # Withdrawn attach kinds. Kept in a separate table from the builtins because the
        # silence has a different quality: an unported builtin dies, an unported attach
        # kind exits 0 and degrades to SEC("syscall").
        withdrawn_attach: WITHDRAWN_ATTACH,
        context_gates: CONTEXT_GATES.map { |n, g|
          { builtin: n, domain: g[:domain], valid_secs: g[:valid_secs] }
        },
        # `valid_secs` only ever meant "this compiles". Compiling and firing are
        # different things -- of these 32 hooks, only 4 had ever had their firing
        # measured -- so each hook says what reaches it, whether its return value is
        # honoured, and whether the obvious operation misses it. For a machine author
        # this is the only machine-readable ground for "will the policy I wrote be
        # silent".
        dpath_hooks: DPATH_HOOKS.map { |sec, h|
          { sec: sec, form: h[:form], guard: h[:guard], load_measured: h[:measured],
            fire: h[:fire], fired_by: h[:by], fire_measured: h[:fired],
            caveat: h[:caveat],
            # Non-nil = path SELECTION is structurally impossible, so path_eq /
            # path_starts_with / path_contains fail at compile time. emit_path and
            # parent_path_eq still compile.
            no_select: h[:no_select],
            lsm_active_required: lsm_active_required?(sec) }
        },
        # A summary of the `no_select` above: what is refused, and what is still allowed
        # on the same hook. The asymmetry is the claim, so neither half is published
        # without the other.
        dpath_no_select: { secs: DPATH_NO_SELECT_SECS,
                           refused_builtins: DPATH_SELECT_BUILTINS,
                           allowed_builtins: DPATH_NONSELECT_BUILTINS,
                           measured: "firing sweep of all 32 gated hooks; refused at compile time" },
        dpath_rejected: DPATH_MEASURED_REJECTED,
        ruby_subset: RUBY_SUBSET,
        # Surface sugar. ruby_subset is prose, so it cannot answer "can I write
        # pkt.l4.proto" mechanically -- which is why that spelling went on being
        # advertised for a year after it stopped working. This is the list of
        # **equivalence claims**, and the affordance gate measures on every run whether
        # the two spellings really produce the same C. withdrawn_sugar holds the
        # spellings that were taken back.
        surface_sugar: surface_sugar.map { |s|
          s.merge(sugar: s[:sugar].to_s.gsub("<BODY>", "    ..."),
                  flat:  s[:flat].to_s.gsub("<BODY>", "  ..."))
        },
        withdrawn_sugar: WITHDRAWN_SUGAR,
        # The syntax vocabulary. The prose in `ruby_subset[:supported]` is still
        # there but is **no longer the authority**: one claim = one construct,
        # each carrying what it lowers to (`lowers_to`) and a twin with the
        # construct removed (`without`). tools/affordance_gate.rb --section syntax
        # measures on every run that the advertised spelling compiles, that it
        # becomes what is claimed, and that the needle is not merely satisfied by
        # boilerplate -- and, in the opposite direction, that every node type and
        # operator the generator accepts is advertised by some claim.
        syntax: SYNTAX,
        withdrawn_syntax: WITHDRAWN_SYNTAX,
        syntax_coverage_authorities: SYNTAX_COVERAGE_AUTHORITIES,
        # The map vocabulary. While this was empty, nothing in the affordance said that
        # writing `@x += 1` creates a map, or that a ring buffer is 256 KiB and drops
        # silently when it overflows. The implementation was sound throughout: this was
        # silence rather than a lie, which is why it went unnoticed.
        maps: MAPS,
        withdrawn_maps: WITHDRAWN_MAPS,
        enrichers: ENRICHERS,
        krew_probes: KREW_PROBE_DOMAINS,
        # The multi-hook required sets: builtins that produce no span alone. The
        # compile-time check enforces them loudly.
        required_sets: REQUIRED_SETS,
        # The packed-record channel contracts: the bytes written into a ringbuf and
        # the OTLP attributes they become. This only reads what the generator
        # produced from the record declaration; no offset is computed here, because
        # there is exactly one implementation of that layout.
        record_channels: record_channels,
        # The closed sets behind every type-driven derived value. A channel's consumer
        # properties and its egress attributes point in here. Without it, "what can
        # ever appear in this attribute" is unanswerable until a probe has been run and
        # one sample looked at -- which is the same predicament as being handed a bare
        # error number.
        record_value_maps: record_value_maps,
        # Histogram bucket boundaries, declared once and shared. Published so that "are
        # these comparable with the histograms an OTel SDK or eBPF instrumentation
        # produces" can be answered here rather than by diffing two C files: the
        # boundaries were aligned to those defaults, and the array is now one
        # declaration that both readers use.
        record_bounds_sets: record_bounds_sets,
        # The same layouts, published in the OBJECT rather than here.
        # `record_channels` above is what a reader gets if it can run this Ruby;
        # RECORD_BTF is what it gets if all it has is the .bpf.o. Both are
        # derived from record_schema.h, so they cannot disagree -- but only one
        # of them travels with the object, and a reader that has to copy a layout
        # by hand gets it wrong silently (a Go struct with every field name, type
        # and order correct read cgid = 764504178688 instead of 178 on 5 records
        # out of 5, because encoding/binary does not reproduce C's internal
        # padding; 29 of 64 declared fields shift that way).
        record_btf: RECORD_BTF,
        # The consumer DSL's vocabulary and the rule by which `to_span` resolves.
        # typed_channels lists the ids for which `on_emit :<id>` is a typed consumer;
        # any other id is a named event.
        consumer_dsl: { typed_channels: typed_record_channel_ids, verbs: CONSUMER_DSL },
        # The `param` surface: how a probe is narrowed WITHOUT
        # being rewritten. A probe's own parameters are per-file and live in
        # `spinel-ebpf describe`; this is the vocabulary.
        runtime_params: RUNTIME_PARAMS,
        # The `filter_by` surface: one declaration that narrows
        # every handler in the unit. Sits next to runtime_params because it is the
        # same .rodata mechanism with a fixed vocabulary instead of user names.
        common_filter: COMMON_FILTER,
        # The `keep_if` surface: the userspace half. Placed
        # immediately after common_filter because the first thing a reader (or a
        # model) has to decide is which of the two it is holding, and
        # consumer_filter.line is the answer.
        consumer_filter: CONSUMER_FILTER,
      }
    end

    # The affordance document as pretty-printed JSON.
    def affordance_json
      require "json"
      JSON.pretty_generate(affordance)
    end

    # --- the required-set queries ---

    # Given the set of builtin names in use, return the missing counterpart of each
    # required-set contract.
    # Returns: [ { name:, mode:, present: [...], missing: [...], why: }, ... ]
    # A satisfied set is omitted. Both the compile-time check and the affordances
    # use this.
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
