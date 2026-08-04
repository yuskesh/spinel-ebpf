/* loader_contract.h -- the codegen <-> loader seam, declared once.
 *
 * The generated .bpf.c and the generated loader (bin/spinel-ebpf's build_glue_c
 * heredoc) share a vocabulary: map names, program-name prefixes, ELF section
 * names, .rodata symbol prefixes, the width of a record the loader moves, and
 * the rule by which it assigns an index. Historically every one of those was an
 * independent literal in up to three files across two languages, and NOTHING
 * compiled the loader, so a disagreement was invisible. Four deliberate
 * one-token corruptions were measured, and all four passed every gate:
 *
 *   the loader's slot counter starts at 1             -> every gate green,
 *     ICMP runs the TCP handler, exit 0, totals still add up
 *   the loader looks up one wrong token               -> gates green
 *   same, other map                                   -> gates green (push -2)
 *   the loader reserves 4 bytes where the callback reads 8
 *     -> gates green, the callback FIRES, the count is right,
 *        and only the VALUE is silently zero
 *
 * This file is the join. It is the same move record_schema.h made for ringbuf
 * record layout and probe_ctx_schema.h made for the probe context: the shared
 * thing becomes data, the consumers are generated from it, and a gate compares
 * what is declared against the parties that already publish the same fact
 * independently.
 *
 * --- What is single-sourced, and what is only mirrored ---
 *
 * TRULY SINGLE-SOURCED: the loader half. tools/gen_loader_contract.c emits
 * src/spinel_ebpf/loader_contract_gen.rb and build_glue_c interpolates those
 * constants, so the four measured drifts are no longer WRITABLE in the glue --
 * there is no literal there to mistype, and strncmp's length is computed from
 * the token instead of typed next to it.
 *
 * MIRRORED + GATED: the producer half. A BPF map is declared as a C IDENTIFIER
 * (`struct {...} bpf_user_cmds SEC(".maps");`) inside a templates/ .template.c file;
 * macro-izing that turns every map declaration into token pasting, and it would
 * change the emitted .bpf.c, which this work explicitly must not do. So the
 * producer keeps its literal and tools/loader_gate.rb compares this table
 * against the party that already publishes the producer side:
 *
 *   LC_AUTH_GOLDEN         a committed tests/golden .bpf.c -- the codegen's own
 *                          output, kept honest by tools/golden.rb + stage2
 *   LC_AUTH_RECORD_SCHEMA  record_schema.h's `map_suffix` (already declarative)
 *   LC_AUTH_ATTACH_KINDS   Capabilities::ATTACH_KINDS[:sec] (machine-readable)
 *   LC_AUTH_CODEGEN_C      a literal in spinel_ebpf_cc.c (scanned). Used ONLY for
 *                          the two .rodata prefixes. Measured: "the token is a
 *                          literal in the codegen" is a BAD proxy for "the
 *                          codegen emits it": three of the six emit-channel
 *                          suffixes (_pair_events, _emit3_events, _emit4_events)
 *                          never appear as literals -- two come from a template
 *                          and one is assembled with printf ("%s_emit%d_events").
 *                          Those are LC_AUTH_GOLDEN instead, i.e. checked against
 *                          the codegen output rather than its source.
 *   LC_AUTH_CODEGEN_RULE   not a token at all: a rule the codegen enforces, read
 *                          back by RUNNING the codegen (see LC_PROG_ARRAY_SLOT_BASE)
 *   LC_AUTH_NONE           ORPHAN: the loader looks this up and NOTHING produces
 *                          it. Declared, not hidden. The gate refuses a NEW
 *                          orphan and refuses an orphan that quietly gains a
 *                          producer.
 *
 * --- The five kinds of contract ---
 *
 * The census asked whether the four kinds named in the original plan (map names
 * / program-name prefixes / value widths / allocation rules) were all of them.
 * They were not. Sweeping every libbpf entry point build_glue_c actually calls
 * (the set is closed: every bpf_ and ring_buffer__ call in the heredoc was
 * enumerated) leaves five ways the loader can disagree with the kernel side:
 *
 *   1 NAME      the token itself                     -- `kind` below
 *   2 TYPE      the BPF map type the loader's API assumes (user_ring_buffer__new
 *               on a plain RINGBUF fails; the loader keys ringbuf discovery on
 *               bpf_map__type)                       -- `map_type`
 *   3 SHAPE     key/value size and layout            -- `key_ctype`/`value_ctype`/
 *                                                      `value_bytes` (the 4-vs-8
 *                                                      byte drift above)
 *   4 ALLOC     which index means which thing        -- `alloc` (the slot-base
 *                                                      drift above)
 *   5 ENCODING  what the bytes MEAN at the same size -- `encoding`
 *
 * The fifth is the one the plan did not name and it is the least visible: a
 * host-order vs network-order key, a value written as an fd that the kernel
 * stores as a socket pointer, a checksum folded in the kernel's native word
 * order. Same width, same type, same name -- and wrong. It is declared here
 * because it cannot be derived, and the gate can only check that a declaration
 * EXISTS where the shape alone does not determine the meaning; it cannot check
 * that the sentence is true. That limit is stated here rather than papered over.
 *
 * Capacity (max_entries) is deliberately NOT in the table: exceeding it makes
 * bpf_map_update_elem return an error the loader already prints, so it is loud,
 * and Capabilities::MAPS already publishes every max_entries with a
 * `when_full`. Duplicating it here would create the second author this file
 * exists to remove.
 *
 * --- Evolution ---
 *
 * There is no append-only rule here, unlike record_schema.h: nothing burns these
 * into a deployed artifact, and a token that stops existing SHOULD leave. What
 * the gate enforces instead is that the table stays EXHAUSTIVE -- it scans
 * build_glue_c for every name-carrying site and fails on a token that is not
 * declared. That is what keeps the census from rotting the way the prose table
 * in the original plan would have.
 */
#ifndef SPNL_LOADER_CONTRACT_H
#define SPNL_LOADER_CONTRACT_H

typedef enum {
  LC_MAP_NAME = 0,   /* exact map name   -- bpf_object__find_map_by_name(obj, "<t>") */
  LC_MAP_SUFFIX,     /* per-unit map     -- bpf_map__name(m) + strstr(nm, "<t>")      */
  LC_PROG_PREFIX,    /* prog-name prefix -- bpf_program__name(p) + strncmp(n,"<t>",L) */
  LC_SEC_NAME,       /* ELF section name -- bpf_program__section_name(p) + strcmp     */
  LC_RODATA_PREFIX,  /* .rodata symbol   -- skel->rodata-><t><name>                   */
  LC_PROG_SEPARATOR, /* separator INSIDE a prog name -- strstr(rest, "<t>")           */
} LcKind;

typedef enum {
  LC_AUTH_GOLDEN = 0,
  LC_AUTH_RECORD_SCHEMA,
  LC_AUTH_ATTACH_KINDS,
  LC_AUTH_CODEGEN_C,
  LC_AUTH_CODEGEN_RULE,
  LC_AUTH_NONE,
} LcAuthority;

typedef struct {
  const char *token;       /* the shared spelling, verbatim */
  const char *ruby_const;  /* the constant the generated Ruby publishes */
  LcKind      kind;
  LcAuthority authority;
  const char *witness;     /* golden basename / channel id / attach kind, or NULL */
  const char *map_type;    /* BPF_MAP_TYPE_<this>, or NULL when not a map */
  const char *key_ctype;   /* verbatim, as the producer spells it; NULL if none */
  const char *value_ctype;
  int         value_bytes; /* bytes the LOADER moves per record; 0 = it moves none */
  const char *alloc;       /* index allocation rule, or NULL when there is no index */
  const char *encoding;    /* meaning of the bytes where shape does not fix it */
  const char *note;
} LcEntry;

/* The loader writes the Nth `def xdp_tail__<name>`, in declaration
 * order, into spnl_prog_array[N]. The base is 0 and that is not checkable by
 * reading text: the only other party that knows it is the codegen's own
 * literal-slot bound (`slot < 0 || slot >= g_n_tail_targets`), which is why the
 * gate RUNS the codegen and reads the accepted range back out of it. */
#define LC_PROG_ARRAY_SLOT_BASE 0

static const LcEntry lc_entries[] = {
  /* ---- exact map names the loader finds by string --------------------------- */
  { "spnl_prog_array", "MAP_PROG_ARRAY", LC_MAP_NAME, LC_AUTH_GOLDEN,
    "142_tail_call_dispatch", "PROG_ARRAY", "__u32", "__u32", 4,
    "declaration order of `def xdp_tail__<name>`, base LC_PROG_ARRAY_SLOT_BASE",
    "the value is written as a program fd; the kernel stores the program",
    "A jump into an unpopulated slot FALLS THROUGH silently, so an off-by-one "
    "here is not an error, it is a different program running." },

  { "bpf_blocklist", "MAP_BLOCKLIST", LC_MAP_NAME, LC_AUTH_GOLDEN,
    "31_tc_blocklist", "HASH", "__u32", "__u8", 1, NULL,
    "key is an IPv4 address in HOST order (the BPF side converts, not the loader)",
    "sp_bpf_blocklist_add/del." },

  { "bpf_cidr_block", "MAP_CIDR_BLOCK", LC_MAP_NAME, LC_AUTH_GOLDEN,
    "57_cidr_blocklist", "LPM_TRIE", "struct spnl_cidr_key", "__u8", 1, NULL,
    "key.data[0..3] is the IPv4 address most-significant byte first, which is "
    "NOT the host order the same loader passes to bpf_blocklist",
    "LPM_TRIE keys are a prefixlen plus big-endian bytes by kernel rule." },

  { "bpf_user_cmds", "MAP_USER_CMDS", LC_MAP_NAME, LC_AUTH_GOLDEN,
    "143_user_ringbuf_channel", "USER_RINGBUF", NULL, "__s64", 8, NULL,
    "one record is exactly one __s64, FIFO; a short record makes bpf_dynptr_read "
    "return -E2BIG and the callback observe zero",
    "Reserving 4 here is silent at run time -- the callback fires, the count "
    "is right, and only the value is 0." },

  { "bpf_worker_socks", "MAP_WORKER_SOCKS", LC_MAP_NAME, LC_AUTH_GOLDEN,
    "168_reuseport_select", "REUSEPORT_SOCKARRAY", "__u32", "__u64", 8,
    "worker index chosen by the forking userspace, not by the codegen",
    "the value is written as a listen fd; the kernel stores the socket it names",
    "sp_bpf_reuseport_register." },

  { "bpf_stacks", "MAP_STACKS", LC_MAP_NAME, LC_AUTH_GOLDEN,
    "48_stack_trace", "STACK_TRACE", "__u32", NULL, 0, NULL, NULL,
    "value_ctype is deliberately NULL: the producer spells the value "
    "`127 * sizeof(__u64)` and the loader never reads it -- only the NAME travels, "
    "runtime (spnl_dump_stack, the offcpu drain, the request-tree push)." },

  { "bpf_hist_keyed", "MAP_HIST_KEYED", LC_MAP_NAME, LC_AUTH_GOLDEN,
    "42_keyed_hist", "HASH", "__u64", "struct spnl_hist_struct", 0, NULL, NULL,
    "Same as bpf_stacks: the name travels to the runtime as an argument." },

  /* ---- ORPHANS: the loader looks these up and no producer exists ------------- *
   * The kernel_cache maps were implemented in the retired Ruby generator
   * (src/spinel_ebpf/codegen_bpf.rb) and never ported to the production C
   * codegen, but sp_kc_set() is still emitted into every glue that declares a
   * kernel_cache path. The lookup returns NULL and sp_kc_set returns -2, so this
   * is loud at run time rather than silent -- which is why it is recorded here
   * instead of deleting the glue (that is a surface decision, not a seam one).
   * The gate refuses a new orphan, and refuses an orphan that gains a producer
   * without the declaration moving. */
  { "bpf_kc_resp", "MAP_KC_RESP", LC_MAP_NAME, LC_AUTH_NONE,
    NULL, "ARRAY", "__u32", NULL, 256, "kernel_cache declaration order, base 0",
    "the value is a fixed response body of exactly value_bytes bytes, zero "
    "padded; the retired generator called the same number KERNEL_CACHE_RESP_CAP",
    "Retired Ruby generator only. No production C codegen emits this map "
    "(measured: 0 hits in spinel_ebpf_cc.c, in templates, and in all goldens)." },

  { "bpf_kc_resp_len", "MAP_KC_RESP_LEN", LC_MAP_NAME, LC_AUTH_NONE,
    NULL, "ARRAY", "__u32", "__u32", 4, "same slot as bpf_kc_resp", NULL,
    "Retired Ruby generator only. No production C codegen emits this map." },

  { "bpf_kc_resp_csum", "MAP_KC_RESP_CSUM", LC_MAP_NAME, LC_AUTH_NONE,
    NULL, "ARRAY", "__u32", "__u32", 4, "same slot as bpf_kc_resp",
    "a 16-bit-folded partial checksum computed over 16-bit words in the KERNEL's "
    "native (little-endian on arm64) order -- the loader must fold the same way",
    "Retired Ruby generator only. No production C codegen emits this map. The "
    "clearest instance of kind 5: right name, right type, right width, and "
    "wrong if the word order disagrees." },

  /* ---- per-unit maps the loader finds by suffix ------------------------------ */
  { "_events", "SUFFIX_EMIT_INT", LC_MAP_SUFFIX, LC_AUTH_GOLDEN,
    "103_emit_parent_path", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The `spnl_emit` channel, and also the loose end of every other suffix: the "
    "loader's ringbuf sweep tests it LAST and only after excluding the specific "
    "ones." },
  { "_str_events", "SUFFIX_EMIT_STR", LC_MAP_SUFFIX, LC_AUTH_GOLDEN,
    "103_emit_parent_path", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The `spnl_emit_str` channel." },
  { "_pair_events", "SUFFIX_EMIT_PAIR", LC_MAP_SUFFIX, LC_AUTH_GOLDEN,
    "137_sock_accessors", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The `spnl_emit_pair` channel." },
  { "_emit3_events", "SUFFIX_EMIT3", LC_MAP_SUFFIX, LC_AUTH_GOLDEN,
    "36_emit_n_tuple", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The `spnl_emit3` channel." },
  { "_emit4_events", "SUFFIX_EMIT4", LC_MAP_SUFFIX, LC_AUTH_GOLDEN,
    "137_sock_accessors", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The `spnl_emit4` channel." },
  { "_lost", "SUFFIX_LOST", LC_MAP_SUFFIX, LC_AUTH_GOLDEN,
    "105_emit_dns", "PERCPU_ARRAY", NULL, NULL, 0, NULL, NULL,
    "The per-channel ring-full counter. Matched at the END of the name "
    "(`_mn + _ml - 5`), not anywhere in it, so the length 5 is part of the "
    "contract and is generated from the token." },

  /* The seven packed channels: record_schema.h already declares `map_suffix`,
   * so this table names the channel and the gate reads the spelling out of
   * record_schema_gen.json rather than restating it. */
  { "_dns_events", "SUFFIX_DNS", LC_MAP_SUFFIX, LC_AUTH_RECORD_SCHEMA,
    "dns", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The per-unit DNS-event channel." },
  { "_conn_events", "SUFFIX_CONN", LC_MAP_SUFFIX, LC_AUTH_RECORD_SCHEMA,
    "conn", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The per-unit connect-event channel." },
  { "_l7_events", "SUFFIX_L7", LC_MAP_SUFFIX, LC_AUTH_RECORD_SCHEMA,
    "l7", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The per-unit L7 latency-event channel." },
  { "_http_events", "SUFFIX_HTTP", LC_MAP_SUFFIX, LC_AUTH_RECORD_SCHEMA,
    "http", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The per-unit HTTP L7 RED channel." },
  { "_redis_events", "SUFFIX_REDIS", LC_MAP_SUFFIX, LC_AUTH_RECORD_SCHEMA,
    "redis", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The per-unit Redis L7 RED channel." },
  { "_offcpu_events", "SUFFIX_OFFCPU", LC_MAP_SUFFIX, LC_AUTH_RECORD_SCHEMA,
    "offcpu", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The per-unit off-CPU L7 correlation channel." },
  { "_l7stream_events", "SUFFIX_L7STREAM", LC_MAP_SUFFIX, LC_AUTH_RECORD_SCHEMA,
    "l7stream", "RINGBUF", NULL, NULL, 0, NULL, NULL,
    "The per-unit sock-keyed L7 stream channel, and the one channel the loader "
    "reads with its own C text rather than the runtime's mirror "
    "(record_schema.h calls that out as outside its scope)." },

  /* ---- program-name prefixes the loader keys on ----------------------------- *
   * The strncmp length is NOT written here: gen_loader_contract.c computes it
   * from the token, so `strncmp(name, "xdp_tail__", 9)` is unwritable. */
  { "xdp_tail__", "PREFIX_XDP_TAIL", LC_PROG_PREFIX, LC_AUTH_GOLDEN,
    "142_tail_call_dispatch", NULL, NULL, NULL, 0, NULL, NULL,
    "Used for OPPOSITE decisions in two places: skip auto-attach, and populate "
    "the PROG_ARRAY. A prefix that matched only one of the two would attach "
    "tail-call targets to the interface." },
  { "uprobe__", "PREFIX_UPROBE", LC_PROG_PREFIX, LC_AUTH_GOLDEN,
    "109_ssl_http_l7", NULL, NULL, NULL, 0, NULL, NULL,
    "Program-name prefix for uprobe handlers." },
  { "uretprobe__", "PREFIX_URETPROBE", LC_PROG_PREFIX, LC_AUTH_GOLDEN,
    "109_ssl_http_l7", NULL, NULL, NULL, 0, NULL, NULL,
    "Program-name prefix for uretprobe handlers." },
  { "usdt__", "PREFIX_USDT", LC_PROG_PREFIX, LC_AUTH_GOLDEN,
    "39_usdt_basic", NULL, NULL, NULL, 0, NULL, NULL,
    "The loader splits the REST of the name on `__` into provider/probe, "
    "so the prefix length also fixes where that split starts." },
  { "spnl_timer_arm_", "PREFIX_TIMER_ARM", LC_PROG_PREFIX, LC_AUTH_GOLDEN,
    "145_timer_event_loop", NULL, NULL, NULL, 0, NULL, NULL,
    "The loader runs these once with bpf_prog_test_run to arm the timer; "
    "missing them means the probe loads and never ticks." },

/* ---- separators INSIDE a program name ------------------------------------ *
 * Found by the gate's coverage scan, not by the hand census this table started
 * from: the loader splits what follows `usdt__` on a second `__` to recover
 * provider and probe. Same class of shared token as a prefix -- the codegen
 * chooses the spelling when it synthesises the program name -- and invisible to
 * a grep for map names, which is the whole reason the coverage direction exists. */
{ "__", "SEPARATOR_USDT", LC_PROG_SEPARATOR, LC_AUTH_GOLDEN,
  "39_usdt_basic", NULL, NULL, NULL, 0, NULL, NULL,
  "`usdt__<provider>__<probe>`: the loader takes the FIRST `__` after the "
  "prefix, so a provider containing `__` is not representable -- which is why "
  "the loader carries an explicit 'malformed USDT prog name' diagnostic." },

  /* ---- ELF section names the loader compares -------------------------------- *
   * These are libbpf's vocabulary on both sides, but they are still shared: the
   * codegen chooses the SEC string and the loader dispatches on it. The party
   * that already publishes them machine-readably is Capabilities::ATTACH_KINDS,
   * so `witness` is the attach kind and the gate reads :sec from it. */
  { "uprobe", "SEC_UPROBE", LC_SEC_NAME, LC_AUTH_ATTACH_KINDS,
    "uprobe", NULL, NULL, NULL, 0, NULL, NULL,
    "Section name for uprobe attach." },
  { "uretprobe", "SEC_URETPROBE", LC_SEC_NAME, LC_AUTH_ATTACH_KINDS,
    "uretprobe", NULL, NULL, NULL, 0, NULL, NULL,
    "Section name for uretprobe attach." },
  { "usdt", "SEC_USDT", LC_SEC_NAME, LC_AUTH_ATTACH_KINDS,
    "usdt", NULL, NULL, NULL, 0, NULL, NULL,
    "Section name for USDT attach." },
  { "perf_event", "SEC_PERF_EVENT", LC_SEC_NAME, LC_AUTH_ATTACH_KINDS,
    "perf_event", NULL, NULL, NULL, 0, NULL, NULL,
    "Section name for perf_event attach." },
  { "kprobe.multi", "SEC_KPROBE_MULTI", LC_SEC_NAME, LC_AUTH_ATTACH_KINDS,
    "kprobe_multi", NULL, NULL, NULL, 0, NULL, NULL,
    "Section name for multi-symbol kprobe attach." },

  /* ---- .rodata symbol prefixes ---------------------------------------------- *
   * The loader writes skel->rodata-><sym> between __open() and __load(). The
   * symbol is built in Ruby (Param#c_symbol / FilterKey#c_symbol) and emitted in
   * C; the shared part is the prefix. Unlike everything else here this one IS
   * compile-checked -- but only in a build nobody's gate runs. */
  { "spnl_param_", "PREFIX_RODATA_PARAM", LC_RODATA_PREFIX, LC_AUTH_CODEGEN_C,
    "126_runtime_param", NULL, NULL, "volatile const __s64", 8, NULL, NULL,
    "One symbol per declared runtime parameter. Frozen by BPF_MAP_FREEZE at "
    "load; the assignment must land in the gap between __open() and __load()." },
  { "spnl_filter_", "PREFIX_RODATA_FILTER", LC_RODATA_PREFIX, LC_AUTH_CODEGEN_C,
    "129_common_filter", NULL, NULL, "volatile const __s64", 8, NULL,
    "unset means 0 for pid/tid/cgroup_id but -1 for uid/gid, so that uid 0 "
    "stays selectable -- a shape-identical value with a different meaning",
    "One symbol per declared in-kernel common filter key." },
};

#define LC_N_ENTRIES ((int)(sizeof(lc_entries) / sizeof(lc_entries[0])))

#endif /* SPNL_LOADER_CONTRACT_H */
