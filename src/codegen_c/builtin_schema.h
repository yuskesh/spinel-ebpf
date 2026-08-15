/* builtin_schema.h -- the builtin vocabulary, first axis: declared arity.
 *
 * Every advertised builtin was probed with one surplus argument appended to its
 * own affordance example. 157 died in their handlers' inline checks; the 38
 * below COMPILED BYTE-IDENTICALLY to the correct call -- the surplus argument
 * silently vanished. That is the worst failure shape this project knows: the
 * mistake only ever shows up as silence. `pid(tgid)` or `stack_id(1)` reads as
 * if the argument meant something, compiles, loads, verifies, and answers the
 * no-argument question. This table is the fold: cc_require_declared_arity()
 * checks it at the CallNode entry of both lowering functions, BEFORE any
 * handler matches.
 *
 * SCOPE RULE -- the table deliberately holds ONLY the builtins whose handlers do
 * not enforce their own arity (the measured-silent set). The other 157 keep
 * their inline checks: those die with richer, call-shaped messages ("udp_dport/
 * udp_daddr expect two arguments: the socket and the message (e.g. ...)"), and
 * a central generic check firing first would replace actionable errors with a
 * bland one. When a handler grows its own check, its row here becomes dead and
 * should move out; when a new builtin's handler skips the check, the arity
 * section of tools/affordance_gate.rb (`--section arity`) fails until a row
 * lands here.
 *
 * Lockstep: each row's arity must equal the Ruby side's declared signature
 * (Capabilities.signature_for) -- tests/spinel_ebpf/capabilities_test.rb parses
 * this header and compares, the same pattern the other generated tables use.
 */
#ifndef SPNL_BUILTIN_SCHEMA_H
#define SPNL_BUILTIN_SCHEMA_H

#include <string.h>   /* cc_builtin_on_target: strcmp */

typedef struct {
  const char *name;
  int arity;        /* exact -- these builtins have no optional arguments */
} CcBuiltinArity;

static const CcBuiltinArity cc_declared_arity[] = {
  /* current-task / kernel-context readers: the value comes from the hook
   * context, never from an argument. */
  { "ktime_ns", 0 }, { "pid", 0 }, { "tgid", 0 }, { "tid", 0 },
  { "cpu_id", 0 }, { "uid", 0 }, { "gid", 0 }, { "ppid", 0 },
  { "cgroup_id", 0 }, { "comm_hash", 0 }, { "emit_comm", 0 },
  { "cap_effective", 0 },
  /* latency pair -- the KEYED forms lat_start(key)/lat_end(key) are different
   * builtins with their own handler checks. */
  { "latency_start", 0 }, { "latency_end", 0 },
  /* stack ids */
  { "stack_id", 0 }, { "user_stack_id", 0 },
  /* queue/stack pops -- push takes a value, pop takes nothing. */
  { "queue_pop", 0 }, { "fifo_pop", 0 }, { "lifo_pop", 0 },
  /* per-task storage read */
  { "task_load", 0 },
  /* sock_addr ctx readers */
  { "sock_addr_ip4", 0 }, { "sock_addr_port", 0 },
  /* packet header readers -- all read ctx, arity 0. The chain spellings
   * (`pkt.len`) have a receiver and are exempt from this check by construction
   * (a builtin call is a bare call). */
  { "pkt_len", 0 }, { "pkt_eth_proto", 0 },
  { "pkt_ip4_src", 0 }, { "pkt_ip4_dst", 0 },
  { "pkt_ip6_src_hi", 0 }, { "pkt_ip6_src_lo", 0 },
  { "pkt_ip6_dst_hi", 0 }, { "pkt_ip6_dst_lo", 0 },
  { "pkt_l4_proto", 0 }, { "pkt_l4_sport", 0 }, { "pkt_l4_dport", 0 },
  { "pkt_l4_payload_len", 0 },
  { "pkt_tcp_flags", 0 }, { "pkt_tcp_seq", 0 }, { "pkt_tcp_ack", 0 },
  /* conntrack delete: exactly the flow name -- the handler checked "at least
   * one" and ignored the rest (measured). */
  { "flow_del", 1 },
};
#define CC_N_DECLARED_ARITY ((int)(sizeof(cc_declared_arity) / sizeof(cc_declared_arity[0])))

/* --- per-target existence ---------------------------------------------------
 *
 * "builtin X exists on target Y" is a fact two consumers used to hold in their
 * own spelling: target_profile.rb's call_allowlist arrays, and the C backstop
 * (amp_scan_supported) as an inline strcmp chain. One fact with several
 * consumers is exactly what belongs in a single declaration, so it is declared
 * once here and everything else derives:
 *   - the backstop calls cc_builtin_on_target()
 *   - target_profile.rb reads the generated JSON (make -C src/codegen_c
 *     builtin-schema) for its allowlists
 *   - the builtin existence coverage subtracts the declared non-linux names
 *     instead of pattern-matching them out of the source
 *
 * SCOPE RULE -- rows exist only where the target set differs from the default
 * {linux}: the overwhelming majority of the vocabulary is linux-only and listing
 * it would bury the exceptions. A builtin absent from this table is linux-only
 * by definition (cc_builtin_on_target's else arm).
 * The prose halves (supported_summary, the backstop die text) stay in their
 * consumers -- they are not shared facts; the die-message/supported_summary
 * lockstep lives in tests/spinel_ebpf/target_profile_test.rb as before. */
#define CC_TGT_LINUX     1u
#define CC_TGT_AMP       2u   /* the microcontroller (M-core) target */

typedef struct {
  const char *name;
  unsigned targets;   /* OR of CC_TGT_*; never 0 */
} CcBuiltinTargets;

static const CcBuiltinTargets cc_builtin_targets[] = {
  /* linux builtins that ALSO lower on the M-core (amp_emit / amp_ktime) */
  { "spnl_emit",     CC_TGT_LINUX | CC_TGT_AMP },
  { "ktime_ns",      CC_TGT_LINUX | CC_TGT_AMP },
};
#define CC_N_BUILTIN_TARGETS ((int)(sizeof(cc_builtin_targets) / sizeof(cc_builtin_targets[0])))

static inline int cc_builtin_on_target(const char *name, unsigned tgt) {
  for (int i = 0; i < CC_N_BUILTIN_TARGETS; i++)
    if (!strcmp(name, cc_builtin_targets[i].name))
      return (cc_builtin_targets[i].targets & tgt) != 0;
  return tgt == CC_TGT_LINUX;   /* default: linux-only */
}

/* --- per-target SYNTAX support ----------------------------------------------
 *
 * `times` is not a builtin (it is iterator syntax, owned by the SYNTAX
 * vocabulary and excluded from the builtin existence coverage for exactly that
 * reason), but WHERE a construct lowers is still a per-target fact with several
 * consumers: a restricted target's scan must not die on a construct it can
 * lower, and the Ruby partition's allowlist check must not count that construct
 * as an unsupported call there. Same shape as cc_builtin_targets, kept as a
 * SEPARATE table so syntax never pollutes the builtin vocabulary.
 *
 * The table is EMPTY in this tree, and that is a fact rather than an omission.
 * A row is only meaningful for a target that HAS an allowlist to be exempt
 * from: linux has none (a plain {linux} row would be dead by construction, and
 * the generator refuses one), and the single restricted target here, AMP v0,
 * has no loop lowering at all -- so amp refusing `n.times` is correct behaviour,
 * not a missing row. What is carried is the mechanism: adding a construct to a
 * restricted target is one row, and the three consumers below follow it.
 * (An empty array is a compiler extension rather than strict ISO C; both
 * toolchains this builds with accept it, and every consumer loops
 * `i < CC_N_SYNTAX_TARGETS` and so never reads an element.) */
typedef struct {
  const char *name;
  unsigned targets;
} CcSyntaxTargets;

static const CcSyntaxTargets cc_syntax_targets[] = {};
#define CC_N_SYNTAX_TARGETS ((int)(sizeof(cc_syntax_targets) / sizeof(cc_syntax_targets[0])))

static inline int cc_syntax_on_target(const char *name, unsigned tgt) {
  for (int i = 0; i < CC_N_SYNTAX_TARGETS; i++)
    if (!strcmp(name, cc_syntax_targets[i].name))
      return (cc_syntax_targets[i].targets & tgt) != 0;
  return 0;   /* not a declared syntax name */
}

#endif /* SPNL_BUILTIN_SCHEMA_H */
