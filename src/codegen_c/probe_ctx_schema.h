/* probe_ctx_schema.h -- declarative probe context + attach-point contract.
 *
 * A probe that observes an RTOS event needs to see something about that event.
 * The question this file answers is *what*, in a way that four parties agree on
 * without any of them re-typing it:
 *
 *   the M-core dispatcher   fills a frame before calling the probe
 *   the M-core runtime      answers ctx_field(<id>) out of that frame
 *   the capability table    publishes which fields each attach point provides
 *   the Linux installer     rejects a probe that asks for a field not published
 *
 * Historically that is four hand-written copies of one list. Here the list is
 * data, exactly as src/codegen_c/record_schema.h made the ringbuf record layout
 * data, and tools/gen_probe_ctx.c derives all four from it.
 *
 * --- Why a flat frame instead of a context pointer ---
 *
 * The probe never receives a pointer. The dispatcher fills a frame of 64-bit
 * slots indexed by field id, and `ctx_field(<id>)` reads that frame after a
 * bounds check and a membership check. Two consequences, both deliberate:
 *
 *   The native blob holds no pointer into RTOS memory, so "probe reads a stale
 *   thread struct" is not a bug that can be written. Memory safety for context
 *   access lives in one helper, not in every probe.
 *
 *   The field set becomes a vocabulary the capability table can speak. An
 *   installer can answer "thread.switched_in exists, but thread.previous.id is
 *   not published here" instead of only "that attach point exists".
 *
 * The cost is that the dispatcher fills every field of an attach point whether
 * the probe reads it or not, and that the frame is sized by the *global* field
 * count. Both are fine at this size and both are measurable later; compacting
 * the frame per schema is a change to the generator, not to the contract.
 *
 * --- Three namespaces (U0) ---
 *
 * FIELD ids   1..N, dense, assigned by position in pc_fields[]. 0 means invalid.
 * ATTACH ids  explicit, with reserved ranges so the two classes of attach point
 *             never collide:
 *               0x0001-0x0FFF  RTOS-provided (rides a Zephyr tracing hook)
 *               0x1000-0x1FFF  application-declared static probe points
 *               0xF000-0xFFFF  reserved for experiments; never published
 * SLOT states the slot lifecycle. Declared here so the Linux installer and the
 *             M-core loader name the same states.
 *
 * --- Evolution rule ---
 *
 * APPEND-ONLY, as in record_schema.h, and tools/probe_ctx_gate.rb makes it a
 * gate rather than a convention. A field id is burned into every blob that ever
 * called ctx_field on it, so reusing or renumbering one silently changes what an
 * old probe reads. Removing a field from an attach point breaks probes that were
 * admitted against it. Both are refused by the gate; appending is free.
 */
#ifndef SPNL_PROBE_CTX_SCHEMA_H
#define SPNL_PROBE_CTX_SCHEMA_H

#include <stddef.h>   /* NULL, for the field-list terminators below */

/* One context field.
 *
 * `ctype` is how the value is spelled where the dispatcher reads it from Zephyr,
 * and exists so the generated filler casts explicitly rather than relying on the
 * frame's uint64_t to do it silently. Signedness matters: a priority is a signed
 * int8_t in Zephyr and a probe comparing `prio < 0` must see that, so the
 * generator sign-extends when `is_signed`.
 *
 * `expose` is the Ruby-visible type. v0 has only "int": ctx_field returns one
 * 64-bit value, and a string-valued context field (a thread name, say) would
 * need a different helper shape. Declaring the axis now keeps that door open
 * without pretending it is implemented. */
typedef struct {
  const char *name;      /* dotted, manifest- and Ruby-visible: "thread.current.id" */
  const char *ctype;     /* source type at the dispatcher, verbatim */
  int         size;      /* sizeof(ctype), bytes */
  int         is_signed; /* 1 -> sign-extend into the frame slot */
  const char *expose;    /* "int" (v0). NULL = declared but not readable yet */
  const char *note;      /* provenance: where the dispatcher gets it */
} PcField;

/* One attach point.
 *
 * `exec_class` is load-bearing, not documentation. It says what the probe is
 * running inside, and both the cycle-budget policy and the fault policy read it:
 *   "THREAD"        ordinary thread context; preemptible
 *   "SCHED_LOCKED"  scheduler or irq lock held; a long probe delays every thread
 *   "ISR"           interrupt context; a long probe delays every deadline
 * When it is not yet measured, declare the strictest one that could apply. An
 * attach point that turns out to be cheaper can be relaxed later (additive);
 * discovering that a published THREAD point is really ISR is a breaking change.
 *
 * `max_cycle_budget` is the ceiling this attach point admits, in the platform's
 * calibrated cycle units. The installer refuses a probe whose computed budget
 * exceeds it. Raising it is additive; lowering it can evict admitted probes, so
 * the gate treats a decrease as breaking.
 *
 * `kconfig` is the symbol that decides whether this point is *built in*. Zephyr's
 * hook inventory is not the same thing as the firmware's exported attach set: a
 * hook that exists upstream may simply not be compiled into this build. The capability table publishes only what was compiled, and this names the
 * switch, so "why is that attach point missing" has an answer in the schema.
 *
 * `fields` is a NULL-terminated list of field names, and it is the source of the
 * per-attach bitmap the capability table carries. */
typedef struct {
  const char *name;             /* "thread.switched_in" */
  unsigned    attach_id;        /* stable; see the reserved ranges above */
  const char *exec_class;       /* "THREAD" | "SCHED_LOCKED" | "ISR" */
  unsigned    max_cycle_budget; /* calibrated cycle units; 0 = not admissible */
  const char *hook;             /* the Zephyr hook it rides, for provenance */
  const char *kconfig;          /* the symbol that builds it in */
  const char *const *fields;    /* NULL-terminated field names */
  const char *note;
} PcAttach;

/* ------------------------------------------------------------------------- *
 * Fields. Append only; ids are positions, so nothing above a new entry moves.
 * ------------------------------------------------------------------------- */
static const PcField pc_fields[] = {
  { "thread.current.id",       "uint32_t", 4, 0, "int",
    "k_thread identity of the thread being switched in; the dispatcher passes "
    "the thread's numeric id, never its pointer" },
  { "thread.current.priority", "int8_t",   1, 1, "int",
    "Zephyr priority of that thread; negative values are cooperative, so this "
    "field is sign-extended into the frame" },
  { "timestamp.cycles",        "uint64_t", 8, 0, "int",
    "free-running cycle counter read by the dispatcher at hook entry, before "
    "the probe runs, so every field of one event shares one instant" },
};

/* ------------------------------------------------------------------------- *
 * Attach points.
 * ------------------------------------------------------------------------- */

/* v0 opens `thread.switched_in` and nothing else. One attach point is enough to
 * exercise all four undecided things at once -- the shape of the context, memory
 * safety, the cost bound, and capability negotiation -- and the several hundred
 * remaining Zephyr hooks cost nothing to add once those are settled.
 *
 * `switched_out` is deliberately absent. Zephyr fires the two hooks separately
 * and the current-thread state changes between them, so a `THREAD_SWITCH
 * {previous, next}` event is something the dispatcher would have to *synthesise*
 * rather than merely forward. That is a real design decision, not an omission,
 * and it is left until there is a probe that needs the correlation. */
static const char *const pc_at_thread_switched_in_fields[] = {
  "thread.current.id",
  "thread.current.priority",
  "timestamp.cycles",
  NULL,
};

static const PcAttach pc_attaches[] = {
  { "thread.switched_in", 0x0001, "SCHED_LOCKED", 500,
    "sys_port_trace_k_thread_switched_in",
    "CONFIG_OBS_ATTACH_THREAD_SWITCHED_IN",
    pc_at_thread_switched_in_fields,
    "Zephyr calls this from the scheduler with interrupts locked on the paths "
    "measured so far, so it is declared SCHED_LOCKED -- the stricter of the two "
    "plausible classes. Measuring it may allow relaxing to THREAD later, which is "
    "additive, and discovering the reverse would be a breaking change, which is "
    "why the strict class is the default" },
};

/* ------------------------------------------------------------------------- *
 * Slot lifecycle. Declared here so the installer and the loader name the same
 * states; the transitions live in the runtime.
 * ------------------------------------------------------------------------- */
typedef struct {
  const char *name;
  unsigned    value;
  const char *note;
} PcSlotState;

static const PcSlotState pc_slot_states[] = {
  { "EMPTY",       0, "no blob; IVARS and code slot are zeroed" },
  { "STAGED",      1, "blob written to staging, nothing validated yet" },
  { "READY",       2, "manifest, capability binding and cost admitted" },
  { "ACTIVE",      3, "dispatcher may call it" },
  { "QUIESCING",   4, "dispatcher will not call it; calls already entered may run" },
  { "DETACHED",    5, "active_calls == 0" },
  { "RECLAIMABLE", 6, "ring drained and acknowledged; nothing left to read" },
};

#endif /* SPNL_PROBE_CTX_SCHEMA_H */
