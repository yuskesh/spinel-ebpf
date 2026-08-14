/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * amp_check.c -- a bytecode checker run before a program is shipped to the
 * real-time core. The verification is decoupled from execution.
 *
 * That core has no verifier of its own. Before deployment this checker inspects the
 * bytecode (the .text of a .bpf.o) on the build host or the application core, and
 * only what passes is compiled ahead of time into a slot on the real-time core.
 * The loader there still gates on magic, ABI version and length, so there are two
 * lines of defence. What is enforced here:
 *   (1) A helper allowlist: a call may only name an amp helper id (1 = emit,
 *       2 = ktime). Any other id, and any local call, is rejected.
 *   (2) Bounded control flow: a backward branch is rejected, so there are no loops
 *       and execution is finite. The generated programs are loop-free, so this
 *       produces no false rejections.
 *   (3) Memory range: every load and store must resolve within the fixed ABI
 *       region. Because the ABI is fixed, what would otherwise be a range analysis
 *       degenerates into a constant range check: an instance variable is addressed
 *       by loading a fixed address into a base register and then indexing off it,
 *       so it is enough to check that the base immediate plus the offset falls
 *       inside the instance-variable region. BPF keeps memory-base immediates and
 *       data constants in separate opcodes, so no dataflow analysis is needed and
 *       there are no false positives. Stack-relative access is allowed; a load or
 *       store through any other, unverified base is rejected. Calls are covered by
 *       the allowlist above, and the ahead-of-time compiler bakes each id to a
 *       fixed helper slot, so both dimensions -- the data region and the helper
 *       slots -- are closed.
 *   (4) Deny by default: an instruction this walk does not recognise is rejected
 *       rather than waved through. The earlier shape of this checker only rejected
 *       what it had a rule for, which meant every future opcode -- and every
 *       opcode this walk simply forgot -- was permitted by omission. On a core with
 *       no verifier that is the wrong direction to fail in. Widening the subset is
 *       now a deliberate edit here, and the rejection message says which opcode.
 *   (5) A static cost bound: the programs are straight-line (2 forbids loops), so
 *       an upper bound follows from counting instructions. Each class carries a
 *       weight and each helper a fixed charge, and a program whose total exceeds
 *       --max-cost is rejected before it ships. The units are not cycles: they are
 *       pre-calibration weights, and turning them into a time budget for a
 *       particular core is a separate, measured step. The split is deliberate --
 *       the probe author declares what they can accept, the toolchain computes
 *       what the program costs, and neither number is inferred from the other.
 *
 * usage: amp_check <prog.bpf.o> [--max-cost N] [--cost-only]
 *        (exit 0 = ok, 1 = reject, 2 = usage/IO)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>

#include "spnl/amp_abi.h"   /* AMP_IVARS_BASE / AMP_IVARS_SIZE (fixed ABI) */

/* The allowlist of amp helper ids. Extend it when the helper set grows. */
static int amp_helper_allowed(int32_t id) { return id == 1 || id == 2; }

/* The frame the ahead-of-time compiler gives a program. Stack-relative access was
 * previously allowed unconditionally, which let a program read or write past its
 * own frame into whatever the firmware had below it -- the one hole left in an
 * otherwise closed memory story. */
#define AMP_STACK_BYTES 512

/* Static cost weights, in pre-calibration units. Deliberately coarse: the point is
 * to separate "this program is unbounded" from "this program is small", not to
 * predict a cycle count. Memory costs more than arithmetic because it can miss;
 * a branch costs more than an add because it can mispredict. */
#define COST_ALU     1u
#define COST_BRANCH  2u
#define COST_MEM     4u
#define COST_LDDW    2u

/* Helpers are charged as a unit, since their bodies are not in this bytecode.
 * The emit charge dominates: it writes a record, flushes it, and publishes an
 * index. Reading the time source is comparatively cheap. */
static unsigned amp_helper_cost(int32_t id) {
    switch (id) {
    case 1: return 60u;   /* emit: record write + cache flush + index publish */
    case 2: return 12u;   /* ktime: read the time source */
    default: return 0u;   /* unreachable: the allowlist rejects first */
    }
}

/* Register-immediate tracking (S4). known: 0=unknown, 1=constant, 2=stack(r10). */
struct regv { int known; uint64_t val; };

static int check_addr(const struct regv *base, int16_t off, size_t i, const char *how,
                      char *err, size_t errlen) {
    if (base->known == 2) {                         /* r10-relative = the program's own frame */
        if (off < -AMP_STACK_BYTES || off >= 0) {
            snprintf(err, errlen,
                     "insn %zu: %s at r10%+d is outside the program's %d-byte stack frame "
                     "[r10-%d, r10)", i, how, off, AMP_STACK_BYTES, AMP_STACK_BYTES);
            return -1;
        }
        return 0;
    }
    if (base->known == 1) {
        uint64_t addr = base->val + (uint64_t)(int64_t)off;
        if (addr >= (uint64_t)AMP_IVARS_BASE &&
            addr <  (uint64_t)AMP_IVARS_BASE + (uint64_t)AMP_IVARS_SIZE) {
            return 0;                               /* inside the ivar carveout: allow */
        }
        snprintf(err, errlen,
                 "insn %zu: %s at 0x%llx outside the fixed ABI ivar carveout "
                 "[0x%08x, 0x%08x)", i, how, (unsigned long long)addr,
                 (unsigned)AMP_IVARS_BASE, (unsigned)(AMP_IVARS_BASE + AMP_IVARS_SIZE));
        return -1;
    }
    snprintf(err, errlen,
             "insn %zu: %s via unverifiable (non-constant, non-stack) base register",
             i, how);
    return -1;
}

/* Check a BPF .text (array of 8-byte insns; LDDW is 16). Returns 0 ok, -1 reject. */
static int amp_check_text(const uint8_t *text, size_t len, unsigned *cost_out,
                          char *err, size_t errlen) {
    unsigned cost = 0;
    if (len % 8 != 0) { snprintf(err, errlen, ".text length %zu not a multiple of 8", len); return -1; }
    size_t n = len / 8;

    struct regv reg[11];
    for (int r = 0; r < 11; r++) reg[r] = (struct regv){0, 0};
    reg[10].known = 2;   /* r10 = read-only frame pointer (stack) */
    /* r1 = ctx pointer on entry: left unknown; amp handlers ignore ctx. */

    for (size_t i = 0; i < n; i++) {
        const uint8_t *insn = text + i * 8;
        uint8_t opcode = insn[0];
        uint8_t dst    = insn[1] & 0xf;
        uint8_t src    = (insn[1] >> 4) & 0xf;
        int16_t off    = (int16_t)(insn[2] | (insn[3] << 8));
        int32_t imm    = (int32_t)(insn[4] | (insn[5] << 8) | (insn[6] << 16) | ((uint32_t)insn[7] << 24));
        uint8_t cls    = opcode & 0x07;
        uint8_t mode   = opcode & 0xe0;

        if (opcode == 0x18) {   /* LDDW: 64-bit immediate load (2 insn slots) */
            uint64_t lo = (uint32_t)imm;
            uint64_t hi = (i + 1 < n)
                ? (uint32_t)(text[(i+1)*8+4] | (text[(i+1)*8+5] << 8) |
                             (text[(i+1)*8+6] << 16) | ((uint32_t)text[(i+1)*8+7] << 24)) : 0;
            if (dst < 11) reg[dst] = (struct regv){1, lo | (hi << 32)};
            cost += COST_LDDW;
            i++;
            continue;
        }
        if (opcode == 0x85) {   /* BPF_JMP | BPF_CALL */
            if (src == 1) { snprintf(err, errlen, "insn %zu: local/pseudo call not allowed (amp is 1 program = 1 function)", i); return -1; }
            if (!amp_helper_allowed(imm)) { snprintf(err, errlen, "insn %zu: call to disallowed helper id %d (allowed: 1=amp_emit, 2=amp_ktime)", i, imm); return -1; }
            for (int r = 0; r <= 5; r++) reg[r].known = 0;   /* r0=ret, r1-r5 clobbered */
            cost += amp_helper_cost(imm);
            continue;
        }
        if (opcode == 0x95) continue;   /* EXIT */

        /* Memory classes. Only BPF_MEM addressing is understood, and the range
         * check below is what makes it safe -- so an addressing mode this walk
         * cannot interpret has to be refused, not skipped. BPF_ATOMIC lands here:
         * while the default was permissive it fell straight through, and
         * `lock *(u64 *)(0xdeadbeef) += r2` was accepted. */
        if (cls == 0x00 || cls == 0x01 || cls == 0x02 || cls == 0x03) {
            if (mode != 0x60) {
                snprintf(err, errlen,
                         "insn %zu: memory access with addressing mode 0x%02x "
                         "(only BPF_MEM 0x60 is understood; atomics and sign-extending "
                         "or packet-relative loads are not part of the amp subset)",
                         i, mode);
                return -1;
            }
            cost += COST_MEM;
            if (cls == 0x01) {   /* LDX: dst = *(src + off) */
                if (check_addr(&reg[src], off, i, "load", err, errlen) != 0) return -1;
                if (dst < 11) reg[dst].known = 0;   /* loaded value is unknown */
            } else if (cls == 0x02 || cls == 0x03) {   /* ST (imm) / STX (reg) */
                if (check_addr(&reg[dst], off, i, "store", err, errlen) != 0) return -1;
            } else {             /* a BPF_LD form other than the LDDW handled above */
                snprintf(err, errlen, "insn %zu: unsupported BPF_LD form (opcode 0x%02x)", i, opcode);
                return -1;
            }
            continue;
        }

        /* Immediate/reg moves and add feed the constant tracking. */
        if (opcode == 0xb7 || opcode == 0xb4) {           /* MOV64/32 imm */
            if (dst < 11) reg[dst] = (struct regv){1, opcode == 0xb7 ? (uint64_t)(int64_t)imm : (uint32_t)imm};
            cost += COST_ALU;
            continue;
        }
        if (opcode == 0xbf || opcode == 0xbc) {           /* MOV64/32 reg */
            if (dst < 11) reg[dst] = reg[src];
            cost += COST_ALU;
            continue;
        }
        if ((opcode == 0x07 || opcode == 0x04) && dst < 11 && reg[dst].known == 1) {  /* ADD imm on const */
            reg[dst].val += (uint64_t)(int64_t)imm;
            cost += COST_ALU;
            continue;
        }

        /* Branches: reject back-edges (loops). */
        if (cls == 0x05 || cls == 0x06) {   /* BPF_JMP / BPF_JMP32 */
            if (off < 0) { snprintf(err, errlen, "insn %zu: backward branch off=%d (unbounded loop; amp v0 is loop-free)", i, off); return -1; }
            cost += COST_BRANCH;
            continue;
        }

        /* Ordinary arithmetic: whatever it computes stops being a tracked constant. */
        if (cls == 0x04 || cls == 0x07) {   /* ALU32/ALU64 */
            if ((opcode & 0xf0) > 0xd0) {
                snprintf(err, errlen, "insn %zu: unknown ALU operation (opcode 0x%02x)", i, opcode);
                return -1;
            }
            if (dst < 11) reg[dst].known = 0;
            cost += COST_ALU;
            continue;
        }

        /* Deny by default. Reaching here means this walk does not know what the
         * instruction does -- and a check that skips what it cannot read is not a
         * check. Widening the amp subset means teaching this walk the new form
         * deliberately, rather than discovering later that it had been accepted
         * all along. */
        snprintf(err, errlen,
                 "insn %zu: instruction 0x%02x is outside the amp subset "
                 "(the checker refuses what it cannot interpret)", i, opcode);
        return -1;
    }
    if (cost_out) *cost_out = cost;
    return 0;
}

/* Pull the .text section out of a BPF ELF (Elf64, host-endian little). */
static int load_text(const char *path, uint8_t **out, size_t *outlen) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return -1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= (long)sizeof(Elf64_Ehdr)) { fclose(f); return -1; }
    uint8_t *buf = malloc((size_t)sz);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); free(buf); return -1; }
    fclose(f);

    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) { free(buf); return -1; }
    Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff);
    const char *shstr = (const char *)(buf + sh[eh->e_shstrndx].sh_offset);
    for (int i = 0; i < eh->e_shnum; i++) {
        if (strcmp(shstr + sh[i].sh_name, ".text") == 0) {
            *outlen = sh[i].sh_size;
            *out = malloc(sh[i].sh_size);
            memcpy(*out, buf + sh[i].sh_offset, sh[i].sh_size);
            free(buf);
            return 0;
        }
    }
    free(buf);
    return -1;   /* no .text */
}

int main(int argc, char **argv) {
    const char *path = NULL;
    long max_cost = -1;      /* -1 = no ceiling; admission is the installer's job */
    int cost_only = 0;

    for (int a = 1; a < argc; a++) {
        if (!strcmp(argv[a], "--max-cost") && a + 1 < argc) max_cost = strtol(argv[++a], NULL, 0);
        else if (!strcmp(argv[a], "--cost-only")) cost_only = 1;
        else if (argv[a][0] == '-') { fprintf(stderr, "amp_check: unknown option %s\n", argv[a]); return 2; }
        else path = argv[a];
    }
    if (!path) {
        fprintf(stderr, "usage: %s [--max-cost N] [--cost-only] <prog.bpf.o>\n", argv[0]);
        return 2;
    }

    uint8_t *text = NULL; size_t len = 0;
    if (load_text(path, &text, &len) != 0) { fprintf(stderr, "amp_check: cannot read .text from %s\n", path); return 2; }
    char err[256] = {0};
    unsigned cost = 0;
    int rc = amp_check_text(text, len, &cost, err, sizeof err);
    free(text);
    if (rc != 0) { fprintf(stderr, "amp_check: REJECT %s: %s\n", path, err); return 1; }

    /* The computed number belongs to the toolchain, not to the probe author: the
     * author declares what they can accept, this says what the program costs, and
     * the two are compared here rather than either being trusted to match. */
    if (cost_only) { printf("%u\n", cost); return 0; }
    if (max_cost >= 0 && (long)cost > max_cost) {
        fprintf(stderr, "amp_check: REJECT %s: static cost %u units exceeds the declared "
                        "ceiling of %ld (cost units, before platform calibration)\n",
                path, cost, max_cost);
        return 1;
    }
    fprintf(stderr, "amp_check: OK %s (%zu insns, %u cost units)\n", path, len / 8, cost);
    return 0;
}
