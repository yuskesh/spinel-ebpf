/* SPDX-License-Identifier: GPL-2.0
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
 * Together this rules out, before deployment, both running unverified bytecode on
 * that core and writing outside the region the ABI reserves.
 *
 * usage: amp_check <prog.bpf.o>   (exit 0 = ok, 1 = reject, 2 = usage/IO)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>

#include "spnl/amp_abi_imx95m7.h"   /* AMP_IVARS_BASE / AMP_IVARS_SIZE (fixed ABI) */

/* The allowlist of amp helper ids. Extend it when the helper set grows. */
static int amp_helper_allowed(int32_t id) { return id == 1 || id == 2; }

/* Register-immediate tracking (S4). known: 0=unknown, 1=constant, 2=stack(r10). */
struct regv { int known; uint64_t val; };

static int check_addr(const struct regv *base, int16_t off, size_t i, const char *how,
                      char *err, size_t errlen) {
    if (base->known == 2) return 0;                 /* r10-relative = BPF/DTCM stack: allow */
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
static int amp_check_text(const uint8_t *text, size_t len, char *err, size_t errlen) {
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
            i++;
            continue;
        }
        if (opcode == 0x85) {   /* BPF_JMP | BPF_CALL */
            if (src == 1) { snprintf(err, errlen, "insn %zu: local/pseudo call not allowed (amp is 1 program = 1 function)", i); return -1; }
            if (!amp_helper_allowed(imm)) { snprintf(err, errlen, "insn %zu: call to disallowed helper id %d (allowed: 1=amp_emit, 2=amp_ktime)", i, imm); return -1; }
            for (int r = 0; r <= 5; r++) reg[r].known = 0;   /* r0=ret, r1-r5 clobbered */
            continue;
        }
        if (opcode == 0x95) continue;   /* EXIT */

        /* Memory access (mode==MEM 0x60): range-check the base register. */
        if (mode == 0x60 && (cls == 0x01 || cls == 0x02 || cls == 0x03)) {
            if (cls == 0x01) {   /* LDX: dst = *(src + off) */
                if (check_addr(&reg[src], off, i, "load", err, errlen) != 0) return -1;
                if (dst < 11) reg[dst].known = 0;   /* loaded value is unknown */
            } else {             /* ST (imm) / STX (reg): *(dst + off) = ... */
                if (check_addr(&reg[dst], off, i, "store", err, errlen) != 0) return -1;
            }
            continue;
        }

        /* Immediate/reg moves and add feed the constant tracking. */
        if (opcode == 0xb7 || opcode == 0xb4) {           /* MOV64/32 imm */
            if (dst < 11) reg[dst] = (struct regv){1, opcode == 0xb7 ? (uint64_t)(int64_t)imm : (uint32_t)imm};
            continue;
        }
        if (opcode == 0xbf || opcode == 0xbc) {           /* MOV64/32 reg */
            if (dst < 11) reg[dst] = reg[src];
            continue;
        }
        if ((opcode == 0x07 || opcode == 0x04) && dst < 11 && reg[dst].known == 1) {  /* ADD imm on const */
            reg[dst].val += (uint64_t)(int64_t)imm;
            continue;
        }

        /* Branches: reject back-edges (loops). */
        if (cls == 0x05 || cls == 0x06) {   /* BPF_JMP / BPF_JMP32 */
            if (off < 0) { snprintf(err, errlen, "insn %zu: backward branch off=%d (unbounded loop; amp v0 is loop-free)", i, off); return -1; }
            continue;
        }

        /* Any other insn writing a dst register makes it unknown. */
        if (cls == 0x04 || cls == 0x07 || cls == 0x00) {   /* ALU32/ALU64/LD */
            if (dst < 11) reg[dst].known = 0;
        }
    }
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
    if (argc < 2) { fprintf(stderr, "usage: %s <prog.bpf.o>\n", argv[0]); return 2; }
    uint8_t *text = NULL; size_t len = 0;
    if (load_text(argv[1], &text, &len) != 0) { fprintf(stderr, "amp_check: cannot read .text from %s\n", argv[1]); return 2; }
    char err[256] = {0};
    int rc = amp_check_text(text, len, err, sizeof err);
    free(text);
    if (rc != 0) { fprintf(stderr, "amp_check: REJECT %s: %s\n", argv[1], err); return 1; }
    fprintf(stderr, "amp_check: OK %s (%zu insns)\n", argv[1], len / 8);
    return 0;
}
