/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * a55_cmd.c -- A55->M7 cmd ring push for no-restart hot swap.
 *
 * Pushes an INSTALL (new blob) or TEARDOWN command into the cmd ring
 * (AMP_CMD_RING_BASE) so the running M7 loader swaps the active probe with NO
 * remoteproc restart (A/B slots) or removes it tracelessly. Decoupled verification:
 * run amp_check on the probe's .bpf.o BEFORE calling this (the M7 re-gates on
 * magic/abi/length). Writes the mapping with word-aligned stores only (arm64
 * /dev/mem = Device memory faults on unaligned access -- the same lesson as a55_stage).
 *
 * build:  gcc -O2 -I<repo>/include a55_cmd.c -o a55_cmd
 * run:    ./a55_cmd install <blob.bin> <ivars_size>
 *         ./a55_cmd teardown
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "spnl/amp_abi_imx95m7.h"

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s install <blob.bin> <ivars_size> | teardown\n", argv[0]);
		return 2;
	}
	uint32_t type, len = 0, ivars_size = 0;
	static uint8_t blob[AMP_BLOB_MAX];

	if (strcmp(argv[1], "install") == 0) {
		if (argc < 4) { fprintf(stderr, "install needs <blob.bin> <ivars_size>\n"); return 2; }
		type = AMP_CMD_INSTALL;
		ivars_size = (uint32_t)strtoul(argv[3], NULL, 0);
		FILE *f = fopen(argv[2], "rb");
		if (!f) { perror("open blob"); return 1; }
		len = (uint32_t)fread(blob, 1, sizeof(blob), f);
		fclose(f);
		if (len == 0 || len > AMP_BLOB_MAX) { fprintf(stderr, "bad blob size %u\n", len); return 1; }
	} else if (strcmp(argv[1], "teardown") == 0) {
		type = AMP_CMD_TEARDOWN;
	} else {
		fprintf(stderr, "unknown command '%s'\n", argv[1]);
		return 2;
	}

	int fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0) { perror("open /dev/mem"); return 1; }
	void *base = mmap(NULL, AMP_CMD_RING_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
			  fd, (off_t)AMP_CMD_RING_BASE);
	if (base == MAP_FAILED) { perror("mmap"); return 1; }

	volatile struct amp_cmd_ring *cr = (volatile struct amp_cmd_ring *)base;
	if (cr->magic != AMP_CMD_RING_MAGIC) {
		fprintf(stderr, "[a55_cmd] cmd ring not ready (magic=0x%08x); is the M7 up?\n", cr->magic);
		return 1;
	}
	uint32_t prod = cr->prod, cons = cr->cons, cap = cr->capacity;
	if (prod - cons >= cap) { fprintf(stderr, "[a55_cmd] cmd ring full\n"); return 1; }

	/* Build the record image in normal memory (word-padded), then copy it into
	 * the ring slot with aligned 32-bit stores; publish prod last. */
	enum { RECW = (sizeof(struct amp_cmd_rec) + 3) / 4 };
	static uint32_t img[RECW];
	memset(img, 0, sizeof(img));
	struct amp_cmd_rec *rec = (struct amp_cmd_rec *)img;
	rec->type = type;
	rec->abi_version = AMP_ABI_VERSION;
	rec->length = len;
	rec->ivars_size = ivars_size;
	if (type == AMP_CMD_INSTALL) {
		memcpy(rec->blob, blob, len);
	}

	volatile uint32_t *slot = (volatile uint32_t *)
		((volatile uint8_t *)base + sizeof(struct amp_cmd_ring)
		 + (size_t)(prod % cap) * sizeof(struct amp_cmd_rec));
	for (unsigned i = 0; i < RECW; i++) {
		slot[i] = img[i];
	}
	__sync_synchronize();
	cr->prod = prod + 1;   /* publish (single aligned word) */
	__sync_synchronize();

	if (type == AMP_CMD_INSTALL) {
		printf("[a55_cmd] pushed INSTALL len=%u at prod=%u (abi=%u ivars_size=%u)\n",
		       len, prod + 1, AMP_ABI_VERSION, ivars_size);
	} else {
		printf("[a55_cmd] pushed TEARDOWN at prod=%u (abi=%u)\n", prod + 1, AMP_ABI_VERSION);
	}
	munmap(base, AMP_CMD_RING_SIZE);
	close(fd);
	return 0;
}
