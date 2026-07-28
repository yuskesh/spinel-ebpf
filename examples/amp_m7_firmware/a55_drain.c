/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * a55_drain.c -- A55-side drain for the M7 shared ring.
 *
 * mmap the shared DDR ring (physical AMP_RING_PHYS) via /dev/mem, poll for new
 * records, and print each. Standalone (no OTLP deps) so it builds on the board
 * with plain gcc; the OTLP path (amp_ring_drain_logs -> spnl_otlp) lives in the
 * host runtime and gets wired once the ring is proven end-to-end.
 *
 * build on the A55 board:  gcc -O2 -I<repo>/include a55_drain.c -o a55_drain
 * run:                     ./a55_drain            (Ctrl-C to stop)
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "spnl/amp_ring.h"

#define AMP_RING_PHYS 0x88400000UL   /* must match amp_producer.c */
#define MAP_LEN       0x10000UL      /* 64 KiB window (ctrl + slots) */

int main(void)
{
	int fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0) { perror("open /dev/mem"); return 1; }

	/* map the ring page(s); /dev/mem gives a device (uncached/coherent) view,
	 * so we see what the M7 flushed to DDR. */
	void *base = mmap(NULL, MAP_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)AMP_RING_PHYS);
	if (base == MAP_FAILED) { perror("mmap"); return 1; }

	volatile struct amp_ring *r = (volatile struct amp_ring *)base;
	printf("[a55_drain] ring @ 0x%lx  magic=0x%08x cap=%u rec_size=%u\n",
	       AMP_RING_PHYS, r->magic, r->capacity, r->rec_size);
	if (r->magic != AMP_RING_MAGIC)
		printf("[a55_drain] (magic not ARNG yet — waiting for M7 to init)\n");

	uint32_t cons = r->cons;
	for (;;) {
		uint32_t prod = r->prod;                     /* published by M7 */
		while (cons != prod) {
			struct amp_ring_rec *rec =
				(struct amp_ring_rec *)amp_ring_slots((struct amp_ring *)r) + (cons % r->capacity);
			printf("[a55_drain] rec #%u: value=%lld ts=%llu type=0x%04x\n",
			       cons, (long long)rec->value,
			       (unsigned long long)rec->hdr.timestamp, rec->hdr.type);
			fflush(stdout);
			cons++;
		}
		r->cons = cons;                              /* ack consumption */
		usleep(200 * 1000);                          /* 5 Hz poll */
	}
}
