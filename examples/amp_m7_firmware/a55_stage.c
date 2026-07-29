/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * a55_stage.c -- A55-side blob staging for the fixed-ABI M7 runtime.
 *
 * Writes `struct amp_blob_staging` (magic/abi_version/length/ivars_size) + the
 * single-pass blob bytes to the fixed shared-memory staging region
 * (AMP_STAGING_BASE) so the M7 loader (amp_m7_runtime) reads it at boot. This is
 * how "firmware fixed, blob swapped" works: build the firmware once, stage a blob,
 * remoteproc restart. Mirrors a55_drain.c's uncached /dev/mem view.
 *
 * build on the A55 board:  gcc -O2 -I<repo>/include a55_stage.c -o a55_stage
 * run:                     ./a55_stage <blob.bin> <ivars_size> [staging_phys]
 *   ivars_size = the probe's amp_ivars_size (from the .bpf.c manifest; hb_hw = 4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "spnl/amp_abi.h"

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s <blob.bin> <ivars_size> [staging_phys]\n", argv[0]);
		return 2;
	}
	const char *path = argv[1];
	uint32_t ivars_size = (uint32_t)strtoul(argv[2], NULL, 0);
	uint64_t phys = (argc > 3) ? strtoull(argv[3], NULL, 0) : (uint64_t)AMP_STAGING_BASE;

	static uint8_t blob[AMP_BLOB_MAX];
	FILE *f = fopen(path, "rb");
	if (!f) { perror("open blob"); return 1; }
	size_t n = fread(blob, 1, sizeof(blob), f);
	fclose(f);
	if (n == 0 || n > AMP_BLOB_MAX) {
		fprintf(stderr, "bad blob size %zu (max %u)\n", n, (unsigned)AMP_BLOB_MAX);
		return 1;
	}

	int fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0) { perror("open /dev/mem"); return 1; }

	void *base = mmap(NULL, AMP_STAGING_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
			  fd, (off_t)phys);
	if (base == MAP_FAILED) { perror("mmap"); return 1; }

	/*
	 * /dev/mem maps physical RAM as Device memory on arm64, where unaligned
	 * accesses fault (BUS_ADRALN). memcpy() uses wide/unaligned stores, so we
	 * must write the mapping only via naturally-aligned 32-bit stores. Build the
	 * full image (header + blob, tail zero-padded to a word) in normal memory,
	 * then copy it word-by-word. Magic is published last, after a barrier.
	 */
	volatile uint32_t *dst = (volatile uint32_t *)base;
	uint32_t hdr_words = (uint32_t)(sizeof(struct amp_blob_staging) / 4);  /* magic,abi,len,ivars */
	uint32_t blob_words = (uint32_t)((n + 3) / 4);

	static uint32_t img[(sizeof(struct amp_blob_staging) + AMP_BLOB_MAX) / 4 + 1];
	img[0] = AMP_STAGING_MAGIC;   /* [0] not published to the mapping until last */
	img[1] = AMP_ABI_VERSION;
	img[2] = (uint32_t)n;
	img[3] = ivars_size;
	memcpy(&img[hdr_words], blob, n);   /* into normal memory — aligned copy is fine */

	/* fields + blob first (skip word 0 = magic), aligned stores. */
	for (uint32_t i = 1; i < hdr_words + blob_words; i++) {
		dst[i] = img[i];
	}
	__sync_synchronize();
	dst[0] = AMP_STAGING_MAGIC;   /* publish magic last */
	__sync_synchronize();

	printf("[a55_stage] staged %zu bytes at 0x%llx "
	       "(magic=0x%08x abi_version=%u ivars_size=%u)\n",
	       n, (unsigned long long)phys, AMP_STAGING_MAGIC, AMP_ABI_VERSION, ivars_size);
	munmap(base, AMP_STAGING_SIZE);
	close(fd);
	return 0;
}
