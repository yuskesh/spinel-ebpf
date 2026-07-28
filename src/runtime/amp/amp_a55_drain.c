/* SPDX-License-Identifier: GPL-2.0
 *
 * amp_a55_drain.c -- a fixed, probe-independent drain for the application core.
 *
 * The M7/A55 pair's A55 output is now just blob + manifest (symmetric with the M7
 * libamp_m7): the ring ABI is fixed (AMP_RING_BASE, spnl/amp_ring.h) and all
 * probe-specific info (service.name / OTLP endpoint) is read from the manifest —
 * nothing is codegen-generated per probe. One drain binary serves every probe.
 *
 * `amp_drain_build` (the manifest-driven ring -> OTLP-logs step) is factored out
 * so the host test drives it with a synthetic ring (no /dev/mem, no network). The
 * board main() adds the /dev/mem ring mmap + OTLP push (verified on HW / network
 * environment by the supervisor).
 *
 * board build:  gcc -O2 -I<repo>/include -I<repo>/src/runtime/amp -I<repo>/src/runtime/otlp ... \
 *                 amp_a55_drain.c amp_manifest.c amp_otlp.c otlp_*.c nanopb ... -o amp_a55_drain
 * run:          ./amp_a55_drain <base>.manifest        (Ctrl-C to stop; --once for one pass)
 */
#include "amp_manifest.h"
#include "amp_otlp.h"
#include "spnl/amp_ring.h"

#include <stdint.h>
#include <stddef.h>

#ifndef AMP_DRAIN_BUFSZ
#define AMP_DRAIN_BUFSZ 65536
#endif

/* Build one OTLP ExportLogsServiceRequest from the ring's pending records, with
 * the resource service.name taken from the manifest. Returns encoded byte length
 * (0 if nothing pending, -1 on error); *nd = record count. */
long amp_drain_build(struct amp_ring *r, const struct amp_manifest *m,
		     uint8_t *buf, size_t cap, size_t *nd)
{
	return amp_ring_drain_logs(r, buf, cap, m->service_name, "0.1.0", 0, nd);
}

#ifndef AMP_DRAIN_NO_MAIN
#include "spnl/amp_abi_imx95m7.h"
#include "otlp_grpc.h"   /* otlp_transport_send */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <base>.manifest [--once]\n", argv[0]);
		return 2;
	}
	struct amp_manifest m;
	if (amp_manifest_load(argv[1], &m) != 0) {
		fprintf(stderr, "[amp_a55_drain] cannot read manifest: %s\n", argv[1]);
		return 1;
	}
	if (m.abi_version != AMP_ABI_VERSION) {
		fprintf(stderr, "[amp_a55_drain] manifest abi_version %u != %u — refusing\n",
			m.abi_version, AMP_ABI_VERSION);
		return 1;
	}
	int once = (argc > 2 && strcmp(argv[2], "--once") == 0);

	int fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0) {
		perror("open /dev/mem");
		return 1;
	}
	void *base = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE, MAP_SHARED,
			  fd, (off_t)AMP_RING_BASE);
	if (base == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	struct amp_ring *r = (struct amp_ring *)base;
	fprintf(stderr, "[amp_a55_drain] ring@0x%08x service=%s endpoint=%s (probe-independent)\n",
		(unsigned)AMP_RING_BASE, m.service_name, m.endpoint);

	static uint8_t buf[AMP_DRAIN_BUFSZ];
	for (;;) {
		size_t nd = 0;
		long len = amp_drain_build(r, &m, buf, sizeof(buf), &nd);
		if (len > 0 && nd > 0) {
			int status = 0;
			char err[256] = {0};
			int rc = otlp_transport_send(
				m.endpoint, "/v1/logs",
				"/opentelemetry.proto.collector.logs.v1.LogsService/Export",
				"application/x-protobuf", buf, (size_t)len, &status, err, sizeof(err));
			fprintf(stderr, "[amp_a55_drain] pushed %zu records -> %s (rc=%d status=%d) %s\n",
				nd, m.endpoint, rc, status, err[0] ? err : "");
		}
		if (once) {
			break;
		}
		usleep(200 * 1000);
	}
	munmap(base, 0x10000);
	close(fd);
	return 0;
}
#endif /* AMP_DRAIN_NO_MAIN */
