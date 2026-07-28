/* SPDX-License-Identifier: GPL-2.0
 *
 * amp_manifest.h -- parse a <base>.manifest produced by
 * `spinel-ebpf compile --target amp-m7 --build`. The fixed A55 drain reads
 * probe-specific info (service.name / OTLP endpoint) from here rather than
 * having it baked into the blob or the drain binary (probe-independent drain).
 */
#ifndef SPNL_AMP_MANIFEST_H
#define SPNL_AMP_MANIFEST_H

#include <stdint.h>

struct amp_manifest {
	char     service_name[64];   /* OTLP resource service.name */
	char     endpoint[160];      /* OTLP endpoint (http://.../grpc://...) */
	uint32_t abi_version;        /* must match AMP_ABI_VERSION */
	uint32_t ivars_size;         /* probe @ivar carveout bytes (for reference) */
	uint32_t n_triggers;         /* number of trigger= lines */
};

/* Parse `path` (key=value lines, '#' comments). Fills sensible defaults first
 * (service_name="spinel-amp-m7", endpoint=""). Returns 0 on success, -1 if the
 * file can't be opened. */
int amp_manifest_load(const char *path, struct amp_manifest *m);

#endif /* SPNL_AMP_MANIFEST_H */
