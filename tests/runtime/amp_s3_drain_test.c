/*
 * amp_s3_drain_test.c -- host verification of the fixed, manifest-driven
 * A55 drain. Loads a real <base>.manifest (produced by the CLI 1-command build),
 * builds a synthetic ring holding what the QEMU/M7 blob emits (hb_hw = @ticks*7 =
 * 7,14,21), and runs the SAME amp_drain_build the board binary uses -- with the
 * OTLP resource service.name taken from the manifest. Writes the payload to
 * argv[2] for protoc decode by run_amp_s3.sh (asserts service.name flows from the
 * manifest, not a hardcode). No /dev/mem, no network.
 */
#define AMP_DRAIN_NO_MAIN
#include "amp_a55_drain.c"   /* amp_drain_build (+ amp_manifest.h, amp_otlp.h, amp_ring.h) */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s <base>.manifest <out.pb>\n", argv[0]);
		return 2;
	}
	struct amp_manifest m;
	if (amp_manifest_load(argv[1], &m) != 0) {
		fprintf(stderr, "manifest load failed: %s\n", argv[1]);
		return 1;
	}
	fprintf(stderr, "[amp-build] manifest: service=%s endpoint=%s abi=%u ivars_size=%u triggers=%u\n",
		m.service_name, m.endpoint, m.abi_version, m.ivars_size, m.n_triggers);

	/* synthetic ring = what the single-pass hb_hw blob writes on the M7. */
	const uint32_t CAP = 8;
	struct amp_ring *r = calloc(1, sizeof(struct amp_ring) + CAP * sizeof(struct amp_ring_rec));
	if (!r) {
		return 1;
	}
	amp_ring_init(r, CAP);
	const uint64_t base = 1700000000000000000ULL;
	for (int i = 1; i <= 3; i++) {
		if (!amp_ring_emit(r, base + (uint64_t)i, (int64_t)(i * 7))) {
			fprintf(stderr, "unexpected full\n");
			return 1;
		}
	}

	uint8_t buf[8192];
	size_t nd = 0;
	long len = amp_drain_build(r, &m, buf, sizeof(buf), &nd);
	if (len <= 0 || nd != 3) {
		fprintf(stderr, "drain failed (len=%ld nd=%zu)\n", len, nd);
		return 1;
	}
	FILE *fp = fopen(argv[2], "wb");
	if (!fp || fwrite(buf, 1, (size_t)len, fp) != (size_t)len) {
		perror("write out.pb");
		return 1;
	}
	fclose(fp);
	free(r);
	fprintf(stderr, "[amp-build] drained %zu records (service='%s' from manifest) -> %s (%ld bytes)\n",
		nd, m.service_name, argv[2], len);
	return 0;
}
