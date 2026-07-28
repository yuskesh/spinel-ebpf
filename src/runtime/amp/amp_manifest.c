/* SPDX-License-Identifier: GPL-2.0
 *
 * amp_manifest.c -- the <base>.manifest parser (see amp_manifest.h).
 */
#include "amp_manifest.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void set_str(char *dst, size_t cap, const char *v)
{
	size_t n = strlen(v);
	if (n >= cap) {
		n = cap - 1;
	}
	memcpy(dst, v, n);
	dst[n] = '\0';
}

int amp_manifest_load(const char *path, struct amp_manifest *m)
{
	memset(m, 0, sizeof(*m));
	set_str(m->service_name, sizeof(m->service_name), "spinel-amp-m7");
	m->endpoint[0] = '\0';

	FILE *f = fopen(path, "r");
	if (!f) {
		return -1;
	}
	char line[256];
	while (fgets(line, sizeof(line), f)) {
		if (line[0] == '#' || line[0] == '\n') {
			continue;
		}
		char *nl = strchr(line, '\n');
		if (nl) {
			*nl = '\0';
		}
		char *eq = strchr(line, '=');
		if (!eq) {
			continue;
		}
		*eq = '\0';
		const char *k = line, *v = eq + 1;
		if (!strcmp(k, "service.name")) {
			set_str(m->service_name, sizeof(m->service_name), v);
		} else if (!strcmp(k, "otlp.endpoint")) {
			set_str(m->endpoint, sizeof(m->endpoint), v);
		} else if (!strcmp(k, "abi_version")) {
			m->abi_version = (uint32_t)strtoul(v, NULL, 0);
		} else if (!strcmp(k, "ivars_size")) {
			m->ivars_size = (uint32_t)strtoul(v, NULL, 0);
		} else if (!strcmp(k, "trigger")) {
			m->n_triggers++;
		}
	}
	fclose(f);
	return 0;
}
