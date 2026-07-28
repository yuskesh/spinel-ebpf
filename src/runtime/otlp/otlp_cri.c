/* otlp_cri.c — cgroup_id -> CRI container 名の解決。詳細は otlp_cri.h。 */
#include "otlp_cri.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ---- CRIMAP (cgid -> container 名) ---- */
typedef struct { uint64_t cgid; char name[256]; } cri_ent_t;

static cri_ent_t *g_map = NULL;
static int        g_map_n = 0;
static int        g_inited = -1;   /* -1 unknown, 0 off (no CRIMAP), 1 on */

static void map_add(uint64_t cgid, const char *name) {
    cri_ent_t *e = realloc(g_map, sizeof(cri_ent_t) * (g_map_n + 1));
    if (!e) return;
    g_map = e;
    cri_ent_t *p = &g_map[g_map_n];
    p->cgid = cgid;
    snprintf(p->name, sizeof p->name, "%s", name);
    g_map_n++;
}

/* SPNL_K8S_CRIMAP を 1 度だけ読む (uidmap/ipmap と同じ lazy one-shot)。 */
static void lazy_init(void) {
    if (g_inited >= 0) return;
    const char *crimap = getenv("SPNL_K8S_CRIMAP");
    if (!crimap || !crimap[0]) { g_inited = 0; return; }   /* gate: no map -> hard no-op */

    FILE *f = fopen(crimap, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof line, f)) {
            unsigned long long cgid = 0;
            char name[256];
            /* 行形式 "<cgid> <container_name>" (cgid = leaf cgroup inode、10 進)。 */
            if (sscanf(line, "%llu %255s", &cgid, name) == 2 && cgid != 0)
                map_add((uint64_t)cgid, name);
        }
        fclose(f);
    }
    g_inited = 1;
}

int spnl_cri_lookup(uint64_t cgid, char *name_out, int cap) {
    if (!name_out || cap <= 0 || cgid == 0) return 0;
    lazy_init();
    if (g_inited != 1) return 0;
    for (int i = 0; i < g_map_n; i++) {
        if (g_map[i].cgid == cgid) {
            snprintf(name_out, (size_t)cap, "%s", g_map[i].name);
            return 1;
        }
    }
    return 0;
}

int spnl_cri_enrich_attrs(uint64_t cgid, otlp_kv_t *attrs, int max) {
    if (!attrs || max <= 0) return 0;
    char name[256];
    if (!spnl_cri_lookup(cgid, name, sizeof name) || !name[0]) return 0;
    snprintf(attrs[0].key, sizeof attrs[0].key, "%s", "k8s.container.name");
    snprintf(attrs[0].val, sizeof attrs[0].val, "%s", name);
    return 1;
}
