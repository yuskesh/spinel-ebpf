/* otlp_k8s.c -- resolve a cgroup id to its Kubernetes pod. See otlp_k8s.h. */
#include "otlp_k8s.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Split the part of the path from "kubepods" onwards on "/" to obtain
 * {qos, pod_uid, container_id}. */
int spnl_k8s_parse_kubepods_path(const char *cgroup_path, spnl_k8s_pod_t *out)
{
    if (!cgroup_path || !out) return 0;
    memset(out, 0, sizeof *out);

    const char *kp = strstr(cgroup_path, "kubepods");
    if (!kp) return 0;

    /* Copy from "kubepods" onwards and split on "/", stripping the systemd
     * ".slice" and ".scope" suffixes as we go. */
    char buf[1024];
    snprintf(buf, sizeof buf, "%s", kp);

    char *save = NULL;
    for (char *tok = strtok_r(buf, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
        /* Drop the systemd suffixes: kubepods-burstable-pod<UID>.slice,
         * cri-*-<id>.scope. */
        char comp[512];
        snprintf(comp, sizeof comp, "%s", tok);
        char *dot = strrchr(comp, '.');
        if (dot && (!strcmp(dot, ".slice") || !strcmp(dot, ".scope"))) *dot = '\0';

        /* The QoS class. */
        if (!strcmp(comp, "besteffort") || !strcmp(comp, "burstable") || !strcmp(comp, "guaranteed")) {
            snprintf(out->qos, sizeof out->qos, "%s", comp);
            continue;
        }
        /* Reduce the systemd form "kubepods-burstable-pod<UID>" to the pod token.
         * To avoid matching the "pod" inside "kubepods", only accept a "pod" that
         * begins the string or follows a '-', and is itself followed by a hex
         * digit -- the start of the UID. */
        const char *podp = NULL;
        for (const char *sp = comp; (sp = strstr(sp, "pod")); sp += 3) {
            char after = sp[3];
            char before = (sp == comp) ? '\0' : sp[-1];
            int hexish = (after >= '0' && after <= '9') || (after >= 'a' && after <= 'f');
            if ((sp == comp || before == '-') && hexish) { podp = sp; break; }
        }
        if (podp) {
            /* Pick up the QoS class when it is embedded in the prefix. */
            if (!out->qos[0]) {
                if (strstr(comp, "burstable"))  snprintf(out->qos, sizeof out->qos, "burstable");
                else if (strstr(comp, "besteffort")) snprintf(out->qos, sizeof out->qos, "besteffort");
                else if (strstr(comp, "guaranteed")) snprintf(out->qos, sizeof out->qos, "guaranteed");
            }
            snprintf(out->pod_uid, sizeof out->pod_uid, "%s", podp + 3);
            /* Normalise the UID separators: systemd writes '_' where the API says '-'. */
            for (char *c = out->pod_uid; *c; c++) if (*c == '_') *c = '-';
            continue;
        }
        /* Once pod_uid is known, any further component is the container id. */
        if (out->pod_uid[0] && !out->container_id[0]) {
            const char *cid = comp;
            /* Strip the systemd prefixes "cri-containerd-<id>" and "docker-<id>". */
            const char *dash = strrchr(comp, '-');
            if (dash && strlen(dash + 1) >= 32) cid = dash + 1;
            snprintf(out->container_id, sizeof out->container_id, "%s", cid);
        }
    }

    out->found = out->pod_uid[0] ? 1 : 0;
    return out->found;
}

/* Walk cgroup_root recursively looking for the directory whose inode is cgid. */
static int walk_find(const char *dir, uint64_t cgid, char *outpath, size_t outcap)
{
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *de;
    int found = 0;
    while (!found && (de = readdir(d))) {
        if (de->d_name[0] == '.' &&
            (de->d_name[1] == '\0' || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;
        char path[1024];
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (!S_ISDIR(st.st_mode)) continue;
        if ((uint64_t)st.st_ino == cgid) {
            snprintf(outpath, outcap, "%s", path);
            found = 1;
            break;
        }
        found = walk_find(path, cgid, outpath, outcap);
    }
    closedir(d);
    return found;
}

int spnl_k8s_lookup_by_cgroup_id(uint64_t cgid, const char *cgroup_root, spnl_k8s_pod_t *out)
{
    if (!out) return 0;
    memset(out, 0, sizeof *out);
    const char *root = cgroup_root ? cgroup_root : "/sys/fs/cgroup";
    char path[1024] = {0};
    /* Search under kubepods first: it is faster, and avoids false matches. */
    char kroot[1024];
    snprintf(kroot, sizeof kroot, "%s/kubepods", root);
    if (!walk_find(kroot, cgid, path, sizeof path)) {
        /* Try the systemd spelling, kubepods.slice, as well. */
        snprintf(kroot, sizeof kroot, "%s/kubepods.slice", root);
        if (!walk_find(kroot, cgid, path, sizeof path)) return 0;
    }
    return spnl_k8s_parse_kubepods_path(path, out);
}

int spnl_k8s_resolve_name(spnl_k8s_pod_t *p, const char *uidmap_file)
{
    if (!p || !p->pod_uid[0] || !uidmap_file) return 0;
    FILE *f = fopen(uidmap_file, "r");
    if (!f) return 0;
    char line[640];
    int hit = 0;
    while (fgets(line, sizeof line, f)) {
        /* The line format, extended backward-compatibly:
         * "<uid> <namespace>/<name> [<deployment> <service>]" */
        char uid[64], nsname[400], depl[256] = "", svc[256] = "";
        int nf = sscanf(line, "%63s %399s %255s %255s", uid, nsname, depl, svc);
        if (nf < 2) continue;
        if (strcmp(uid, p->pod_uid) != 0) continue;
        char *slash = strchr(nsname, '/');
        if (slash) {
            *slash = '\0';
            snprintf(p->namespace_, sizeof p->namespace_, "%s", nsname);
            snprintf(p->pod_name, sizeof p->pod_name, "%s", slash + 1);
        } else {
            snprintf(p->pod_name, sizeof p->pod_name, "%s", nsname);
        }
        /* Columns three and four, the workload and Service. A "-" or an empty
         * value is a placeholder for "not resolved", and is ignored. */
        if (nf >= 3 && depl[0] && strcmp(depl, "-") != 0)
            snprintf(p->deployment, sizeof p->deployment, "%s", depl);
        if (nf >= 4 && svc[0] && strcmp(svc, "-") != 0)
            snprintf(p->service, sizeof p->service, "%s", svc);
        hit = 1;
        break;
    }
    fclose(f);
    return hit;
}

int spnl_k8s_fill_attrs(const spnl_k8s_pod_t *p, otlp_kv_t *attrs, int max)
{
    if (!p || !attrs) return 0;
    int n = 0;
    #define PUT(k, v) do { if ((v)[0] && n < max) { \
        snprintf(attrs[n].key, sizeof attrs[n].key, "%s", (k)); \
        snprintf(attrs[n].val, sizeof attrs[n].val, "%s", (v)); n++; } } while (0)
    PUT("k8s.namespace.name", p->namespace_);
    PUT("k8s.pod.name",       p->pod_name);
    PUT("k8s.pod.uid",        p->pod_uid);
    PUT("k8s.container.name", p->container_id);  /* the container id; the CRI enricher
                                                    rewrites this to a real name */
    PUT("k8s.deployment.name", p->deployment);   /* owning workload, uid map column 3 */
    PUT("k8s.service.name",    p->service);      /* originating Service, uid map column 4 */
    #undef PUT
    return n;
}

int spnl_k8s_enrich_attrs(uint64_t cgid, const char *cgroup_root,
                          const char *uidmap_file, otlp_kv_t *attrs, int max)
{
    spnl_k8s_pod_t p;
    if (!spnl_k8s_lookup_by_cgroup_id(cgid, cgroup_root, &p)) return 0;
    if (uidmap_file) spnl_k8s_resolve_name(&p, uidmap_file);
    return spnl_k8s_fill_attrs(&p, attrs, max);
}
