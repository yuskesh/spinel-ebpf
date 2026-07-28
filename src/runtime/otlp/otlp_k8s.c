/* otlp_k8s.c — cgroup_id -> k8s pod 解決。詳細は otlp_k8s.h。 */
#include "otlp_k8s.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

/* パス中の "kubepods" 以降を "/" で分解し {qos, pod_uid, container_id} を得る。 */
int spnl_k8s_parse_kubepods_path(const char *cgroup_path, spnl_k8s_pod_t *out)
{
    if (!cgroup_path || !out) return 0;
    memset(out, 0, sizeof *out);

    const char *kp = strstr(cgroup_path, "kubepods");
    if (!kp) return 0;

    /* kubepods 以降をコピーして "/" で分解 (systemd の ".slice"/".scope" 接尾辞も剥がす)。 */
    char buf[1024];
    snprintf(buf, sizeof buf, "%s", kp);

    char *save = NULL;
    for (char *tok = strtok_r(buf, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
        /* systemd 形の接尾辞を除去 (kubepods-burstable-pod<UID>.slice / cri-*-<id>.scope)。 */
        char comp[512];
        snprintf(comp, sizeof comp, "%s", tok);
        char *dot = strrchr(comp, '.');
        if (dot && (!strcmp(dot, ".slice") || !strcmp(dot, ".scope"))) *dot = '\0';

        /* qos クラス。 */
        if (!strcmp(comp, "besteffort") || !strcmp(comp, "burstable") || !strcmp(comp, "guaranteed")) {
            snprintf(out->qos, sizeof out->qos, "%s", comp);
            continue;
        }
        /* systemd 形 "kubepods-burstable-pod<UID>" -> pod トークンへ縮約。
         * "kubepods" 内の "pod" を誤検出しないよう、行頭 or '-' の直後で、かつ直後が
         * hex (UID の先頭) の "pod" だけを採用する。 */
        const char *podp = NULL;
        for (const char *sp = comp; (sp = strstr(sp, "pod")); sp += 3) {
            char after = sp[3];
            char before = (sp == comp) ? '\0' : sp[-1];
            int hexish = (after >= '0' && after <= '9') || (after >= 'a' && after <= 'f');
            if ((sp == comp || before == '-') && hexish) { podp = sp; break; }
        }
        if (podp) {
            /* qos が prefix に埋まっている場合も拾う。 */
            if (!out->qos[0]) {
                if (strstr(comp, "burstable"))  snprintf(out->qos, sizeof out->qos, "burstable");
                else if (strstr(comp, "besteffort")) snprintf(out->qos, sizeof out->qos, "besteffort");
                else if (strstr(comp, "guaranteed")) snprintf(out->qos, sizeof out->qos, "guaranteed");
            }
            snprintf(out->pod_uid, sizeof out->pod_uid, "%s", podp + 3);
            /* UID の区切りを正規化 (systemd の '_' -> '-')。 */
            for (char *c = out->pod_uid; *c; c++) if (*c == '_') *c = '-';
            continue;
        }
        /* pod_uid が確定済で、これ以上分解要素があれば container id。 */
        if (out->pod_uid[0] && !out->container_id[0]) {
            const char *cid = comp;
            /* systemd 形 "cri-containerd-<id>" / "docker-<id>" の prefix を剥がす。 */
            const char *dash = strrchr(comp, '-');
            if (dash && strlen(dash + 1) >= 32) cid = dash + 1;
            snprintf(out->container_id, sizeof out->container_id, "%s", cid);
        }
    }

    out->found = out->pod_uid[0] ? 1 : 0;
    return out->found;
}

/* cgroup_root 以下を再帰 walk して inode == cgid のディレクトリを見つける。 */
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
    /* まず kubepods 直下に限定して walk (速い・誤検出を避ける)。 */
    char kroot[1024];
    snprintf(kroot, sizeof kroot, "%s/kubepods", root);
    if (!walk_find(kroot, cgid, path, sizeof path)) {
        /* systemd 形 kubepods.slice も試す。 */
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
        /* 形式 (後方互換): "<uid> <namespace>/<name> [<deployment> <service>]" */
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
        /* 3/4 列目 (workload/service)。"-" or 空はプレースホルダ (未解決) として無視。 */
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
    PUT("k8s.container.name", p->container_id);  /* MVP: container id (CRI 名解決は E303) */
    PUT("k8s.deployment.name", p->deployment);   /* E310: owning workload (uid マップ 3 列目) */
    PUT("k8s.service.name",    p->service);       /* E310: 発信元 Service (uid マップ 4 列目) */
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
