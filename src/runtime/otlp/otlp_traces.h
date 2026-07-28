/*
 * otlp_traces.h — メソッド呼び出しツリーを OTLP traces (span) に変換
 *
 * kernel は uprobe/uretprobe で enter/exit イベント (kind,idx,ktime,tid) を emit4 ringbuf に出す。
 * userspace は (1) それを per-tid スタックで組み立てて span にし (otlp_traces_assemble)、
 * (2) OTLP ExportTraceServiceRequest を nanopb で組む (otlp_traces_build)。
 *
 * 親 span id は「呼び出し開始(enter)時」に確定する必要がある(exit は内側から先に返るため)。
 * よって enter で span_id を割当 + 親 = スタック直下、trace_id は最外(depth 0)で生成する。
 * libbpf 非依存(drain は呼び出し側=otlp_agent が行い、events 配列を渡す)→ host で単体検証可能。
 */
#ifndef SPNL_OTLP_TRACES_H
#define SPNL_OTLP_TRACES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "otlp_http.h"   /* otlp_kv_t (E292 generic span attrs) */

#ifdef __cplusplus
extern "C" {
#endif

#define OTLP_TRACE_MAX_TIDS  64
#define OTLP_TRACE_MAX_DEPTH 64

/* emit4 から decode した enter/exit イベント (kind: 0=enter, 1=exit) */
typedef struct {
    int32_t  kind;
    int32_t  idx;
    uint64_t ktime_ns;
    uint64_t tid;
} otlp_span_event_t;

/* 組み立て済の span */
typedef struct {
    uint8_t  trace_id[16];
    uint8_t  span_id[8];
    uint8_t  parent_span_id[8];
    bool     has_parent;
    int32_t  method_idx;
    uint64_t start_unix_ns;
    uint64_t end_unix_ns;
} otlp_span_t;

/* idx -> 名前/ファイル/行 (code.* 属性 + span 名に使う) */
typedef struct {
    int32_t     idx;
    const char *method;
    const char *file;
    int32_t     line;
} otlp_method_meta_t;

/*
 * events (実行順) を span 群に組み立てる。off_ns は ktime(monotonic) -> unix nano の加算オフセット
 * (= realtime - monotonic)。seed は trace/span id 生成の種 (テストは固定、本番は wall^pid 等)。
 * 組み立てた span 数を返す (max_out で頭打ち)。
 */
int otlp_traces_assemble(const otlp_span_event_t *ev, size_t nev,
                         int64_t off_ns, uint64_t seed,
                         otlp_span_t *out, size_t max_out);

/* spans から OTLP ExportTraceServiceRequest を組む。成功でバイト数、失敗で -1。 */
long otlp_traces_build(uint8_t *buf, size_t cap,
                       const char *service_name, const char *service_version,
                       const char *scope_name,
                       const otlp_span_t *spans, size_t nspans,
                       const otlp_method_meta_t *metas, size_t nmetas);

/* HTTP server span (kind=SERVER + http.* 属性、W3C trace context 伝播)。
 * OBI/semconv v1.41.0 互換の server/client/scheme/route 属性を追加。 */
typedef struct {
    uint8_t  trace_id[16];
    uint8_t  span_id[8];
    uint8_t  parent_span_id[8];
    bool     has_parent;
    uint64_t start_unix_ns;
    uint64_t end_unix_ns;
    const char *name;            /* span 名 (例 "GET /path" or "GET <route>") */
    const char *http_method;     /* http.request.method (NULL 可) */
    const char *url_path;        /* url.path (NULL 可) */
    int32_t     status_code;     /* http.response.status_code (<=0 は省略、>=500 で Span.status=ERROR) */
    const char *server_address;  /* server.address (getsockname 由来、NULL/空は省略) */
    int32_t     server_port;     /* server.port (<=0 は省略) */
    const char *client_address;  /* client.address (getpeername 由来、NULL/空は省略) */
    const char *url_scheme;      /* url.scheme (spinel server は "http" 固定、NULL/空は省略) */
    const char *route;           /* http.route (低カーディナリティ経路、NULL/空は省略) */
    /* L2–L8 横断相関の追加属性 (任意、省略可)。従来の span_fd 経路は tenant=NULL /
     * tcp_retransmits=-1 / tcp_server_sends=-1 を渡すので全て省略され、出力は byte 一致。 */
    const char *tenant;            /* L8 ビジネス文脈 (NULL/空は省略) -> attribute "tenant" */
    int64_t     tcp_established;    /* L4 4-tuple keyed ESTABLISHED 数 (<0 は省略) -> "net.tcp.established" */
    int64_t     tcp_state_changes; /* L4 4-tuple keyed 状態遷移数 (<0 は省略) -> "net.tcp.state_changes" */
} otlp_http_span_t;

/* 単一 HTTP server span を OTLP ExportTraceServiceRequest に組む。成功でバイト数、失敗で -1。 */
long otlp_traces_http_build(uint8_t *buf, size_t cap,
                            const char *service_name, const char *service_version,
                            const char *scope_name,
                            const otlp_http_span_t *span);

/* 任意ラベルの汎用 span (kind + 任意 KV 属性)。監査 (deny/path/lineage) を
 * span 化して Splunk O11y に直送するため (O11y は OTLP logs 直送不可、E291)。
 * E271 の「任意プローブ keyed メトリクスを任意ラベルで」の span 版。 */
typedef struct {
    uint8_t  trace_id[16];
    uint8_t  span_id[8];
    uint8_t  parent_span_id[8];
    bool     has_parent;
    uint64_t start_unix_ns;
    uint64_t end_unix_ns;
    const char     *name;    /* span 名 */
    int32_t         kind;    /* opentelemetry SpanKind (0 は INTERNAL に既定化) */
    bool            is_error;/* true で Span.status=ERROR (deny を APM で色分け) */
    const otlp_kv_t *attrs;  /* 任意 KV 属性 (semconv 等)、空文字 val は省略 */
    int             nattrs;
} otlp_generic_span_t;

/* 単一の汎用 span を OTLP ExportTraceServiceRequest に組む。成功でバイト数、失敗で -1。 */
long otlp_traces_generic_build(uint8_t *buf, size_t cap,
                               const char *service_name, const char *service_version,
                               const char *scope_name,
                               const otlp_generic_span_t *span);

/* 複数の汎用 span を 1 つの ResourceSpans/ScopeSpans にまとめて 1 リクエストに符号化
 * (「1 record = 1 POST」を潰すバッチ化の符号化側)。resource 属性 (service.*) は全 span 共通、
 * k8s.* 等は span 属性なので別 pod の span を 1 ResourceSpans に混在してよい (OTLP 意味論)。
 * 成功でバイト数、失敗で -1。nspans==1 は otlp_traces_generic_build と byte 一致。 */
long otlp_traces_generic_build_multi(uint8_t *buf, size_t cap,
                                     const char *service_name, const char *service_version,
                                     const char *scope_name,
                                     const otlp_generic_span_t *spans, size_t nspans);

/* ---- E312: マルチ span トレース組み立て (層 2、runtime) ----
 * 関連イベント (request window / off-CPU 待ち / DNS / connect / L7) を「共通 trace_id +
 * 親子リンク (parent_span_id)」の木にするための ID 生成プリミティブ。seed は splitmix64 の
 * 状態 (呼ぶたび前進、本番は wall^pid 等の非決定種、テストは固定)。probe/codegen は無変更。 */

/* root span: 新しい trace_id(16) + span_id(8) を割り当て、has_parent=false / parent_span_id=0。
 * start/end/name/attrs/kind は呼び出し側が別途設定する。 */
void otlp_span_new_root(otlp_generic_span_t *s, uint64_t *seed);

/* child span: parent と同じ trace_id、parent_span_id = parent->span_id、新しい span_id を割り当て、
 * has_parent=true。start/end/name/attrs/kind は呼び出し側が別途設定する (親 window 内に nest)。 */
void otlp_span_new_child(otlp_generic_span_t *child,
                         const otlp_generic_span_t *parent, uint64_t *seed);

/* 受信 traceparent (W3C "vv-<32hex>-<16hex>-ff") があれば **その trace_id を根**にし、
 * parent_span_id = 受信 span-id (呼び出し側の span)、has_parent=true にする (= 我々の span は
 * 分散トレースの子として nest)。無効/NULL なら otlp_span_new_root と同じ (生成)。span_id は常に
 * 新規割当。戻り値: 1=継承, 0=生成。 */
int otlp_span_root_from_traceparent(otlp_generic_span_t *s, const char *traceparent,
                                    uint64_t *seed);

/* E312 Step2: cross-record 子相関の述語。child の (tgid, ktime) が parent の request window
 * [start_ktime, start_ktime+dur_ns] 内で **かつ同 tgid** なら 1。parent_start_ktime==0
 * (window 不明・旧 record) は相関しない (0)。ktime は monotonic 生値 (unix 変換前) で比較。
 * 前提: 1 tid=1 リクエストの同期ハンドラ (sequential)。並行/非同期は best-effort (誤相関より
 * fallback = 単一 span 優先)。 */
int otlp_child_in_window(uint32_t child_tgid, uint64_t child_ktime,
                         uint32_t parent_tgid, uint64_t parent_start_ktime,
                         uint64_t parent_dur_ns);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_TRACES_H */
