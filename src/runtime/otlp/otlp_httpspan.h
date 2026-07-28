/*
 * otlp_httpspan.h — HTTP server span + W3C trace context 伝播 (P003 option)
 *
 * spinel-compiled な HTTP サーバ (Ruby) から呼ぶ FFI。受信リクエストの `traceparent`
 * ヘッダを取り込み、リクエスト 1 件 = SERVER span を作って OTLP traces で送る。
 * libbpf 非依存 (otlp_traces/json + transport のみ)。service 名は env OTEL_SERVICE_NAME。
 */
#ifndef SPNL_OTLP_HTTPSPAN_H
#define SPNL_OTLP_HTTPSPAN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* wall-clock 現在時刻 (unix nanoseconds)。span の start/end 計測に使う。 */
uint64_t spnl_otlp_now_unix_ns(void);

/*
 * 受信 traceparent (W3C "00-<32hex>-<16hex>-<2hex>"、NULL/空/不正なら新規 trace) を取り込み、
 * OBI/semconv v1.41.0 互換の SERVER span を 1 つ OTLP traces で endpoint に送る。
 *
 *  - fd >= 0 のとき accept 済み client socket から getsockname → server.address/server.port、
 *    getpeername → client.address を自動導出 (IPv4/IPv6、inet_ntop)。fd < 0 なら省略。
 *  - url.scheme は "http" 固定 (spinel server は平文)。
 *  - route が非 NULL/非空なら span 名 = "<METHOD> <route>" + http.route 属性、そうでなければ
 *    span 名 = "<METHOD> <target>" (path fallback)。
 *  - status_code >= 500 で Span.status = ERROR。
 *
 * 成功で HTTP status (200 等)、失敗で -1。
 */
int spnl_otlp_http_span_fd(int fd, const char *traceparent, const char *method,
                           const char *target, const char *route, int status_code,
                           uint64_t start_unix_ns, uint64_t end_unix_ns, const char *endpoint);

/*
 * L2–L8 横断相関付き SERVER span。spnl_otlp_http_span_fd に加えて、L8 の tenant と、
 * L3/L4 の 4-tuple keyed メトリクス (tcp_established / tcp_state_changes) を同一 span の属性
 * (tenant / net.tcp.established / net.tcp.state_changes) として載せる。established/state_changes
 * が負のときは該当属性を省略。userspace 結合デモ (xlayer_correlate.rb) 用。成功で HTTP status。
 */
int spnl_otlp_http_span_fd_x(int fd, const char *traceparent, const char *method,
                             const char *target, const char *route, int status_code,
                             uint64_t start_unix_ns, uint64_t end_unix_ns, const char *tenant,
                             long long tcp_established, long long tcp_state_changes,
                             const char *endpoint);

/*
 * 後方互換 wrapper: fd=-1 / route=NULL で spnl_otlp_http_span_fd を呼ぶ (E270 の元 API)。
 * SERVER span (name="<method> <target>"、http.request.method / url.path / http.response.status_code)。
 */
int spnl_otlp_http_span(const char *traceparent, const char *method, const char *target,
                        int status_code, uint64_t start_unix_ns, uint64_t end_unix_ns,
                        const char *endpoint);

/*
 * 蓄積した http.server.request.duration (秒・明示バケット Histogram、OBI 同一バケット
 * [0,0.005,...,10]、CUMULATIVE、E272 S2) を OTLP metrics で endpoint に送る。
 * シリーズは spnl_otlp_http_span_fd/_http_span 呼び出し毎に (t1-t0) を積む。属性は
 * http.request.method / http.route (route があるとき) / http.response.status_code。
 * 成功で HTTP status、失敗で -1。
 */
int spnl_otlp_http_metrics_push(const char *endpoint);

/*
 * 監査 (deny/path/lineage) を 1 span 化して直送 (O11y は OTLP logs 直送不可、E291)。
 *   exe_path -> process.executable.path (semconv)、file_path -> file.path (semconv)、
 *   parent_exe_path -> process.parent.executable.path (独自 key)、verdict -> verdict (独自 key)。
 *   deny != 0 で Span.status=ERROR (APM で色分け)。traceparent を継続 (E274 相関)。
 * span 名 "file_open <file_path>"、kind=INTERNAL。成功で HTTP status、失敗で -1。
 */
int spnl_otlp_audit_file_span(const char *traceparent,
                              const char *exe_path, const char *parent_exe_path,
                              const char *file_path, const char *verdict, int deny,
                              uint64_t start_unix_ns, uint64_t end_unix_ns,
                              const char *endpoint);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_HTTPSPAN_H */
