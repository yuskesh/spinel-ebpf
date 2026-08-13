# o11y_backend — an observability backend written in Ruby (spinel AOT)

Receives logs over OTLP, lands them in Parquet segments, answers a small
pipeline query language, and shows up in Grafana. Runs on **Ruby plus
libduckdb and libsqlite3** — no Ruby VM, no collector in front.

```text
OTLP client ── HTTP :4318 / gRPC :4317 ──> ingestd (fork worker × N, epoll + keepalive,
   │                                        sk_reuseport BPF worker selection [opt-in])
   │                                          │ decode → DuckDB appender → rotate
   │                                          ▼
   │                                    data/*.parquet  ◄── compactor (resident, periodic merge)
   │                                          │
   │                                    catalog.db (SQLite — single source of truth
   │                                          │             for live segments)
Grafana / curl ── POST /api/v1/query ──> queryd ── read_parquet([live…]) → bound SQL
```

Both OTLP transports are served in every combination of
{HTTP/1.1, gRPC} × {plaintext, TLS} × {identity, gzip}; an OpenTelemetry SDK
or collector pointed at the default endpoints works without configuration
changes.

The interesting part is where the lines are drawn. Ruby owns every decision —
schemas, rotation and compaction policy, the query language, what an error
says. C appears only as four thin shims for boundaries a safe Ruby subset
should not own: nghttp2's callback-driven HTTP/2 state machine, zlib's
inflate, mbedTLS session state, and one DuckDB result-serialization call that
must call `duckdb_free` on memory the library hands over. And one function is
eBPF: the kernel picks which worker gets each connection, written in the same
five lines of Ruby as everything else and compiled by the same toolchain.

## File map

| path | what it is |
|---|---|
| `ingestd.rb` | ingest daemon (fork topology of workers + compactor, eBPF worker selection) |
| `queryd.rb` | query daemon (catalog-driven, pipeline language + structured filters) |
| `lib/net.rb` | socket/epoll/fork FFI declarations |
| `lib/http.rb` | HTTP/1.x read/write incl. keepalive policy, plaintext + TLS variants |
| `lib/h2.rb` + `native/o11y_h2.c` | OTLP/gRPC receive (nghttp2 h2c; callbacks stay in C) |
| `lib/gzip.rb` + `native/o11y_gzip.c` | gzip inflate (gRPC frames and HTTP Content-Encoding) |
| `lib/tls.rb` + `native/o11y_tls.c` | TLS termination (mbedTLS, per-port ALPN, 5s I/O deadline) |
| `lib/duck.rb` | DuckDB FFI (64-bit values declared `:long` — `:int` is C int and truncates silently) |
| `lib/catalog.rb` | SQLite segment catalog (live → dead → purge state machine) |
| `lib/decoder.rb` | hand-written OTLP protobuf decoder (byte-walk, columnar output) |
| `lib/query_ast.rb` | pipeline language → allowlist + bind SQL compiler |
| `native/o11y_duck_json.c` | DuckDB result → JSON in one call (owns `duckdb_free`) |
| `scripts/` | libduckdb fetch / test payload generation / Grafana provisioning |

## Quickstart (Linux build environment)

System prerequisites (Debian/Ubuntu): `libsqlite3-dev libnghttp2-dev
zlib1g-dev` plus the toolchain the repo already needs (clang, ruby;
libbpf-dev and bpftool for the eBPF side). libduckdb is not packaged by
distros and is fetched by script below; mbedTLS builds from the deps/
checkout.

```sh
# once, from the repo root:
SPNL_WITH_PROTO=1 scripts/setup.sh        # spinel + opentelemetry-proto
sh scripts/build-mbedtls.sh               # TLS static libs (only needed for TLS mode)

cd examples/o11y_backend
sh scripts/fetch-duckdb.sh                # vendor/duckdb (version recorded in VERSION)
sh scripts/gen-test-payload.sh            # tests/payload_logs.bin (needs protoc)

# build (ingestd is eBPF-mixed, queryd is native-only)
ruby ../../bin/spinel-ebpf compile ingestd.rb --build -o build
ruby ../../bin/spinel-ebpf compile queryd.rb --native-only --build -o build

# run
mkdir -p data
LD_LIBRARY_PATH=vendor/duckdb O11Y_WORKERS=4 ./build/ingestd 4318 100000 data &
LD_LIBRARY_PATH=vendor/duckdb ./build/queryd 4319 data &
# TLS termination: set both O11Y_TLS_CERT and O11Y_TLS_KEY to make 4317/4318 TLS listeners

# ingest and query
curl -X POST --data-binary @tests/payload_logs.bin \
     -H 'Content-Type: application/x-protobuf' http://127.0.0.1:4318/v1/logs
curl -X POST -H 'Content-Type: application/json' \
     -d '{"q":"logs | severity >= error | stats count() by service"}' \
     http://127.0.0.1:4319/api/v1/query
```

For Grafana, `sh scripts/provision-grafana.sh <grafana> <queryd>` installs an
Infinity datasource and a logs dashboard against the query API
(`"format":"objects"` returns rows Infinity consumes directly).

## Rules the code follows everywhere

- **User values are always bound.** The only strings concatenated into SQL are
  server-generated segment paths and a validated integer limit. The query
  language compiles identifiers and operators through allowlists.
- **Errors name the subject and the remedy.** A rejected request says what was
  wrong and what would have been accepted (`unknown field 'endpoint'
  (supported: service, …)`).
- **Feed every parser broken input.** The decoder, the gzip path and the TLS
  accept path each carry negative tests because their worst failures are
  silent ones: a truncated protobuf that reports success with zero records, a
  plaintext client that pins a TLS handshake forever.
- **64-bit crosses FFI as `:long`.** `:int` lowers to a 32-bit C int and
  truncates without a word; it survives every test that uses small numbers and
  breaks on the first nanosecond timestamp.
- **Visibility boundary = segment.** Rows not yet rotated out of a worker's
  memory table are not queryable; tune rotation thresholds accordingly.

## Known limits

Partial reads from slow plaintext clients block a worker (TLS connections
carry a 5-second I/O deadline); no SIGCHLD reaping or graceful shutdown; the
BPF worker-selection modulo is a literal that must match `O11Y_WORKERS`; the
pipeline language splits stages on `|` before quoting, so a quoted `|` in a
`contains` pattern mis-parses; logs only (metrics and traces are future work);
no mTLS or certificate rotation.
