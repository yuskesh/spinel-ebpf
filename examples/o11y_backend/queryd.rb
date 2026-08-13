# queryd -- catalog-driven query daemon.
#
#   POST /api/v1/query  ... two entry forms:
#     {"q": "logs | severity >= error | stats count() by service"}   ... pipeline language -> AST -> SQL
#     {"service": "api", "severity_min": 17, "start":..., "end":..., "limit":..., "format":...}
#                                                                    ... structured filters (fixed shape)
#   GET /healthz
#
# Discipline: every user value is bound. The only strings concatenated into
# SQL are catalog-owned segment paths (server-generated) and a validated
# integer limit. Result walking + JSON serialization is one C-wrapper call
# (odc_exec_json in lib/duck). The segment set is read from the catalog's
# live list on every query, which stays consistent with compaction through
# its transaction.
#
# Build:
#   cd examples/o11y_backend
#   ruby ../../bin/spinel-ebpf compile queryd.rb --native-only --build -o build
# Run:
#   LD_LIBRARY_PATH=vendor/duckdb ./build/queryd <port=4319> <data_dir=data>

require "json"
require_relative "lib/net"
require_relative "lib/http"
require_relative "lib/duck"
require_relative "lib/catalog"
require_relative "lib/query_ast"

COLS = "ts, service, severity, severity_text, body"
QUERY_COLUMNS_JSON = "[{\"name\":\"ts\",\"type\":\"time_ns\"},{\"name\":\"service\",\"type\":\"string\"}," \
                     "{\"name\":\"severity\",\"type\":\"number\"},{\"name\":\"severity_text\",\"type\":\"string\"}," \
                     "{\"name\":\"body\",\"type\":\"string\"}]"
END_NS_MAX = 4611686018427387904   # 2^62: sentinel for "no end given"

# The catalog live list -> a `read_parquet([...])` FROM fragment. "" when no segments.
def source_from_catalog(catalog)
  err, lives = catalog.live
  return [err, ""] if err != ""
  return ["", ""] if lives.length == 0
  list = lives.map { |r| "'" + r[0].to_s + "'" }.join(",")
  ["", "SELECT " + COLS + " FROM read_parquet([" + list + "])"]
end

# prepare -> bind (time range + extras) -> one-call execute+serialize. [err, rows_json]
def exec_bound(conn, sql, start_ns, end_ns, extra_binds, objects)
  if DUCK.duckdb_prepare(conn, sql, DUCK.stmt_out) != DUCK::OK
    stmt = DUCK.read_ptr(DUCK.stmt_out)
    err = "prepare: " + DUCK.duckdb_prepare_error(stmt)
    DUCK.duckdb_destroy_prepare(DUCK.stmt_out)
    return [err, ""]
  end
  stmt = DUCK.read_ptr(DUCK.stmt_out)
  bidx = 1
  DUCK.duckdb_bind_int64(stmt, bidx, start_ns); bidx += 1
  DUCK.duckdb_bind_int64(stmt, bidx, end_ns);   bidx += 1
  extra_binds.each do |b|
    if b[0] == "i"
      DUCK.duckdb_bind_int64(stmt, bidx, b[1])
    else
      DUCK.duckdb_bind_varchar(stmt, bidx, b[1])
    end
    bidx += 1
  end
  rows_json = DUCK.odc_exec_json(stmt, objects ? 1 : 0)
  DUCK.duckdb_destroy_prepare(DUCK.stmt_out)
  return ["execute: " + rows_json, ""] if rows_json.start_with?("{\"__error\"")
  ["", rows_json]
end

# The pipeline-language path ({"q": ...})
def handle_ast_query(fd, conn, src, q, start_ns, end_ns, keep)
  aerr, asql, abinds = QueryAst.compile(q["q"], src)
  if aerr != ""
    http_json_error(fd, "400 Bad Request", aerr, keep)
    return
  end
  xerr, rows_json = exec_bound(conn, asql, start_ns, end_ns, abinds, true)
  if xerr != ""
    http_json_error(fd, "500 Internal Server Error", xerr, keep)
  else
    http_json(fd, "200 OK", "{\"rows\":" + rows_json + "}", keep)
  end
end

# The structured-filter path (service / severity_min / limit / format)
def handle_structured_query(fd, conn, src, q, start_ns, end_ns, keep)
  service = q["service"] != nil ? q["service"] : ""
  sev_min = q["severity_min"] != nil ? q["severity_min"] : 0
  limit   = q["limit"] != nil ? q["limit"] : 100
  fmt     = q["format"] != nil ? q["format"] : "columns"
  limit = 1 if limit < 1
  limit = 10000 if limit > 10000
  if fmt != "columns" && fmt != "objects"
    http_json_error(fd, "400 Bad Request", "unknown format '#{fmt}' (supported: columns, objects)", keep)
    return
  end
  objects = fmt == "objects"
  proj = objects ? "ts // 1000000 AS ts_ms, service, severity, severity_text, body" : COLS
  sql = "SELECT " + proj + " FROM (" + src + ") WHERE ts >= ? AND ts < ?"
  binds = []
  if service != ""
    sql = sql + " AND service = ?"
    binds << ["s", service]
  end
  if sev_min > 0
    sql = sql + " AND severity >= ?"
    binds << ["i", sev_min]
  end
  sql = sql + " ORDER BY ts LIMIT " + limit.to_s
  xerr, rows_json = exec_bound(conn, sql, start_ns, end_ns, binds, objects)
  if xerr != ""
    http_json_error(fd, "500 Internal Server Error", xerr, keep)
  elsif objects
    http_json(fd, "200 OK", "{\"rows\":" + rows_json + "}", keep)
  else
    http_json(fd, "200 OK", "{\"columns\":" + QUERY_COLUMNS_JSON + ",\"rows\":" + rows_json + "}", keep)
  end
end

def handle_query(fd, conn, catalog, head, body)
  keep = head.keep
  if head.line.start_with?("POST /api/v1/query")
    q = body.length > 0 ? JSON.parse(body) : {}
    start_ns = q["start"] != nil ? q["start"] : 0
    end_ns   = q["end"]   != nil ? q["end"]   : END_NS_MAX
    serr, src = source_from_catalog(catalog)
    if serr != ""
      http_json_error(fd, "500 Internal Server Error", serr, keep)
    elsif src == ""
      http_json(fd, "200 OK", "{\"rows\":[]}", keep)
    elsif q["q"] != nil
      handle_ast_query(fd, conn, src, q, start_ns, end_ns, keep)
    else
      handle_structured_query(fd, conn, src, q, start_ns, end_ns, keep)
    end
  elsif head.line.start_with?("GET /healthz")
    http_json(fd, "200 OK", "{\"ok\":true}", keep)
  else
    http_json_error(fd, "404 Not Found",
                    "unknown path (have: POST /api/v1/query, GET /healthz)", keep)
  end
end

# ---- main ----

port     = ARGV.length >= 1 ? ARGV[0].to_i : 4319
data_dir = ARGV.length >= 2 ? ARGV[1] : "data"

conn = duck_connect
if conn == nil
  puts "[queryd] duckdb open failed"
  exit 1
end
catalog = Catalog.new
cerr = catalog.open(data_dir + "/catalog.db")
if cerr != ""
  puts "[queryd] catalog: " + cerr
  exit 1
end

lfd = Net.sp_net_listen(port, 0)
if lfd < 0
  puts "[queryd] listen failed on #{port}"
  exit 1
end
puts "[queryd pid=#{Net.sp_net_getpid}] ready on #{port} (catalog=#{data_dir}/catalog.db)"

# A single blocking loop is enough for queries; the load lives on the ingest side
loop do
  fd = Net.sp_net_accept(lfd)
  next if fd < 0
  loop do
    head = http_read_head(fd)
    break if head == nil
    body = http_read_body(fd, head.clen)
    handle_query(fd, conn, catalog, head, body)
    break unless head.keep
  end
  Net.sp_net_rl_close(fd)
end
