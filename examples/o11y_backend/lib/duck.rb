# Shared DuckDB FFI declarations and connection helpers.
#
# Anything that carries a 64-bit value is declared :long -- :int lowers to a
# C `int` (32-bit) and silently truncates, which surfaces the first time a
# nanosecond timestamp comes back through duckdb_value_int64.

module DUCK
  ffi_lib "duckdb"
  ffi_cflags "-Lvendor/duckdb -Ivendor/duckdb"
  ffi_cflags "native/o11y_duck_json.c"
  ffi_const :OK, 0
  ffi_func :duckdb_open,             [:str, :ptr], :int
  ffi_func :duckdb_connect,          [:ptr, :ptr], :int
  ffi_func :duckdb_query,            [:ptr, :str, :ptr], :int
  ffi_func :duckdb_row_count,        [:ptr], :long
  ffi_func :duckdb_value_int64,      [:ptr, :long, :long], :long
  ffi_func :duckdb_value_varchar,    [:ptr, :long, :long], :str
  ffi_func :duckdb_result_error,     [:ptr], :str
  ffi_func :duckdb_destroy_result,   [:ptr], :void
  ffi_func :duckdb_appender_create,  [:ptr, :str, :str, :ptr], :int
  ffi_func :duckdb_append_int64,     [:ptr, :long], :int
  ffi_func :duckdb_append_varchar,   [:ptr, :str], :int
  ffi_func :duckdb_appender_end_row, [:ptr], :int
  ffi_func :duckdb_appender_error,   [:ptr], :str
  ffi_func :duckdb_appender_destroy, [:ptr], :int
  ffi_func :duckdb_prepare,          [:ptr, :str, :ptr], :int
  ffi_func :duckdb_prepare_error,    [:ptr], :str
  ffi_func :duckdb_bind_int64,       [:ptr, :long, :long], :int
  ffi_func :duckdb_bind_varchar,     [:ptr, :long, :str], :int
  ffi_func :duckdb_execute_prepared, [:ptr, :ptr], :int
  ffi_func :duckdb_destroy_prepare,  [:ptr], :void
  ffi_func :odc_exec_json,           [:ptr, :int], :binstr  # execute + walk + serialize in one call
  ffi_buffer :db_out,   8
  ffi_buffer :conn_out, 8
  ffi_buffer :app_out,  8
  ffi_buffer :stmt_out, 8
  ffi_buffer :res,      256      # duckdb_result is caller-allocated; over-allocate (actual ~48B)
  ffi_read_ptr :read_ptr, 0
end

def duck_connect
  return nil unless DUCK.duckdb_open(":memory:", DUCK.db_out) == DUCK::OK
  db = DUCK.read_ptr(DUCK.db_out)
  return nil unless DUCK.duckdb_connect(db, DUCK.conn_out) == DUCK::OK
  DUCK.read_ptr(DUCK.conn_out)
end

def exec_sql(conn, sql)
  if DUCK.duckdb_query(conn, sql, DUCK.res) != DUCK::OK
    err = DUCK.duckdb_result_error(DUCK.res)
    DUCK.duckdb_destroy_result(DUCK.res)
    return err
  end
  DUCK.duckdb_destroy_result(DUCK.res)
  ""
end

# Run an aggregate that returns a single int. [err, value]
def duck_scalar(conn, sql)
  if DUCK.duckdb_query(conn, sql, DUCK.res) != DUCK::OK
    err = DUCK.duckdb_result_error(DUCK.res)
    DUCK.duckdb_destroy_result(DUCK.res)
    return [err, 0]
  end
  v = DUCK.duckdb_value_int64(DUCK.res, 0, 0)
  DUCK.duckdb_destroy_result(DUCK.res)
  ["", v]
end
