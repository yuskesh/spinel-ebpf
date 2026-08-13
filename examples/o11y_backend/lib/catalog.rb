# Segment catalog: the single source of truth for which Parquet segments are
# live, kept in SQLite (the control-plane database of this example).
#
# Why it exists: file-glob discovery has an unfixable race against compaction
# (between deleting the inputs and renaming the output, a concurrent query sees
# either duplicates or a gap). The catalog closes it with a transaction plus
# deferred deletion:
#
#   register: live -> (compaction swap, one txn) dead -> (next cycle) file+row purged
#
# Concurrency: N ingest workers + a compactor + the query server touch the same
# database from separate processes, hence WAL mode and a 5s busy timeout. Write
# transactions are kept short.
#
# sqlite3_exec needs a C callback, which this FFI cannot express, so everything
# goes through prepare/step/column. SQLITE_TRANSIENT is (void*)-1, passed as a
# :long -1.

module SQLITE
  ffi_lib "sqlite3"
  ffi_const :OK, 0
  ffi_const :ROW, 100
  ffi_const :DONE, 101
  ffi_func :sqlite3_open,         [:str, :ptr], :int
  ffi_func :sqlite3_busy_timeout, [:ptr, :int], :int
  ffi_func :sqlite3_prepare_v2,   [:ptr, :str, :int, :ptr, :ptr], :int
  ffi_func :sqlite3_step,         [:ptr], :int
  ffi_func :sqlite3_column_int64, [:ptr, :int], :long
  ffi_func :sqlite3_column_text,  [:ptr, :int], :str
  ffi_func :sqlite3_bind_int64,   [:ptr, :int, :long], :int
  ffi_func :sqlite3_bind_text,    [:ptr, :int, :str, :int, :long], :int
  ffi_func :sqlite3_finalize,     [:ptr], :int
  ffi_func :sqlite3_errmsg,       [:ptr], :str
  ffi_buffer :db_out,   8
  ffi_buffer :stmt_out, 8
  ffi_buffer :tail_out, 8
  ffi_read_ptr :read_ptr, 0
end

class Catalog
  def initialize
    @db = nil
  end

  def errmsg
    "sqlite: " + SQLITE.sqlite3_errmsg(@db)
  end

  # binds: [["s", v] | ["i", v], ...]. Result rows follow want_types ("s"/"i").
  # Returns [err, rows].
  def q(sql, binds, want_types)
    if SQLITE.sqlite3_prepare_v2(@db, sql, -1, SQLITE.stmt_out, SQLITE.tail_out) != SQLITE::OK
      return [errmsg + " in: " + sql, []]
    end
    stmt = SQLITE.read_ptr(SQLITE.stmt_out)
    i = 0
    while i < binds.length
      b = binds[i]
      if b[0] == "i"
        SQLITE.sqlite3_bind_int64(stmt, i + 1, b[1])
      else
        SQLITE.sqlite3_bind_text(stmt, i + 1, b[1], -1, -1)
      end
      i += 1
    end
    rows = []
    loop do
      rc = SQLITE.sqlite3_step(stmt)
      break if rc == SQLITE::DONE
      if rc != SQLITE::ROW
        e = errmsg
        SQLITE.sqlite3_finalize(stmt)
        return [e + " in: " + sql, []]
      end
      row = []
      c = 0
      while c < want_types.length
        row << (want_types[c] == "i" ? SQLITE.sqlite3_column_int64(stmt, c) :
                                       SQLITE.sqlite3_column_text(stmt, c))
        c += 1
      end
      rows << row
    end
    SQLITE.sqlite3_finalize(stmt)
    ["", rows]
  end

  def exec(sql, binds)
    err, _rows = q(sql, binds, [])
    err
  end

  # Returns err ("" = success).
  def open(path)
    return "sqlite3_open failed" unless SQLITE.sqlite3_open(path, SQLITE.db_out) == SQLITE::OK
    @db = SQLITE.read_ptr(SQLITE.db_out)
    SQLITE.sqlite3_busy_timeout(@db, 5000)
    err = exec("PRAGMA journal_mode=WAL", [])   # returns one row, which q() discards
    return err if err != ""
    exec("CREATE TABLE IF NOT EXISTS segments(" \
         "path TEXT PRIMARY KEY, rows INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'live')", [])
  end

  def register(path, nrows)
    exec("INSERT INTO segments(path, rows, state) VALUES(?, ?, 'live')",
         [["s", path], ["i", nrows]])
  end

  # [err, [[path, rows], ...]]
  def live
    q("SELECT path, rows FROM segments WHERE state = 'live' ORDER BY path", [], ["s", "i"])
  end

  # [err, [path, ...]]
  def dead_paths
    err, rows = q("SELECT path FROM segments WHERE state = 'dead'", [], ["s"])
    [err, rows.map { |r| r[0].to_s }]
  end

  def purge_dead(path)
    exec("DELETE FROM segments WHERE path = ? AND state = 'dead'", [["s", path]])
  end

  # Atomic replacement for compaction: olds -> dead, new -> live, one txn.
  def swap(old_paths, new_path, new_rows)
    err = exec("BEGIN IMMEDIATE", [])
    return err if err != ""
    old_paths.each do |p|
      err = exec("UPDATE segments SET state = 'dead' WHERE path = ?", [["s", p]])
      if err != ""
        exec("ROLLBACK", [])
        return err
      end
    end
    err = register(new_path, new_rows)
    if err != ""
      exec("ROLLBACK", [])
      return err
    end
    exec("COMMIT", [])
  end
end
