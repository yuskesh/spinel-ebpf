# parse_request_line regression test.
#
# Runs the same Ruby under both CRuby and the spinel-compiled binary and
# confirms that stdout is byte-identical. This follows the same
# "reference Ruby vs spinel build" pattern that spinel's own test harness uses.

require_relative "../../examples/http_server/http-1.0-server/http_parser"

def show(label, req)
  puts label + ": method=" + req.verb + " path=" + req.path + " version=" + req.version + " valid=" + req.valid.to_s
end

# --- happy path ---
show("get_root",       parse_request_line("GET / HTTP/1.0"))
show("get_health",     parse_request_line("GET /health HTTP/1.0"))
show("get_deep_path",  parse_request_line("GET /a/b/c HTTP/1.0"))
show("get_v11",        parse_request_line("GET / HTTP/1.1"))
show("post",           parse_request_line("POST /api HTTP/1.0"))
show("head",           parse_request_line("HEAD /robots.txt HTTP/1.0"))
show("delete",         parse_request_line("DELETE /items/42 HTTP/1.1"))

# --- malformed: structural failures all yield valid=0 ---
show("empty_line",     parse_request_line(""))
show("missing_path",   parse_request_line("GET HTTP/1.0"))
show("extra_token",    parse_request_line("GET / HTTP/1.0 trailing"))
show("bad_version",    parse_request_line("GET / HTTP/2.0"))
show("no_version",     parse_request_line("GET /"))
show("relative_path",  parse_request_line("GET foo HTTP/1.0"))
show("uppercase_get",  parse_request_line("get / HTTP/1.0"))  # case-sensitive by spec
