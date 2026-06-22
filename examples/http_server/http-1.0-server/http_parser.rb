# examples/http_server/http-1.0-server/http_parser.rb
#
# Minimal HTTP/1.0 request-line parser for the spinel HTTP server.
# Splits "GET /path HTTP/1.0" into method / path / version with light
# structural validation. Header parsing is intentionally out of scope —
# the server reads + discards header lines until an empty line
# arrives, then dispatches based on this parsed structure.
#
# Designed to run identically under CRuby and spinel so a single
# parser_test.rb run can be diffed against CRuby's reference output.

class HttpRequest
  # `valid` is 1 when the request line parsed into 3 whitespace-separated
  # tokens and the version is one of HTTP/1.0 / HTTP/1.1. Higher-level
  # rejection (unsupported method, malformed path) is the router's job.
  attr_reader :verb, :path, :version, :valid

  def initialize(method, path, version, valid)
    @verb  = method
    @path    = path
    @version = version
    @valid   = valid
  end
end

# Parse a single request line. The caller must have already stripped any
# trailing CRLF (sp_net_read_line does this). Returns an HttpRequest with
# `valid=0` for any structural error so the router can produce a 400
# without needing to handle nil.
def parse_request_line(line)
  parts = line.split(" ")
  if parts.length != 3
    return HttpRequest.new("", "", "", 0)
  end
  m = parts[0]
  p = parts[1]
  v = parts[2]

  valid = 1
  if v != "HTTP/1.0" && v != "HTTP/1.1"
    valid = 0
  end
  # Path must start with "/" (absolute-path form per RFC 1945 §5.1.2).
  # Absolute-URI form ("http://...") is not supported here.
  if p.length == 0 || p[0] != "/"
    valid = 0
  end

  HttpRequest.new(m, p, v, valid)
end
