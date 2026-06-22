# examples/http_server/sendfile_demo/http_parser.rb
#
# Minimal HTTP/1.0 request-line parser (verbatim copy of the basic HTTP/1.0
# server's parser; each example keeps a self-contained copy). Splits
# "GET /path HTTP/1.0" into method / path / version with light
# structural validation.

class HttpRequest
  attr_reader :verb, :path, :version, :valid

  def initialize(method, path, version, valid)
    @verb    = method
    @path    = path
    @version = version
    @valid   = valid
  end
end

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
  if p.length == 0 || p[0] != "/"
    valid = 0
  end

  HttpRequest.new(m, p, v, valid)
end
