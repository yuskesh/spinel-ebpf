# Hand-written protobuf decoder for ExportLogsServiceRequest. Zero
# dependencies: the wire format is only varints and length-delimited fields.
# It decodes exactly what the internal log schema needs:
#   resource.attributes["service.name"]                  (KeyValue/AnyValue)
#   LogRecord.time_unix_nano / severity_number / severity_text / body.string_value
# Every other field is skipped by wire type, so unknown fields never break it.
#
# Output is columnar ("batch, not objects"): one decode call appends in
# parallel to ts[] / severity[] / severity_text[] / service[] / body[].
#
# Field numbers come from opentelemetry-proto (fetch: SPNL_WITH_PROTO=1
# scripts/setup.sh):
#   ExportLogsServiceRequest.resource_logs = 1
#   ResourceLogs.resource = 1 / .scope_logs = 2
#   Resource.attributes = 1
#   ScopeLogs.log_records = 2
#   LogRecord.time_unix_nano = 1 (fixed64) / .severity_number = 2 /
#             .severity_text = 3 / .body = 5 / .observed_time_unix_nano = 11
#   KeyValue.key = 1 / .value = 2, AnyValue.string_value = 1

class OtlpLogsDecoder
  attr_reader :ts, :severity, :severity_text, :service, :body, :errors

  def initialize
    @ts = []
    @severity = []
    @severity_text = []
    @service = []
    @body = []
    @errors = 0
  end

  # ---- protobuf primitives (walking the String directly with getbyte; an
  #      earlier unpack("C*") Array walk allocated a 10k-element Array per call
  #      and was the main allocation cost) ----

  # Read a varint, return [value, new_pos]. value = -1 if malformed.
  def varint(b, pos, limit)
    v = 0
    shift = 0
    while pos < limit && shift <= 63
      byte = b.getbyte(pos)
      pos += 1
      v |= (byte & 0x7f) << shift
      return [v, pos] if (byte & 0x80) == 0
      shift += 7
    end
    @errors += 1
    [-1, limit]
  end

  def fixed64(b, pos, limit)
    if pos + 8 > limit
      @errors += 1
      return [-1, limit]
    end
    v = 0
    i = 7
    while i >= 0
      v = (v << 8) | b.getbyte(pos + i)
      i -= 1
    end
    [v, pos + 8]
  end

  def str_of(b, pos, len)
    b.byteslice(pos, len)
  end

  # Read a length-delimited field's length. Corruption (bad varint or a length
  # past the limit) is counted into @errors and returns -1 -- a truncated
  # payload must never be swallowed silently.
  def len_field(b, pos, limit)
    len, pos = varint(b, pos, limit)
    return [-1, pos] if len < 0            # varint 側で計上済み
    if pos + len > limit
      @errors += 1
      return [-1, pos]
    end
    [len, pos]
  end

  # Skip a field we do not decode, by wire type. Returns new_pos.
  def skip(b, pos, limit, wt)
    if wt == 0
      _v, pos = varint(b, pos, limit)
      pos
    elsif wt == 1
      pos + 8
    elsif wt == 2
      len, pos = len_field(b, pos, limit)
      len < 0 ? limit : pos + len
    elsif wt == 5
      pos + 4
    else
      @errors += 1
      limit
    end
  end

  # ---- message walkers ----

  # AnyValue.string_value (field 1, len-delim). "" when absent.
  def any_string(b, pos, limit)
    s = ""
    while pos < limit
      tag, pos = varint(b, pos, limit)
      return s if tag < 0
      f = tag >> 3
      wt = tag & 7
      if f == 1 && wt == 2
        len, pos = len_field(b, pos, limit)
        return s if len < 0
        s = str_of(b, pos, len)
        pos += len
      else
        pos = skip(b, pos, limit, wt)
      end
    end
    s
  end

  # KeyValue -> [key, string_value]
  def key_value(b, pos, limit)
    k = ""
    v = ""
    while pos < limit
      tag, pos = varint(b, pos, limit)
      return [k, v] if tag < 0
      f = tag >> 3
      wt = tag & 7
      if f == 1 && wt == 2
        len, pos = len_field(b, pos, limit)
        return [k, v] if len < 0
        k = str_of(b, pos, len)
        pos += len
      elsif f == 2 && wt == 2
        len, pos = len_field(b, pos, limit)
        return [k, v] if len < 0
        v = any_string(b, pos, pos + len)
        pos += len
      else
        pos = skip(b, pos, limit, wt)
      end
    end
    [k, v]
  end

  # Resource -> service.name from its attributes. "unknown" when absent.
  def resource_service(b, pos, limit)
    svc = "unknown"
    while pos < limit
      tag, pos = varint(b, pos, limit)
      return svc if tag < 0
      f = tag >> 3
      wt = tag & 7
      if f == 1 && wt == 2
        len, pos = len_field(b, pos, limit)
        return svc if len < 0
        k, v = key_value(b, pos, pos + len)
        svc = v if k == "service.name" && v != ""
        pos += len
      else
        pos = skip(b, pos, limit, wt)
      end
    end
    svc
  end

  # LogRecord -> append one row to the columns
  def log_record(b, pos, limit, svc)
    t = 0
    sev = 0
    sevtext = ""
    bodystr = ""
    while pos < limit
      tag, pos = varint(b, pos, limit)
      break if tag < 0
      f = tag >> 3
      wt = tag & 7
      if f == 1 && wt == 1
        t, pos = fixed64(b, pos, limit)
      elsif f == 2 && wt == 0
        sev, pos = varint(b, pos, limit)
      elsif f == 3 && wt == 2
        len, pos = len_field(b, pos, limit)
        break if len < 0
        sevtext = str_of(b, pos, len)
        pos += len
      elsif f == 5 && wt == 2
        len, pos = len_field(b, pos, limit)
        break if len < 0
        bodystr = any_string(b, pos, pos + len)
        pos += len
      else
        pos = skip(b, pos, limit, wt)
      end
    end
    @ts << t
    @severity << sev
    @severity_text << sevtext
    @service << svc
    @body << bodystr
  end

  # ScopeLogs
  def scope_logs(b, pos, limit, svc)
    while pos < limit
      tag, pos = varint(b, pos, limit)
      return if tag < 0
      f = tag >> 3
      wt = tag & 7
      if f == 2 && wt == 2
        len, pos = len_field(b, pos, limit)
        return if len < 0
        log_record(b, pos, pos + len, svc)
        pos += len
      else
        pos = skip(b, pos, limit, wt)
      end
    end
  end

  # ResourceLogs: resolve the resource (service name) first, then walk
  # scope_logs. protobuf does not guarantee field order, hence two passes.
  def resource_logs(b, pos, limit)
    svc = "unknown"
    p2 = pos
    while p2 < limit
      tag, p2 = varint(b, p2, limit)
      break if tag < 0
      f = tag >> 3
      wt = tag & 7
      if f == 1 && wt == 2
        len, p2 = len_field(b, p2, limit)
        break if len < 0
        svc = resource_service(b, p2, p2 + len)
        p2 += len
      else
        p2 = skip(b, p2, limit, wt)
      end
    end
    while pos < limit
      tag, pos = varint(b, pos, limit)
      return if tag < 0
      f = tag >> 3
      wt = tag & 7
      if f == 2 && wt == 2
        len, pos = len_field(b, pos, limit)
        return if len < 0
        scope_logs(b, pos, pos + len, svc)
        pos += len
      else
        pos = skip(b, pos, limit, wt)
      end
    end
  end

  # Entry point: consume an ExportLogsServiceRequest (binary String), return
  # the number of records appended.
  def decode(payload)
    n0 = @ts.length
    b = payload
    pos = 0
    limit = b.bytesize
    while pos < limit
      tag, pos = varint(b, pos, limit)
      break if tag < 0
      f = tag >> 3
      wt = tag & 7
      if f == 1 && wt == 2
        len, pos = len_field(b, pos, limit)
        break if len < 0
        resource_logs(b, pos, pos + len)
        pos += len
      else
        pos = skip(b, pos, limit, wt)
      end
    end
    @ts.length - n0
  end
end
