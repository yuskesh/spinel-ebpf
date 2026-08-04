# frozen_string_literal: true
#
# Metrics declared on a record channel -- and, above all, the REFUSALS.
#
# The whole safety argument here is that a metric label must have a bound the
# generator can compute from a declaration, before any data exists, because the
# failure mode (an unbounded label producing one time series per distinct value)
# is invisible locally: the spans stay correct, the process exits 0, and the cost
# lands in somebody's backend.
#
# An argument like that is worth exactly as much as its negative controls. If a
# bug made the checker permissive, every "this cannot be declared" claim in
# record_schema.h would quietly become false while every test stayed green. So
# each refusal below is exercised by feeding the generator a REAL declaration
# (record_schema.h with one edit) and asserting it dies, and with a message that
# names the reason rather than "error".
#
# The positive control is the committed header itself: it must still build and
# generate, or the negative controls could be passing because nothing compiles.
require "minitest/autorun"
require "json"
require "tmpdir"
require "open3"

class RecordMetricTest < Minitest::Test
  ROOT   = File.expand_path("../..", __dir__)
  SCHEMA = File.join(ROOT, "src/codegen_c/record_schema.h")
  GEN    = File.join(ROOT, "tools/gen_record_mirror.c")
  JSON_F = File.join(ROOT, "src/spinel_ebpf/record_schema_gen.json")

  # Build the generator against a (possibly edited) copy of the schema header and
  # run it. Returns [ok, combined output].
  def generate(schema_text)
    Dir.mktmpdir("recmetric") do |dir|
      FileUtils_mkdir_p(File.join(dir, "src/codegen_c"))
      FileUtils_mkdir_p(File.join(dir, "tools"))
      File.write(File.join(dir, "src/codegen_c/record_schema.h"), schema_text)
      File.write(File.join(dir, "tools/gen_record_mirror.c"), File.read(GEN))
      bin = File.join(dir, "gen")
      out, st = Open3.capture2e(ENV["CC"] || "cc", "-O2", "-o", bin,
                                File.join(dir, "tools/gen_record_mirror.c"))
      return [false, "compile failed: #{out}"] unless st.success?
      out, st = Open3.capture2e(bin)
      [st.success?, out]
    end
  end

  def FileUtils_mkdir_p(p)
    require "fileutils"
    FileUtils.mkdir_p(p)
  end

  def schema = File.read(SCHEMA)

  # Replace `from` on the first declared label of the http duration metric.
  def with_http_label_from(prop)
    schema.sub('{ "http.request.method", "method", "semconv",',
               %({ "http.request.method", #{prop.inspect}, "semconv",))
  end

  # --- positive control -----------------------------------------------------

  def test_the_committed_declaration_generates
    ok, out = generate(schema)
    assert ok, "committed record_schema.h did not generate: #{out}"
    assert_includes out, "spnl.http.client.request.duration"
    assert_includes out, "SPNL_RECMETRIC_TOTAL_SERIES_BOUND"
  end

  # --- the refusals: an unbounded label must not be declarable ---------------

  def test_a_label_on_an_unbounded_property_is_refused
    # `path` is the archetype: measured, its distinct count grew 1:1 with the
    # number of records (50 -> 50, 100 -> 100).
    src = with_http_label_from("path").sub(
      "    cc_metric_http_method_values,\n" \
      "    (int)(sizeof cc_metric_http_method_values / sizeof cc_metric_http_method_values[0]),\n" \
      "    \"_OTHER\",",
      "    (const char *const *)0, 0, (const char *)0,")
    ok, out = generate(src)
    refute ok, "a label with no bound at all was accepted"
    assert_match(/no permitted set and does not read a code_to_name derivation/, out)
    assert_match(/still available on the span/, out,
                 "refusal must say where the value is still obtainable")
  end

  def test_a_label_on_an_open_value_map_is_refused
    # `tcp_state` renders an unnamed code as "unnamed(%ld)" -- correct for a span
    # attribute (the span keeps the number) and disqualifying for a label, because
    # every unnamed code becomes its own series. Same record, same byte as
    # `direction`, opposite verdict: the difference is in the DECLARATION.
    src = schema.sub('{ "spnl.conn.direction", "direction", "spinel", NULL, 0, NULL,',
                     '{ "spnl.conn.direction", "tcp_state", "spinel", NULL, 0, NULL,')
    ok, out = generate(src)
    refute ok, "a label over a value map with a %ld fallback was accepted"
    assert_match(/`unknown` rendering keeps the number/, out)
  end

  def test_a_label_on_an_unpublished_property_is_refused
    # `daddr` is a real field, deliberately not exposed (the v4/v6 branch belongs
    # to layer 2). A metric may not reach past the published set either.
    ok, out = generate(with_http_label_from("daddr"))
    refute ok, "a label read a property the channel does not publish"
    assert_match(/does not publish/, out)
  end

  def test_a_declared_set_without_a_fallback_is_refused
    src = schema.sub("    \"_OTHER\",\n    \"the same token spnl_http_method()",
                     "    (const char *)0,\n    \"the same token spnl_http_method()")
    ok, out = generate(src)
    refute ok, "a permitted set without a fallback was accepted"
    assert_match(/no fallback/, out)
  end

  def test_a_histogram_over_a_string_property_is_refused
    src = schema.sub('"duration", "spnl.http.client.request.duration", "histogram", "s",' \
                     "\n    \"duration_ns\", \"ns\", \"otel_duration_s\",",
                     '"duration", "spnl.http.client.request.duration", "histogram", "s",' \
                     "\n    \"path\", \"ns\", \"otel_duration_s\",")
    ok, out = generate(src)
    refute ok, "a histogram took its value from a string property"
    assert_match(/not numeric/, out)
  end

  def test_an_unknown_metric_kind_is_refused
    src = schema.sub('"duration", "spnl.http.client.request.duration", "histogram", "s",',
                     '"duration", "spnl.http.client.request.duration", "gauge", "s",')
    ok, out = generate(src)
    refute ok, "an unencodable metric kind was accepted"
    assert_match(/unknown metric kind/, out)
  end

  def test_an_unknown_unit_conversion_is_refused
    # ns bucketed against second boundaries is not an absent histogram, it is a
    # wrong one: every request lands in the +inf bucket and the graph looks fine.
    src = schema.sub("\n    \"duration_ns\", \"ns\", \"otel_duration_s\",",
                     "\n    \"duration_ns\", \"us\", \"otel_duration_s\",")
    ok, out = generate(src)
    refute ok, "an unknown unit conversion was accepted"
    assert_match(/unit conversion the generator does not know/, out)
  end

  def test_exceeding_the_runtime_series_capacity_is_refused
    # The rule that makes "declarable but not exportable" inexpressible: the
    # accumulator is fixed-size, so a declaration that could outgrow it must not
    # build. Widen the status set past the capacity to prove the check bites.
    codes = (600..900).map { |c| %("#{c}") }.join(", ")
    src = schema.sub('  "500", "502", "503", "504",',
                     %(  "500", "502", "503", "504", #{codes},))
    ok, out = generate(src)
    refute ok, "a declaration above the runtime's series capacity was accepted"
    assert_match(/more time series than the runtime can hold/, out)
    assert_match(/narrow a label's permitted set or drop a label/, out,
                 "refusal must say what to do about it")
  end

  def test_a_counter_declaring_a_value_is_refused
    src = schema.sub('{ "count", "spnl.conn.count", "counter", "{connection}", NULL, NULL, NULL,',
                     '{ "count", "spnl.conn.count", "counter", "{connection}", "cgid", "ns", NULL,')
    ok, out = generate(src)
    refute ok, "a counter declared a value"
    assert_match(/counter counts records/, out)
  end

  # --- what the declaration publishes ---------------------------------------

  def doc = JSON.parse(File.read(JSON_F))

  def metrics
    doc["channels"].flat_map { |c| Array(c["metrics"]).map { |m| m.merge("channel" => c["id"]) } }
  end

  def test_every_metric_reads_only_published_properties
    # The metric's numbers are the span's numbers because both are the same
    # published property. If a label could read something the consumer cannot,
    # the two could describe different requests.
    doc["channels"].each do |c|
      props = Array(c.dig("consumer", "properties")).map { |p| p["name"] }
      Array(c["metrics"]).each do |m|
        Array(m["labels"]).each do |l|
          assert_includes props, l["from"], "#{m['name']}: label `#{l['key']}` reads an unpublished property"
        end
        next if m["value_from"].to_s.empty?
        assert_includes props, m["value_from"], "#{m['name']}: value_from is not a published property"
      end
    end
  end

  def test_histogram_boundaries_come_from_a_declared_bounds_set
    ids = Array(doc["bounds_sets"]).map { |b| b["id"] }
    refute_empty ids
    metrics.select { |m| m["kind"] == "histogram" }.each do |m|
      assert_includes ids, m["bounds"], "#{m['name']}: bounds set is not declared"
      b = doc["bounds_sets"].find { |x| x["id"] == m["bounds"] }
      assert_equal b["unit"], m["unit"], "#{m['name']}: metric unit differs from its bounds' unit"
      assert_equal b["values"], m["boundaries"]
    end
  end

  # http.server.request.duration was aligned to OBI's default buckets so the two
  # agents' histograms are comparable. The declaration here is the same array;
  # this pins that it did not quietly become a different ruler.
  def test_the_declared_duration_buckets_are_obis
    b = Array(doc["bounds_sets"]).find { |x| x["id"] == "otel_duration_s" }
    refute_nil b
    assert_equal [0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10],
                 b["values"]
    assert_equal "s", b["unit"]
  end

  # The HTTP server-span runtime must read that same declaration rather than its
  # own copy -- otherwise "one author" is a claim about intent, not about the code.
  def test_the_http_server_histogram_reads_the_declared_bounds
    src = File.read(File.join(ROOT, "src/runtime/otlp/otlp_httpspan.c"))
    assert_match(/SPNL_BOUNDS_OTEL_DURATION_S_INIT/, src,
                 "otlp_httpspan.c still carries its own copy of the boundaries")
    refute_match(/0\.075, 0\.1, 0\.25/, src, "a second literal copy of the buckets reappeared")
  end

  def test_declared_total_is_within_the_runtime_capacity
    gen = File.read(File.join(ROOT, "src/runtime/otlp/record_mirror_gen.h"))
    total = gen[/#define SPNL_RECMETRIC_TOTAL_SERIES_BOUND\s+(\d+)/, 1].to_i
    cap   = gen[/#define SPNL_RECMETRIC_MAX_SERIES\s+(\d+)/, 1].to_i
    assert_operator total, :>, 0
    assert_operator total, :<=, cap
    assert_equal metrics.sum { |m| m["series_bound"] }, total,
                 "the total in the generated header differs from the sum of series_bound in the JSON"
  end
end
