# frozen_string_literal: true

require "minitest/autorun"
require "spinel_ebpf/btf_schema"

# Unit-test the BTF struct parser by injecting dumped header text directly (so it
# runs on the host without bpftool / a BTF kernel). The live `bpftool btf dump`
# path is exercised in the container.
class BtfSchemaTest < Minitest::Test
  SAMPLE = <<~C
    struct trace_event_raw_other {
        struct trace_entry ent;
        int unrelated;
    };

    struct trace_event_raw_demo {
        struct trace_entry ent;
        const void *skaddr;
        int oldstate;
        int newstate;
        __u16 sport;
        __u16 dport;
        unsigned int bytes_alloc;
        __u8 saddr[4];
        __u8 daddr[4];
        __u8 saddr_v6[16];
        char __data[0];
    };
  C

  # Build a BtfSchema with `text` already loaded (bypass bpftool).
  def schema_with(text)
    b = SpinelEbpf::BtfSchema.new(btf_path: "off")   # don't touch the real BTF
    b.instance_variable_set(:@loaded, true)
    b.instance_variable_set(:@load_ok, true)
    b.instance_variable_set(:@text, text)
    b
  end

  def test_unavailable_when_disabled
    b = SpinelEbpf::BtfSchema.new(btf_path: "off")
    refute b.available?
    assert_nil b.field_type("trace_event_raw_demo", "sport")
    assert_nil b.tracepoint_struct("demo")
  end

  def test_scalar_and_pointer_fields_are_int
    b = schema_with(SAMPLE)
    assert b.available?
    assert_equal "int", b.field_type("trace_event_raw_demo", "skaddr")      # pointer
    assert_equal "int", b.field_type("trace_event_raw_demo", "oldstate")    # int
    assert_equal "int", b.field_type("trace_event_raw_demo", "sport")       # __u16
    assert_equal "int", b.field_type("trace_event_raw_demo", "bytes_alloc") # unsigned int
  end

  def test_u8_array_of_4_is_ipv4
    b = schema_with(SAMPLE)
    assert_equal "ipv4", b.field_type("trace_event_raw_demo", "saddr")
    assert_equal "ipv4", b.field_type("trace_event_raw_demo", "daddr")
  end

  def test_non_ipv4_array_and_struct_and_absent_are_nil
    b = schema_with(SAMPLE)
    assert_nil b.field_type("trace_event_raw_demo", "saddr_v6")  # __u8[16], not a scalar
    assert_nil b.field_type("trace_event_raw_demo", "ent")       # embedded struct
    assert_nil b.field_type("trace_event_raw_demo", "__data")    # char[0] trailer
    assert_nil b.field_type("trace_event_raw_demo", "nope")      # absent field
  end

  def test_tracepoint_struct_resolution
    b = schema_with(SAMPLE)
    # complete struct present -> returns the canonical name
    assert_equal "trace_event_raw_demo", b.tracepoint_struct("demo")
    # no such struct -> nil (caller falls back to override/default)
    assert_nil b.tracepoint_struct("does_not_exist")
  end

  def test_struct_fields_nil_for_missing_struct
    b = schema_with(SAMPLE)
    assert_nil b.struct_fields("trace_event_raw_missing")
  end

  # ---------- Phase 2: func_params (BTF FUNC / FUNC_PROTO) ----------

  RAW = <<~RAW
    [100] FUNC 'tcp_sendmsg' type_id=200 linkage=static
    [200] FUNC_PROTO '(anon)' ret_type_id=15 vlen=3
    \t'sk' type_id=300
    \t'msg' type_id=301
    \t'size' type_id=14
    [400] FUNC 'cap_capable' type_id=500 linkage=static
    [500] FUNC_PROTO '(anon)' ret_type_id=14 vlen=4
    \t'cred' type_id=600
    \t'targ_ns' type_id=601
    \t'cap' type_id=14
    \t'opts' type_id=20
    [700] FUNC 'noargs' type_id=800 linkage=static
    [800] FUNC_PROTO '(anon)' ret_type_id=0 vlen=0
  RAW

  # BtfSchema with both the (struct) text and the raw FUNC dump injected.
  def schema_with_raw(text, raw)
    b = schema_with(text)
    b.instance_variable_set(:@raw, raw)
    b.instance_variable_set(:@raw_loaded, true)
    b
  end

  def test_func_params_ordered
    b = schema_with_raw(SAMPLE, RAW)
    assert_equal %w[sk msg size], b.func_params("tcp_sendmsg")
    assert_equal %w[cred targ_ns cap opts], b.func_params("cap_capable")
  end

  def test_func_params_zero_args_and_missing
    b = schema_with_raw(SAMPLE, RAW)
    assert_equal [], b.func_params("noargs")          # vlen=0 -> empty list
    assert_nil b.func_params("does_not_exist")        # not in BTF -> nil
  end

  def test_func_params_nil_when_unavailable
    b = SpinelEbpf::BtfSchema.new(btf_path: "off")
    assert_nil b.func_params("tcp_sendmsg")
  end

  # ---------- Phase 3: enum_value (BTF ENUM / ENUM64) ----------

  RAW_ENUM = <<~RAW
    [123] ENUM 'xdp_action' encoding=UNSIGNED size=4 vlen=3
    \t'XDP_ABORTED' val=0
    \t'XDP_DROP' val=1
    \t'XDP_PASS' val=2
    [200] ENUM '(anon)' encoding=SIGNED size=4 vlen=2
    \t'TCP_ESTABLISHED' val=1
    \t'TCP_CLOSE' val=7
    [300] ENUM64 'big_flags' encoding=UNSIGNED size=8 vlen=1
    \t'BIGVAL' val=0x100000000
    [400] FUNC_PROTO '(anon)' ret_type_id=0 vlen=1
    \t'notanenum' type_id=14
  RAW

  def test_enum_value_named_and_anon
    b = schema_with_raw(SAMPLE, RAW_ENUM)
    assert_equal 2, b.enum_value("XDP_PASS")        # named enum xdp_action
    assert_equal 1, b.enum_value("TCP_ESTABLISHED") # anonymous enum
    assert_equal 7, b.enum_value("TCP_CLOSE")
  end

  def test_enum_value_enum64_and_missing
    b = schema_with_raw(SAMPLE, RAW_ENUM)
    assert_equal 0x100000000, b.enum_value("BIGVAL")  # ENUM64 hex value
    assert_nil b.enum_value("NOT_AN_ENUM")
    assert_nil b.enum_value("notanenum")              # FUNC_PROTO param, not an enumerator
  end

  def test_enum_value_nil_when_unavailable
    b = SpinelEbpf::BtfSchema.new(btf_path: "off")
    assert_nil b.enum_value("XDP_PASS")
  end
end
