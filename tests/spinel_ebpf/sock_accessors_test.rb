# frozen_string_literal: true
#
# sock_*(sk) -- reading a `struct sock *` by name.
#
# Drives the PRODUCTION C codegen (src/codegen_c/spinel_ebpf_cc.c) directly, the
# same binary tools/golden.rb pins. The golden already locks the exact text; what
# this file locks is the handful of decisions that would be SILENTLY wrong rather
# than merely different if someone changed them -- each one measured:
#
#   D1  the per-field byte order. Getting it wrong produces a number that still
#       looks like a port, so no test that only checks "it compiles" would catch
#       it. Measured on one connection to :8123: the raw reads are
#       dport=47903/sport=60404 and the uniformly-swapped reads are 8123/62699,
#       and the same contrast comes back through the real codegen.
#   D2  BPF_CORE_READ, never direct deref. The direct-deref form that tcp_sock_*
#       uses for the trusted struct_ops sk does not load here at all --
#       "R1 invalid mem access 'scalar'" (measured).
#   D3  flat calls, not a `sk.dport` dot form: `sk.<field>` already means the
#       tcp_sock direct deref, and that gate never looks at the receiver.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/sock_accessors_test.rb

require "minitest/autorun"
require "open3"
require "spinel_ebpf/capabilities"
require "spinel_ebpf/codegen_bpf"

class SockAccessorsTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  CAP  = SpinelEbpf::Capabilities
  GEN  = SpinelEbpf::CodegenBpf

  ALL = %w[sock_sport sock_dport sock_saddr sock_daddr sock_family sock_state
           sock_protocol sock_saddr6_hi sock_saddr6_lo sock_daddr6_hi sock_daddr6_lo].freeze

  # Same preflight as golden.rb: +x is not enough, build/ is bind-mounted into
  # the container so the binary may be built for the other platform.
  def self.runnable?
    return @runnable if defined?(@runnable)
    return @runnable = false unless File.executable?(CC)
    out, err, = Open3.capture3(CC)
    @runnable = "#{out}#{err}".include?("usage:")
  rescue StandardError
    @runnable = false
  end

  def skip_unless_cc
    skip "C codegen binary not runnable on this host" unless self.class.runnable?
  end

  def run_cc(base)
    Open3.capture3(CC, "#{FIX}/#{base}.ir", "#{FIX}/#{base}.ast", base)
  end

  def emit(base)
    skip_unless_cc
    out, err, st = run_cc(base)
    assert st.success?, "codegen refused #{base}: #{err}"
    out
  end

  # ---------- D1: the byte order is per field, and it is not uniform ----------

  # The load-bearing assertion of the whole experiment. skc_dport is __be16 and
  # skc_num is __u16 IN THE SAME STRUCT, so exactly one of the two ports gets a
  # swap. If someone "tidies up" by making the family consistent -- either way --
  # this fails, which is the only automated defence against a bug whose symptom
  # is a plausible-looking port number.
  def test_dport_is_swapped_and_sport_is_not
    c = emit("137_sock_accessors")

    assert_includes c, "bpf_ntohs(BPF_CORE_READ((struct sock *)(unsigned long)(sk), __sk_common.skc_dport))",
                    "sock_dport must ntohs: skc_dport is __be16 (measured: raw read = 47903 for port 8123)"
    assert_includes c, "((__s64)BPF_CORE_READ((struct sock *)(unsigned long)(sk), __sk_common.skc_num))",
                    "sock_sport must NOT convert: skc_num is already host order (measured: raw read == getsockname)"
    refute_includes c, "bpf_ntohs(BPF_CORE_READ((struct sock *)(unsigned long)(sk), __sk_common.skc_num))",
                    "swapping skc_num turns the source port into a different plausible port (60404 -> 62699)"
  end

  # Addresses are 32-bit, so they take ntohl rather than ntohs. Reusing the
  # 16-bit swap on a 32-bit field would keep compiling.
  def test_addresses_use_the_32_bit_swap
    c = emit("137_sock_accessors")
    assert_includes c, "bpf_ntohl(BPF_CORE_READ((struct sock *)(unsigned long)(sk), __sk_common.skc_daddr))"
    refute_includes c, "bpf_ntohs(BPF_CORE_READ((struct sock *)(unsigned long)(sk), __sk_common.skc_daddr))"
  end

  # IPv6 follows the same hi/lo packing the pkt_ip6_* accessors use (measured:
  # ::1 -> hi=0 lo=1, both from the raw reads and through the real codegen). hi
  # is words 0,1 and lo is 2,3; swapping the pairs silently reverses the address.
  def test_ipv6_halves_use_the_hi_lo_word_order
    c = emit("137_sock_accessors")
    assert_includes c, "skc_v6_daddr.in6_u.u6_addr32[0]"
    assert_includes c, "skc_v6_daddr.in6_u.u6_addr32[1]"
    assert_match(/u6_addr32\[0\]\)\)\) << 32\)/, c, "hi must be word 0 in the high half")
  end

  # The whole vocabulary is host order, which is what lets a port RANGE be plain
  # Ruby. Over raw __be16 values 8100..8199 is not even a contiguous range.
  def test_every_accessor_is_declared_host_order
    ALL.each do |b|
      sem = CAP.value_semantics_for(b)
      refute_nil sem, "#{b} must declare the unit/byte order of what it returns"
      next if b.start_with?("sock_family", "sock_state", "sock_protocol")
      assert_includes sem, "host order", "#{b}: the byte order has to be stated, not implied"
    end
  end

  # ---------- D2: untrusted pointer ----------

  # tcp_sock_* direct-derefs because struct_ops hands it a trusted sk.
  # Copying that here does not merely violate a convention, it fails to load.
  def test_never_direct_derefs_the_untrusted_pointer
    c = emit("137_sock_accessors")
    refute_includes c, "((struct sock *)(unsigned long)(sk))->__sk_common",
                    "direct deref of a kprobe arg does not load: R1 invalid mem access 'scalar' (measured)"
    assert_includes c, "BPF_CORE_READ((struct sock *)(unsigned long)(sk)"
  end

  # BPF_CORE_READ needs bpf_core_read.h and the swaps need bpf_endian.h; missing
  # either is a build break rather than a wrong value, but pin it anyway since
  # the include is conditional on a scan that is easy to forget to extend.
  def test_pulls_in_the_headers_the_reads_need
    c = emit("137_sock_accessors")
    assert_includes c, "#include <bpf/bpf_core_read.h>"
    assert_includes c, "#include <bpf/bpf_endian.h>"
  end

  # ---------- D3: flat surface, no collision with the tcp_sock dot form ------

  # `sk.<field>` is taken: it lowers to a DIRECT DEREF of tcp_sock, gated
  # only on the method name starting with "tcp_cc__" plus a fixed field table --
  # it never inspects the receiver. A sock_* dot form would therefore put two
  # different read mechanisms behind one spelling on one receiver.
  def test_surface_is_flat_and_takes_the_pointer_explicitly
    ALL.each do |b|
      sig = CAP.signature_for(b)
      assert_equal 1, sig[:arity], "#{b} takes the struct sock * explicitly (D3)"
      assert_equal %w[sk], sig[:params]
      assert_equal "#{b}(sk)", CAP.builtin_entry(b)[:example]
    end
  end

  # And the field names must not collide with the tcp_sock dot vocabulary, so
  # neither reading can ever be mistaken for the other.
  def test_no_name_overlap_with_the_tcp_cc_dot_vocabulary
    tcp_cc_fields = GEN::TCP_SOCK_READERS.keys.map { |k| k.sub(/\Atcp_sock_/, "") }
    bare = ALL.map { |b| b.sub(/\Asock_/, "") }
    assert_empty(bare & tcp_cc_fields,
                 "a name in both vocabularies would mean two mechanisms behind one spelling")
  end

  # Dropping the pointer must be loud: there is no implicit receiver to fall
  # back on, so silently resolving against some `sk` in scope is not an option.
  def test_missing_pointer_is_refused_at_codegen_time
    skip_unless_cc
    _out, err, st = run_cc("138_sock_accessor_arity")
    refute st.success?, "sock_dport with no argument must be refused"
    assert_match(/exactly one argument/, err)
    assert_match(/struct sock/, err, "the message has to say what the argument is")
  end

  # ---------- registration ----------

  def test_registered_as_net_builtins_in_their_own_group
    ALL.each do |b|
      assert_includes GEN::BUILTIN_NAMES, b
      assert_equal :net, CAP.domain_of(b), "same family as sock_addr_*/emit_connect, not the generic kfield reads"
      assert_nil CAP.gate_for(b), "no hook gate: this is the same CO-RE read kfield does ungated"
    end
    assert_includes CAP.related_for("sock_dport"), "sock_sport"
    grp = CAP::BUILTIN_GROUPS.find { |g| g[:name] == "sock_accessor" }
    refute_nil grp
    assert_includes grp[:note], "host order"
  end

  # The two enumerated accessors return values that mean nothing as bare
  # integers; the constants that name them must resolve in the C codegen (not
  # only in the Ruby oracle, where they already existed).
  def test_enumerated_values_have_names_the_codegen_resolves
    c = emit("137_sock_accessors")
    src = File.read("#{FIX}/137_sock_accessors.rb")
    assert_includes src, "TCP_STATE_ESTABLISHED"
    assert_includes src, "AF_INET6"
    assert_includes c, ") == 1",  "TCP_STATE_ESTABLISHED must lower to 1"
    assert_includes c, ") == 10", "AF_INET6 must lower to 10"
  end

  # The address accessors are only meaningful for the matching family, and the
  # codegen cannot check that (it is a runtime property of the socket), so the
  # caveat has to be carried in the affordance the author/AI actually reads.
  def test_address_accessors_carry_the_family_caveat
    %w[sock_saddr sock_daddr].each do |b|
      assert_includes CAP.value_semantics_for(b), "AF_INET",
                      "#{b} on an AF_INET6 socket returns a plausible number, not an error (measured)"
    end
    %w[sock_saddr6_hi sock_daddr6_lo].each do |b|
      assert_includes CAP.value_semantics_for(b), "AF_INET6"
    end
  end
end
