# frozen_string_literal: true
#
# The msghdr seam.
#
# Eleven builtins read the bytes of a send or a receive, and every one of them
# used to resolve `msghdr.msg_iter` on its own -- identically, and identically
# wrong (one arm of a tagged union). The fix is not "eleven corrections": it is
# that the resolution now happens in ONE function, and the value of that is only
# preserved as long as a twelfth site cannot quietly grow its own copy.
#
# So what is pinned here is a STRUCTURAL invariant, not an inventory: "the
# production codegen mentions msg_iter in exactly one place" stays meaningful
# whether there are eleven payload builtins, zero, or twenty. Nothing in this
# file counts the eleven.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/msg_buffer_test.rb
require "minitest/autorun"
require "spinel_ebpf/capabilities"

class MsgBufferTest < Minitest::Test
  ROOT      = File.expand_path("../..", __dir__)
  TPL_DIR   = File.join(ROOT, "src/codegen_c/templates")
  CC        = File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c")
  RESOLVER  = "msg_ubuf.template.c"
  CAP       = SpinelEbpf::Capabilities

  # Source files the production codegen is built from, minus the generated
  # header (templates_gen.h is a copy of the templates and would double-count).
  def production_sources
    Dir[File.join(TPL_DIR, "*.template.c")] + [CC]
  end

  # Strip C comments before looking for a read: the resolver's own comment quotes
  # the old expression verbatim, and a prose mention is not a second reader.
  def code_of(path)
    File.read(path).gsub(%r{/\*.*?\*/}m, "").gsub(%r{//[^\n]*}, "")
  end

  def files_reading_msg_iter
    production_sources.select { |f| code_of(f).include?("msg_iter") }
                      .map { |f| File.basename(f) }.sort
  end

  # ---- the invariant -------------------------------------------------------

  def test_exactly_one_place_resolves_the_msg_iter_union
    assert_equal [RESOLVER], files_reading_msg_iter,
                 "msg_iter is a tagged union; a second reader is a second discipline, " \
                 "and two of them disagreeing costs a silent zero-filled record. " \
                 "Read the buffer through spnl_msg_ubuf() instead."
  end

  # The scanner above is only worth something if it can still see a second
  # reader. Synthesised, so it neither depends on nor anchors any real file.
  def test_the_scanner_would_notice_a_second_reader
    tmp = File.join(TPL_DIR, "zz_selfcheck.template.c")
    File.write(tmp, "void f(struct msghdr *m) { x = BPF_CORE_READ(m, msg_iter.__ubuf_iovec.iov_base); }\n")
    found = files_reading_msg_iter
    assert_includes found, "zz_selfcheck.template.c",
                    "the scanner cannot see a second reader, so a green result above means nothing"
    refute_equal [RESOLVER], found
  ensure
    File.delete(tmp) if tmp && File.exist?(tmp)
  end

  def test_a_prose_mention_is_not_counted_as_a_reader
    # The resolver quotes the old expression inside a comment. If comment
    # stripping broke, every explanation would become a violation and the fix
    # would be to delete the explanation -- so this is checked directly.
    tmp = File.join(TPL_DIR, "zz_prose.template.c")
    File.write(tmp, "/* msg_iter.__ubuf_iovec.iov_base is what this used to read */\nvoid g(void) {}\n")
    refute_includes files_reading_msg_iter, "zz_prose.template.c"
  ensure
    File.delete(tmp) if tmp && File.exist?(tmp)
  end

  # ---- the resolver's own contract ----------------------------------------

  def test_resolver_branches_on_the_tag_and_reads_the_tags_own_member
    src = File.read(File.join(TPL_DIR, RESOLVER))
    # The tag is read, and both arms are named -- from the kernel's BTF, not from
    # numbers written here: an unchecked hand-written table is how enum drift
    # becomes a silent reclassification.
    assert_includes src, "msg_iter.iter_type"
    assert_includes src, "bpf_core_enum_value(enum iter_type, ITER_UBUF)"
    assert_includes src, "bpf_core_enum_value(enum iter_type, ITER_IOVEC)"
    refute_match(/it\s*==\s*[01]\b/, src, "the tag must not be compared against a baked-in number")
    # ITER_IOVEC reads through `__iov`, the member that arm actually names --
    # not through __ubuf_iovec, which happens to alias it.
    assert_includes src, "msg_iter.__iov"
    # Anything that is not a user buffer resolves to NULL rather than to a
    # plausible pointer; that is what turns the case into a reported drop.
    assert_includes src, "iov_offset"
  end

  def test_no_user_buffer_has_a_status_of_its_own
    src = File.read(File.join(TPL_DIR, RESOLVER))
    assert_match(/#define\s+SPNL_RAW_NO_USER_BUFFER\s+\(-1\)/, src)
    emit = File.read(File.join(TPL_DIR, "bi_emit_dns.template.c"))
    assert_includes emit, "SPNL_RAW_NO_USER_BUFFER"
    # The read's return value reaches the record. Discarding it is the specific
    # thing that was fixed: it is what made an unreadable payload look like an
    # unparseable one.
    assert_match(/raw_status\s*=/, emit)
    refute_match(/\(void\)bpf_probe_read_user\(_de/, emit)
  end

  def test_zero_means_ok_so_an_older_producer_stays_readable
    schema = File.read(File.join(ROOT, "src/codegen_c/record_schema.h"))
    dns = schema[/static const CcRecSchema cc_rec_dns = \{.*?\n\};/m]
    refute_nil dns
    # raw_status is appended AFTER the last required field, so an older producer
    # is still accepted; its missing field reads as zero, and zero is "the bytes
    # are the sender's" -- which is what those records meant.
    assert_match(/\.required_through\s*=\s*"duration_ns"/, dns)
    fields = schema[/static const CcRecField cc_rec_dns_fields\[\] = \{.*?\n\};/m]
    assert_equal "raw_status", fields.scan(/\{\s*"([a-z_]+)"/).flatten.last
  end

  # ---- the destination vocabulary -----------------------------------------

  def test_udp_destination_builtins_take_both_the_socket_and_the_message
    %w[udp_dport udp_daddr].each do |b|
      sig = CAP.signature_for(b)
      assert_equal 2, sig[:arity], "#{b} needs the socket AND the message: an unconnected " \
                                   "sender carries the destination in the message"
      assert_equal %w[sk msg], sig[:params]
      refute_nil CAP.value_semantics_for(b),
                 "#{b} returns a number that looks exactly like sock_dport's; the difference " \
                 "only shows up as silence, so it has to be written down"
    end
  end

  def test_sock_accessors_say_what_they_do_not_answer
    # The trap is not that sock_dport is wrong -- it answers a different
    # question, correctly. The affordance has to name the other question, or an
    # author reaching for the obvious spelling gets a probe that reports nothing.
    %w[sock_dport sock_daddr].each do |b|
      summary = CAP.signature_for(b)[:summary]
      assert_match(/udp_d(port|addr)/, summary,
                   "#{b}'s entry must point at the datagram-destination form")
    end
  end

  def test_the_two_questions_are_grouped_together
    g = CAP::BUILTIN_GROUPS.find { |x| x[:name] == "datagram_destination" }
    refute_nil g, "the pair only makes sense read side by side"
    assert_equal %w[udp_dport udp_daddr sock_dport sock_daddr].sort, g[:members].sort
  end
end
