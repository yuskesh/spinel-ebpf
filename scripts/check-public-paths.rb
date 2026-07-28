#!/usr/bin/env ruby
# frozen_string_literal: true
#
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Check that every path into this repository that this tree mentions resolves.
#
# This repository is published from a larger private one whose dependencies live
# somewhere else: there they are git submodules under third_party/, here they are
# fetched on demand into deps/ or vendored into the source tree. Porting a file
# across carries its paths with it, and a path that no longer resolves fails at
# the worst possible moment -- when someone runs the script, long after review,
# with an error naming a directory this repository has never had.
#
# Two rules, both narrow on purpose. A check that cries wolf gets switched off.
#
#   1. third_party/ -- the private repository's submodule root -- must not be
#      mentioned at all, because nothing here is ever under it.
#
#   2. A path whose first component is one of this repository's own top-level
#      directories is unambiguously a reference into this tree, so it must exist.
#      That is what catches a stale src/, tests/ or tools/ path -- including the
#      ones a search-and-replace leaves half-rewritten.
#
# Everything else -- prose with a slash in it, C include roots, protobuf import
# paths, action refs -- is left alone, because there is no way to tell those from
# repository paths without guessing, and guessing is what makes a gate useless.
#
#   ruby scripts/check-public-paths.rb        # exit 1 on any violation

ROOT = File.expand_path("..", __dir__)
Dir.chdir(ROOT)

# The one layout this repository does not have. It is the private repository's
# submodule root, and it rides along on every file ported across. Kept to the
# single name that has actually leaked -- a speculative list would fire on
# vendor/ paths that belong to other projects and teach people to ignore this.
FOREIGN_LAYOUT = %w[third_party].freeze

# Not ours to police: fetched checkouts, build output, vendored third-party code.
# tests/fixtures holds generated parser output that records the paths in force
# when it was generated; those are data, not references to follow.
PRUNE = %w[./.git ./deps ./build ./tests/fixtures
           ./src/runtime/otlp/nanopb ./tools/rbpf-for-microcontrollers].freeze

# Path components that mean "produced by a build", so absence is the normal state.
BUILD_OUTPUT = %w[target build .venv-otlp].freeze

# Own top-level directories, minus the ones whose names collide with system
# paths often enough to be ambiguous in prose (/bin/sh, /include/...).
OWN = (Dir.glob("*").select { |f| File.directory?(f) } - %w[bin include build deps]).freeze

BINARY = /\.(png|jpe?g|gif|pdf|o|a|so|zip|tar|gz|ico)\z/

# A path token: no scheme, no leading slash, not glued to an identifier. The
# leading (?<![\w./:$@-]) keeps us out of URLs, $VAR/... expansions and the
# middle of longer paths.
def token_pattern(heads)
  /(?<![\w.\/:$@-])(?<path>(?:#{heads.join("|")})\/[\w.@+-]+(?:\/[\w.@+-]+)*)/
end

FOREIGN_RE = token_pattern(FOREIGN_LAYOUT)
OWN_RE = token_pattern(OWN)

files = Dir.glob("**/*", File::FNM_DOTMATCH)
           .reject { |f| File.directory?(f) }
           .reject { |f| PRUNE.any? { |p| "./#{f}".start_with?("#{p}/") } }
           .reject { |f| f.match?(BINARY) }
           .reject { |f| File.basename(f) == File.basename(__FILE__) }

foreign = Hash.new { |h, k| h[k] = [] }
dangling = Hash.new { |h, k| h[k] = [] }

files.each do |file|
  text = begin
    File.read(file, encoding: "UTF-8")
  rescue StandardError
    next
  end
  next unless text.valid_encoding?

  text.each_line.with_index(1) do |line, lineno|
    line.scan(FOREIGN_RE) { foreign[file] << [lineno, Regexp.last_match[:path], line.strip[0, 110]] }
    line.scan(OWN_RE) do
      path = Regexp.last_match[:path]
      # A trailing glob or placeholder is a description, not a path; a trailing
      # period is the end of a sentence; a brace form names several files at once.
      next if path.match?(/[*?]|<[^>]*>/)
      path = path.sub(/\.\z/, "")
      next if path.end_with?(".")
      next if BUILD_OUTPUT.any? { |b| path.split("/").include?(b) }
      next if File.exist?(path)
      # A path may be written relative to the file that mentions it.
      next if File.exist?(File.join(File.dirname(file), path))
      # Prose names a group of files without an extension, or with a brace form
      # this pattern truncates: `otlp_http.{c,h}` arrives here as `otlp_http`.
      next unless Dir.glob("#{path}.*").empty?

      dangling[file] << [lineno, path, line.strip[0, 110]]
    end
  end
end

def report(title, hits)
  puts "!!! #{title}:"
  hits.each do |file, list|
    puts "      #{file}"
    list.first(3).each { |lineno, path, line| puts "          #{lineno}: #{path}   -- #{line}" }
    puts "          ... and #{list.length - 3} more" if list.length > 3
  end
end

fail_ = false
unless foreign.empty?
  report("a dependency layout this repository does not use", foreign)
  puts "      Dependencies are fetched into deps/ by scripts/setup.sh, or vendored in-tree."
  fail_ = true
end
unless dangling.empty?
  report("a path into this repository that does not exist", dangling)
  fail_ = true
end

if fail_
  exit 1
else
  puts "path check: OK -- no foreign layout, and every path into this tree resolves"
end
