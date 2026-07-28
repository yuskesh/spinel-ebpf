# spinel-ebpf cross-layer (L2 to L8) dashboard for Splunk Observability Cloud
# (formerly SignalFx)
# ============================================================================
# For the case where OTLP is exported directly to Splunk Observability Cloud
# (SignalFx). The receiving end is ingest.<realm>.signalfx.com, authenticated with
# the x-sf-token header.
#
# Every metric and dimension referenced here is a key spinel-ebpf actually emits:
#   - metric:    http.server.request.duration  (Float64 explicit-bucket Histogram, unit=s)
#   - dimension: http.route / http.request.method / http.response.status_code (L7)
#   - dimension: tenant (L8)
#   - dimension: net.tcp.established / net.tcp.state_changes (L4, keyed by 4-tuple)
#   - dimension: client.address / server.address / server.port (L3/L4)
#
# ---------------------------------------------------------------------------
# How reliable this is -- stated plainly, with nothing invented
# * The Terraform provider assumed here is splunk-terraform/signalfx. Resource
#   names, arguments and the function signatures inside SignalFlow (program_text)
#   can change between provider and SignalFlow versions. In particular, expect to
#   adjust the following for your provider version:
#     - the function that takes a percentile from a histogram metric
#       (histogram(...).percentile(...), .count() and so on). How an OTLP
#       explicit-bucket histogram is converted into SignalFx MTS -- as a native
#       histogram, or as derived .count/.sum/.bucket series -- depends on the
#       ingest path.
#     - the block name for a dashboard variable (filter): variable {} or filter {}.
# * This file has not been through terraform validate, which would need a real
#   provider, org and token. The syntax has only been formatted by eye, so check
#   it with `terraform plan` before applying.
# ---------------------------------------------------------------------------

terraform {
  required_providers {
    signalfx = {
      source = "splunk-terraform/signalfx"
      # version = "~> 9.0"  # set this to the version you actually use
    }
  }
}

# Authentication: pass SFX_AUTH_TOKEN (an org token) and SFX_API_URL
# (= https://api.<realm>.signalfx.com) through the environment or through
# variables. This file assumes the environment.
provider "signalfx" {
  # auth_token = var.sfx_auth_token
  # api_url    = "https://api.us1.signalfx.com"   # set <realm> to yours
}

# ---------------------------------------------------------------------------
# Dashboard group
# ---------------------------------------------------------------------------
resource "signalfx_dashboard_group" "spinel_ebpf" {
  name        = "spinel-ebpf L2–L8 xlayer"
  description = "Cross-layer L3/L4 + L7 + L8 correlation emitted by a single spinel-ebpf binary"
}

# ---------------------------------------------------------------------------
# Chart 1: request latency p50 / p90 / p99, split by http.route
#   metric: http.server.request.duration (explicit-bucket Histogram)
# ---------------------------------------------------------------------------
resource "signalfx_time_chart" "req_duration_pct" {
  name        = "HTTP request duration p50/p90/p99 by route"
  description = "Quantiles of http.server.request.duration split by http.route (L7)"

  # NOTE: the exact SignalFlow spelling of histogram(...).percentile(...) depends
  #       on the ingest path and the version. The dashboard variable tokens $route
  #       and $tenant are fed into the filters.
  program_text = <<-EOF
    P50 = histogram('http.server.request.duration', filter=filter('http.route', '$route*') and filter('tenant', '$tenant*')).percentile(50, by=['http.route']).publish(label='p50')
    P90 = histogram('http.server.request.duration', filter=filter('http.route', '$route*') and filter('tenant', '$tenant*')).percentile(90, by=['http.route']).publish(label='p90')
    P99 = histogram('http.server.request.duration', filter=filter('http.route', '$route*') and filter('tenant', '$tenant*')).percentile(99, by=['http.route']).publish(label='p99')
  EOF

  plot_type         = "LineChart"
  unit_prefix       = "Metric"
  axis_left {
    label     = "seconds"
    min_value = 0
  }
}

# ---------------------------------------------------------------------------
# Chart 2: request count split by route and status
#   Uses the count series of the same histogram (the request rate)
# ---------------------------------------------------------------------------
resource "signalfx_time_chart" "req_count" {
  name        = "HTTP request count by route & status"
  description = "Count of http.server.request.duration split by http.route and http.response.status_code (L7)"

  # NOTE: how the count is taken from a histogram (.count() and so on) is
  #       version-dependent.
  program_text = <<-EOF
    C = histogram('http.server.request.duration', filter=filter('tenant', '$tenant*')).count(by=['http.route', 'http.response.status_code']).publish(label='requests')
  EOF

  plot_type   = "ColumnChart"
  unit_prefix = "Metric"
}

# ---------------------------------------------------------------------------
# Chart 3, the point of the whole demo: the cross-layer panel
#   Splits the L4 metrics net.tcp.state_changes and net.tcp.established by tenant
#   and http.route, so an L4 metric and L7/L8 dimensions sit side by side in one
#   dataset. These are spinel-ebpf's own dimensions, outside semconv.
# ---------------------------------------------------------------------------
resource "signalfx_time_chart" "xlayer_tcp" {
  name        = "xlayer: TCP state_changes / established by tenant & route"
  description = "L4 (net.tcp.*) split along the L8 (tenant) and L7 (http.route) axes -- layers placed together with no join"

  # net.tcp.* can be operated either as a span attribute or as a metric. This is
  # written assuming it was ingested as a gauge/counter metric. If you do not turn
  # it into a metric, pick it up on the traces side instead -- Dashboard Studio
  # and SPL below, or APM in Observability Cloud.
  program_text = <<-EOF
    SC = data('net.tcp.state_changes', filter=filter('tenant', '$tenant*') and filter('http.route', '$route*')).sum(by=['tenant', 'http.route']).publish(label='state_changes')
    ES = data('net.tcp.established',   filter=filter('tenant', '$tenant*') and filter('http.route', '$route*')).sum(by=['tenant', 'http.route']).publish(label='established')
  EOF

  plot_type   = "ColumnChart"
  unit_prefix = "Metric"
}

# ---------------------------------------------------------------------------
# Chart 5: classification of a traffic burst -- the access_class rate split by
# proto and tcp_state.
#   metric:    access_class (a Sum, the basis of the rate). XDP sorts received
#              packets into a small fixed set of classes.
#   dimension: proto (icmp/udp/tcp/other) / tcp_state (syn/established)
#   This breaks down the burst arriving right now, at a glance, into a SYN surge
#   (proto=tcp, tcp_state=syn), established sessions, and ICMP/UDP.
#   Note: high-cardinality dimensions such as the source address (src_ip) are
#   deliberately absent, to avoid exploding the MTS count. See the README.
# ---------------------------------------------------------------------------
resource "signalfx_time_chart" "access_class" {
  name        = "Access-surge classification (rate by proto / tcp_state)"
  description = "access_class split by proto and tcp_state -- the per-class rate of inbound traffic (L3/L4)"

  program_text = <<-EOF
    A = data('access_class', filter=filter('proto', '*')).sum(by=['proto', 'tcp_state']).publish(label='by_class')
  EOF

  plot_type   = "ColumnChart"
  unit_prefix = "Metric"
}

# ---------------------------------------------------------------------------
# Chart 5b: enforcement made visible -- the pass rate against the drop rate.
#   metric:    access_class (a Sum). XDP classifies, dropping only ICMP with
#              XDP_DROP and passing everything else with XDP_PASS.
#   dimension: action (pass/drop) / proto (icmp/udp/tcp/other)
#   Splitting `access_class` **by action** shows how much is being dropped and how
#   much passed, in one chart. The drop side (that is, ICMP) crossing a threshold
#   is a sign of an attack or a misconfiguration.
#   Note: the policy is static -- ICMP only. A dynamic toggle is a candidate
#   extension.
# ---------------------------------------------------------------------------
resource "signalfx_time_chart" "access_action" {
  name        = "Access enforce (pass vs drop rate by proto)"
  description = "access_class split by action (pass/drop) and proto -- how much is blocked versus how much passes (L3/L4)"

  program_text = <<-EOF
    A = data('access_class', filter=filter('action', 'drop')).sum(by=['proto']).publish(label='dropped')
    B = data('access_class', filter=filter('action', 'pass')).sum(by=['proto']).publish(label='passed')
  EOF

  plot_type   = "ColumnChart"
  unit_prefix = "Metric"
}

# ---------------------------------------------------------------------------
# Chart 4: list the routes that are currently slow
# ---------------------------------------------------------------------------
resource "signalfx_list_chart" "slow_routes" {
  name        = "Top routes by p99 latency"
  description = "The http.route values with the highest p99 (L7)"

  program_text = <<-EOF
    P99 = histogram('http.server.request.duration').percentile(99, by=['http.route']).publish(label='p99')
  EOF

  sort_by                 = "-value"
  max_delay               = 0
  refresh_interval        = 30
}

# ---------------------------------------------------------------------------
# The dashboard itself, plus the variables (filters) tenant and http.route
# ---------------------------------------------------------------------------
resource "signalfx_dashboard" "xlayer" {
  name            = "L2–L8 xlayer correlation"
  dashboard_group = signalfx_dashboard_group.spinel_ebpf.id
  description     = "L3/L4, L7 and L8 sit together in one record, so any axis can be used to split or filter"

  # ---- dashboard variable (filter) --------------------------------------
  # NOTE: the name of the variable {} block and its arguments can differ between
  #       provider versions.
  variable {
    property          = "tenant"
    alias             = "tenant"
    description       = "L8: the application tenant, from X-Tenant or derived from the route"
    values            = []          # empty = every tenant; pick one in the UI
    value_required    = false
  }
  variable {
    property          = "http.route"
    alias             = "route"
    description       = "L7: the HTTP route"
    values            = []
    value_required    = false
  }

  # ---- layout ------------------------------------------------------------
  chart {
    chart_id = signalfx_time_chart.req_duration_pct.id
    width    = 6
    height   = 2
    row      = 0
    column   = 0
  }
  chart {
    chart_id = signalfx_time_chart.req_count.id
    width    = 6
    height   = 2
    row      = 0
    column   = 6
  }
  chart {
    chart_id = signalfx_time_chart.xlayer_tcp.id
    width    = 8
    height   = 2
    row      = 2
    column   = 0
  }
  chart {
    chart_id = signalfx_list_chart.slow_routes.id
    width    = 4
    height   = 2
    row      = 2
    column   = 8
  }
  chart {
    chart_id = signalfx_time_chart.access_class.id
    width    = 12
    height   = 2
    row      = 4
    column   = 0
  }
  chart {
    chart_id = signalfx_time_chart.access_action.id
    width    = 12
    height   = 2
    row      = 6
    column   = 0
  }
}
