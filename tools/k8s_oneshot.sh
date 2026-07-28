#!/usr/bin/env bash
#
# k8s_oneshot.sh -- one command to inject an eBPF probe the Kubernetes way, measure,
# and pull it back out.
#
# The moment you want to know something, a throwaway probe binary is shipped with
# `kubectl cp` into a debug pod created by `kubectl debug node/<node>` (the
# privileged sysadmin profile), run for a bounded time inside the node's host
# namespaces via `nsenter -t 1`, its artifacts collected, and the debug pod torn
# down. Unless the probe pins them, BPF programs and links are detached
# automatically when the process exits, so the cluster is clean again afterwards.
#
# No resident agent, no DaemonSet. This is the injection/extraction path for
# one-shot measurement and nothing else.
#
# Two injection modes:
#   (1) cp+nsenter mode (default): --binary kubectl-cp's a probe ELF from your
#       machine and runs it in the host namespaces via nsenter -t 1. The build
#       environment must match the node's arch/glibc.
#   (2) image mode: --probe-image runs an OCI image with the probe baked in as the
#       debug pod's own image. No cp, a single pull, and per-arch differences are
#       absorbed by the image manifest. The image's ENTRYPOINT owns the execution
#       model (pure = in-pod / hybrid = nsenter). A distribution form that takes
#       advantage of the probe being a self-contained AOT-compiled binary.
#
# Usage:
#   tools/k8s_oneshot.sh --binary ./probe --seconds 30 [options] [-- <probe args>]   # cp+nsenter
#   tools/k8s_oneshot.sh --probe-image REF --mode hybrid --seconds 45 [options]      # image
#
# Main options:
#   --binary PATH        (cp+nsenter mode) executable to run on the node's host side
#   --probe-image REF    (image mode) container image with the probe baked in; becomes
#                        the debug pod's image.
#   --mode M             (image mode) SPNL_PROBE_MODE (recon|pure|hybrid, default hybrid).
#   --seconds N          run timeout in seconds (default 30)
#   --max-events K       inject SPNL_MAX_EVENTS=K into the probe. An emit/drain-based
#                        probe exits cleanly on its own once it has taken K events,
#                        leaving no trace. Can be combined with --seconds: whichever
#                        comes first (time or count) ends the run.
#   --env FILE           env file to source before starting the binary (tokens etc.).
#                        Its contents are never logged, and it is deleted from the node
#                        after the run.
#   --file PATH[:NAME]   extra file to inject alongside the binary (repeatable).
#                        Referred to from probe args as @DIR@/NAME.
#   --collect NAME[:DST] after the run, collect NAME from the run directory into DST (repeatable).
#   --node NODE          target node (default: the first Ready node)
#   --image IMG          debug pod image (default: busybox; needs the nsenter/tar/timeout applets)
#   --profile PROF       debug profile (default: sysadmin = privileged + host ns)
#   --pull-policy P      image pull policy (default: IfNotPresent -- no pull if already airgapped)
#   --log FILE           send the probe's stdout+stderr here (default: standard output)
#   --kubectl CMD        kubectl command (default: kubectl)
#   --keep               leave the debug pod behind (for debugging)
#   -- <probe args>      arguments passed to the binary. @DIR@ is replaced with the host
#                        directory the files were injected into.
#
# Because @DIR@ is substituted in probe args, extra files and wire output paths can be
# given as host paths:
#   --binary ./driver --file probe.bpf.o --file uidmap.txt --collect wire.pb:/out/wire.pb \
#     -- "$EP" @DIR@/probe.bpf.o /etc/hostname /sys/fs/cgroup @DIR@/uidmap.txt @DIR@/wire.pb
#
set -euo pipefail

die() { echo "k8s_oneshot: $*" >&2; exit 1; }
log() { echo "[oneshot] $*" >&2; }

# ---- defaults ----
BINARY=""; SECONDS_RUN=30; ENVFILE=""; NODE=""; LOGFILE=""; MAX_EVENTS=""
IMAGE="docker.io/rancher/mirrored-library-busybox:1.37.0"
PROBE_IMAGE=""; PROBE_MODE="hybrid"
PROFILE="sysadmin"; PULL_POLICY="IfNotPresent"; KUBECTL="kubectl"; KEEP=0
FILES=(); COLLECTS=(); PROBE_ARGS=()

# ---- parse ----
while [ $# -gt 0 ]; do
  case "$1" in
    --binary)      BINARY="$2"; shift 2 ;;
    --probe-image) PROBE_IMAGE="$2"; shift 2 ;;
    --mode)        PROBE_MODE="$2"; shift 2 ;;
    --seconds)     SECONDS_RUN="$2"; shift 2 ;;
    --max-events)  MAX_EVENTS="$2"; shift 2 ;;
    --env)         ENVFILE="$2"; shift 2 ;;
    --file)        FILES+=("$2"); shift 2 ;;
    --collect)     COLLECTS+=("$2"); shift 2 ;;
    --node)        NODE="$2"; shift 2 ;;
    --image)       IMAGE="$2"; shift 2 ;;
    --profile)     PROFILE="$2"; shift 2 ;;
    --pull-policy) PULL_POLICY="$2"; shift 2 ;;
    --log)         LOGFILE="$2"; shift 2 ;;
    --kubectl)     KUBECTL="$2"; shift 2 ;;
    --keep)        KEEP=1; shift ;;
    --)            shift; PROBE_ARGS=("$@"); break ;;
    *)             die "unknown option: $1" ;;
  esac
done

if [ -n "$PROBE_IMAGE" ]; then
  [ -z "$BINARY" ] || die "--binary and --probe-image are mutually exclusive (pick cp+nsenter OR image mode)"
else
  [ -n "$BINARY" ] || die "--binary (cp+nsenter) or --probe-image (image mode) is required"
  [ -f "$BINARY" ] || die "binary not found: $BINARY"
fi
[ -n "$ENVFILE" ] && { [ -f "$ENVFILE" ] || die "env file not found: $ENVFILE"; }

kc() { $KUBECTL "$@"; }

# ---- pick node ----
if [ -z "$NODE" ]; then
  NODE="$(kc get nodes -o jsonpath='{range .items[?(@.status.conditions[-1].status=="True")]}{.metadata.name}{"\n"}{end}' 2>/dev/null | head -1)"
  [ -n "$NODE" ] || NODE="$(kc get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
fi
[ -n "$NODE" ] || die "no node found"
if [ -n "$PROBE_IMAGE" ]; then
  log "node=$NODE probe-image=$PROBE_IMAGE mode=$PROBE_MODE profile=$PROFILE seconds=$SECONDS_RUN"
else
  log "node=$NODE image=$IMAGE profile=$PROFILE seconds=$SECONDS_RUN"
fi

# Sweep up debug pods (Succeeded/Failed) a previous run failed to tear down, for idempotency
kc get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{.status.phase}{"\n"}{end}' 2>/dev/null \
  | awk -v n="$NODE" '$2 ~ ("^node-debugger-" n "-") && ($3=="Succeeded"||$3=="Failed"){print $1, $2}' \
  | while read -r ns pod; do log "cleanup stale $ns/$pod"; kc delete pod -n "$ns" "$pod" --grace-period=1 --wait=false >/dev/null 2>&1 || true; done

# ======================================================================================
# Image mode: run the image with the probe baked in as the debug pod's own image.
# No cp+nsenter -- the image's ENTRYPOINT owns the execution model
# (SPNL_PROBE_MODE=recon|pure|hybrid). Tokens are never baked into the image; only
# non-sensitive env is injected into the debug pod (via the --env file).
# ======================================================================================
if [ -n "$PROBE_IMAGE" ]; then
  IPOD=""
  icleanup() {
    local rc=$?
    if [ -n "$IPOD" ] && [ "$KEEP" -eq 0 ]; then
      log "deleting debug pod $IPOD"
      kc delete pod "$IPOD" --grace-period=1 --wait=true --timeout=60s >/dev/null 2>&1 || true
    elif [ -n "$IPOD" ]; then
      log "--keep set; leaving pod $IPOD"
    fi
    return $rc
  }
  trap icleanup EXIT INT TERM

  # Inject non-sensitive env as --env KEY=VAL (assumed token-free; the caller is
  # expected to reject anything sensitive before it gets here).
  ENVARGS=(--env "SPNL_PROBE_MODE=$PROBE_MODE" --env "SPNL_PROBE_SECONDS=$SECONDS_RUN")
  [ -n "$MAX_EVENTS" ] && ENVARGS+=(--env "SPNL_MAX_EVENTS=$MAX_EVENTS")   # event-boxed run
  if [ -n "$ENVFILE" ]; then
    while IFS= read -r line; do
      case "$line" in ''|\#*) continue ;; esac
      ENVARGS+=(--env "$line")
    done < "$ENVFILE"
  fi

  DBG_TTL=$((SECONDS_RUN + 180))
  log "kubectl debug node/$NODE --image=$PROBE_IMAGE --profile=$PROFILE mode=$PROBE_MODE (image ENTRYPOINT)"
  DBG_OUT="$(kc debug "node/$NODE" --image="$PROBE_IMAGE" --profile="$PROFILE" \
               --image-pull-policy="$PULL_POLICY" --attach=false \
               "${ENVARGS[@]}" 2>&1 || true)"
  IPOD="$(printf '%s\n' "$DBG_OUT" | grep -oE 'node-debugger-[a-z0-9.-]+' | head -1 || true)"
  if [ -z "$IPOD" ]; then
    IPOD="$(kc get pods -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.nodeName}{"\n"}{end}' 2>/dev/null \
            | awk -v n="$NODE" '$2==n && $1 ~ /^node-debugger-/{print $1}' | tail -1)"
  fi
  [ -n "$IPOD" ] || { echo "$DBG_OUT" >&2; die "could not determine debug pod name (image mode)"; }
  log "debug pod = $IPOD"

  log "waiting for pod Running..."
  if ! kc wait --for=jsonpath='{.status.phase}'=Running "pod/$IPOD" --timeout=120s >/dev/null 2>&1; then
    phase="$(kc get pod "$IPOD" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [ "$phase" != "Running" ] && [ "$phase" != "Succeeded" ]; then
      log "pod not Running; phase=${phase:-<none>}; recent events:"
      kc describe pod "$IPOD" 2>/dev/null | sed -n '/Events:/,$p' | head -25 >&2 || true
      die "debug pod $IPOD not Running (image import? scheduling? entrypoint?)"
    fi
  fi

  # The probe (entrypoint) stops itself after the timeout, so the pod goes
  # Succeeded/Failed. Wait for that.
  log "waiting up to $((SECONDS_RUN + 60))s for probe to finish..."
  end=$(( $(date +%s) + SECONDS_RUN + 60 ))
  phase="Running"
  while [ "$(date +%s)" -lt "$end" ]; do
    phase="$(kc get pod "$IPOD" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    case "$phase" in Succeeded|Failed) break ;; esac
    sleep 3
  done
  log "probe pod phase=$phase"

  # Collect stdout (entrypoint + probe)
  if [ -n "$LOGFILE" ]; then
    kc logs "$IPOD" >"$LOGFILE" 2>&1 || true
    log "probe logs -> $LOGFILE"
  else
    kc logs "$IPOD" 2>&1 || true
  fi
  # Cleanup: the EXIT trap deletes the pod. The exit code comes from the pod phase.
  [ "$phase" = "Succeeded" ] && exit 0 || exit 1
fi

# Unique run directory (on the host's /tmp; visible from the debug pod as /host/tmp)
RUNID="spnl-oneshot-$$-$(date +%s)"
HOSTDIR="/tmp/$RUNID"           # path as seen from the node's host side (after nsenter)
PODDIR="/host/tmp/$RUNID"       # path as seen from the debug pod (host / is mounted at /host)

POD=""
cleanup() {
  local rc=$?
  if [ -n "$POD" ]; then
    # Delete everything injected (including any token in the env file) from the host
    # before deleting the pod
    kc exec "$POD" -- rm -rf "$PODDIR" >/dev/null 2>&1 || true
    if [ "$KEEP" -eq 0 ]; then
      log "deleting debug pod $POD"
      kc delete pod "$POD" --grace-period=1 --wait=true --timeout=60s >/dev/null 2>&1 || true
    else
      log "--keep set; leaving pod $POD"
    fi
  fi
  return $rc
}
trap cleanup EXIT INT TERM

# ---- create debug pod (kubectl debug node/) ----
# Create it detached with --attach=false. The command just sleeps for seconds+buffer
# and then exits on its own, as insurance against a missed teardown. The pod name is
# picked out of the creation message on stderr.
DBG_TTL=$((SECONDS_RUN + 180))
log "kubectl debug node/$NODE --profile=$PROFILE ..."
DBG_OUT="$(kc debug "node/$NODE" --image="$IMAGE" --profile="$PROFILE" \
             --image-pull-policy="$PULL_POLICY" --attach=false \
             -- sleep "$DBG_TTL" 2>&1 || true)"
POD="$(printf '%s\n' "$DBG_OUT" | grep -oE 'node-debugger-[a-z0-9.-]+' | head -1 || true)"
if [ -z "$POD" ]; then
  # Fallback: the newest node-debugger pod on the target node
  POD="$(kc get pods -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.nodeName}{"\n"}{end}' 2>/dev/null \
          | awk -v n="$NODE" '$2==n && $1 ~ /^node-debugger-/{print $1}' | tail -1)"
fi
[ -n "$POD" ] || { echo "$DBG_OUT" >&2; die "could not determine debug pod name"; }
log "debug pod = $POD"

log "waiting for pod Ready/Running..."
if ! kc wait --for=condition=Ready "pod/$POD" --timeout=120s >/dev/null 2>&1; then
  phase="$(kc get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ "$phase" != "Running" ]; then
    log "pod not Ready; phase=${phase:-<none>}; recent events:"
    kc describe pod "$POD" 2>/dev/null | sed -n '/Events:/,$p' | head -25 >&2 || true
    die "debug pod $POD not Ready (image pull? scheduling? kubectl debug unsupported?)"
  fi
  log "pod phase=Running (no readiness gate)"
fi

# ---- inject binary + aux files via kubectl cp (into /host = node root fs) ----
kc exec "$POD" -- mkdir -p "$PODDIR" || die "mkdir in debug pod failed"
BINNAME="$(basename "$BINARY")"
log "kubectl cp $BINNAME -> node:$HOSTDIR/"
kc cp "$BINARY" "$POD:$PODDIR/$BINNAME" || die "kubectl cp binary failed"

for f in "${FILES[@]:-}"; do
  [ -n "$f" ] || continue
  src="${f%%:*}"; nm="${f#*:}"; [ "$nm" = "$f" ] && nm="$(basename "$src")"
  [ -f "$src" ] || die "aux file not found: $src"
  log "kubectl cp $nm"
  kc cp "$src" "$POD:$PODDIR/$nm" || die "kubectl cp $nm failed"
done

if [ -n "$ENVFILE" ]; then
  # env may contain a token, so inject it as a file rather than on the command line
  kc cp "$ENVFILE" "$POD:$PODDIR/env" || die "kubectl cp env failed"
fi

# ---- probe args with @DIR@ substituted ----
SUBST_ARGS=()
for a in "${PROBE_ARGS[@]:-}"; do SUBST_ARGS+=("${a//@DIR@/$HOSTDIR}"); done

# ---- build the runner that executes on the host side (tokens travel via the file, never logged) ----
RUNNER="$(mktemp)"
{
  echo '#!/bin/sh'
  echo "set -a"
  echo "[ -f \"$HOSTDIR/env\" ] && . \"$HOSTDIR/env\""
  [ -n "$MAX_EVENTS" ] && echo "SPNL_MAX_EVENTS=$MAX_EVENTS"   # event-boxed one-shot
  echo "set +a"
  echo "chmod +x \"$HOSTDIR/$BINNAME\" 2>/dev/null || true"
  echo "cd \"$HOSTDIR\""
  printf 'exec timeout %s "%s/%s"' "$SECONDS_RUN" "$HOSTDIR" "$BINNAME"
  for a in "${SUBST_ARGS[@]:-}"; do printf ' %q' "$a"; done
  printf '\n'
} > "$RUNNER"
kc cp "$RUNNER" "$POD:$PODDIR/run.sh" || die "kubectl cp runner failed"
rm -f "$RUNNER"

# ---- enter the host namespaces with nsenter and run (for a bounded time) ----
log "nsenter -t 1 -m -u -i -n -p  timeout ${SECONDS_RUN}s  $BINNAME"
set +e
if [ -n "$LOGFILE" ]; then
  kc exec "$POD" -- nsenter -t 1 -m -u -i -n -p -- /bin/sh "$HOSTDIR/run.sh" >"$LOGFILE" 2>&1
  RUN_RC=$?
  log "probe exited rc=$RUN_RC (log: $LOGFILE)"
else
  kc exec "$POD" -- nsenter -t 1 -m -u -i -n -p -- /bin/sh "$HOSTDIR/run.sh"
  RUN_RC=$?
  log "probe exited rc=$RUN_RC"
fi
set -e

# ---- collect artifacts ----
for c in "${COLLECTS[@]:-}"; do
  [ -n "$c" ] || continue
  nm="${c%%:*}"; dst="${c#*:}"; [ "$dst" = "$c" ] && dst="./$nm"
  if kc cp "$POD:$PODDIR/$nm" "$dst" >/dev/null 2>&1; then log "collected $nm -> $dst"; else log "collect $nm: not found"; fi
done

# Cleanup: the EXIT trap deletes both the pod and everything injected
exit "$RUN_RC"
