#!/bin/bash
# ZDU-macOS.sh — macOS local worker and agentless SSH control plane.
# Updates include Apple software and Homebrew formulae/casks; applications or services may restart.
#
# HARD SAFETY LIMIT: Apple OS restore/snapshot rollback requires Recovery/boot operations;
# no shell script can restore an APFS snapshot online with zero reboot. This worker NEVER
# restarts macOS and NEVER claims it has restored a running root volume. On a failed gate it
# leaves the node drained, creates encrypted evidence when a recipient certificate exists,
# and invokes only an operator-approved rollback adapter.
#
# Usage: sudo ./ZDU-macOS-apply-default.sh [--plan] [--config /etc/zdu-macos.conf]
#        ./ZDU-macOS-apply-default.sh --mode cluster --hosts hosts.txt --canary mac-canary --apply
# Config is strict KEY=value (no shell evaluation). Keep it root-owned, mode 0600.
# Threat-feed transfers use a guarded curl invocation and private staged file; no `try` syntax.
set -Eeuo pipefail
umask 077
IFS=$'\n\t'
ENGINE_VERSION="1.0.0-readiness-preview"
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
MODE="local"; APPLY=0; CONFIG="$(dirname "$SCRIPT_PATH")/zdu-macos.conf"; HOST_FILE=""; CIDR=""; CANARY=""; BATCH_SIZE=2; CANARY_WAIT=300
RUN_ID="zdu-macos-$(date +%Y%m%d-%H%M%S)-$(scutil --get LocalHostName 2>/dev/null || hostname)"
RUN_ROOT="$(mktemp -d "/private/tmp/zdu-macos.XXXXXXXX")"; LOG_PATH="$RUN_ROOT/engine.log"
chmod 700 "$RUN_ROOT"
SNAPSHOT_CREATED=0; DRAINED=0; IN_FAILURE=0; EMERGENCY_ARMED=0; RUN_EPOCH="$(date +%s)"

# Conservative defaults. Values with lists are comma-separated and may be overridden by config.
REQUIRED_PORTS=""; OBSERVE_PORTS="80,443,3306,5432,8080"
PROTECTED_PROCESSES="nginx,httpd,apache2,docker,containerd,podman,kubelet,postgres,mysqld,mariadbd,mongod,oracle,redis-server"
SAFE_PROCESSES="Google Chrome,Microsoft Edge,firefox,Slack,Teams,Dropbox"
CRITICAL_BINARIES=""; EXPECTED_POST_HASHES_FILE=""; BREW_INCLUDE=""; BREW_EXCLUDE="nginx,httpd,postgresql,mysql,mariadb,mongodb-community,redis"
ALLOW_OS_UPDATES_WORKSTATION=0; ALLOW_OS_UPDATES_SERVER=0; ALLOW_NO_SNAPSHOT=0; ENABLE_DEPENDENCY_REPAIR=0; RECYCLE_SAFE_APPS=0
ERROR_RATE_PERCENT=10; MIN_NEW_ERRORS=2; MAX_DISK_LATENCY_MS=40; HISTORICAL_METRICS_FILE=""
QUARANTINED_PACKAGES=""; QUARANTINED_CVES=""; THREAT_FEED_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"; THREAT_CACHE_TTL_SECONDS=21600; THREAT_CACHE_FILE=""; CACHE_URL=""
LOG_SUBSYSTEM="com.apple.managedconfiguration"
DRAIN_COMMAND=""; ACTIVE_CONNECTIONS_COMMAND=""; ENABLE_COMMAND=""; ROLLBACK_COMMAND=""; NETWORK_QUARANTINE_COMMAND=""; FORENSIC_RECIPIENT_CERT=""
DATABASE_CHANGE_WINDOW_APPROVED=0; DATABASE_TRANSACTION_CHECK_COMMAND=""; DATABASE_BACKUP_COMMAND=""
CANARY_HOST=""; MIN_HEALTHY_NODES=1; CLUSTER_CAPACITY_COMMAND=""; MIN_OS_VERSION=""; COMPLIANCE_REQUIRED=0
REMOTE_RUNTIME_DIR="/var/run/zdu" # fixed, root-owned; never operator-configurable

usage() { cat <<'EOF'
ZDU macOS
  --mode local|cluster    Local worker or SSH control plane (default: local)
  --apply                 Execute changes (default).
  --plan                  Run checks only; do not apply updates.
  --config FILE           KEY=value policy file
  --hosts FILE            SSH target list, one DNS name/IP per line
  --cidr A.B.C.D/N        IPv4 /16-/32, maximum 4096 hosts
  --canary HOST           REQUIRED in cluster mode; pre-designated non-critical node
  --batch-size N          Rolling SSH batch size (default 2)
  --canary-wait SECONDS   Observation window (default 300)
EOF
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode|--config|--hosts|--cidr|--canary|--batch-size|--canary-wait)
      [ "$#" -ge 2 ] || { echo "Missing value for $1" >&2; usage >&2; exit 64; }
      case "$1" in --mode) MODE="$2";; --config) CONFIG="$2";; --hosts) HOST_FILE="$2";; --cidr) CIDR="$2";; --canary) CANARY="$2";; --batch-size) BATCH_SIZE="$2";; --canary-wait) CANARY_WAIT="$2";; esac; shift 2;;
    --apply) APPLY=1; shift;; --plan) APPLY=0; shift;; -h|--help) usage; exit 0;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 64;;
  esac
done
[ "$MODE" = "local" ] || [ "$MODE" = "cluster" ] || { echo "Invalid --mode" >&2; exit 64; }
[[ "$BATCH_SIZE" =~ ^[1-9][0-9]*$ ]] || { echo "--batch-size must be a positive integer" >&2; exit 64; }
[[ "$CANARY_WAIT" =~ ^[0-9]+$ ]] || { echo "--canary-wait must be a non-negative integer" >&2; exit 64; }

# SAFETY INTERLOCK: targeted diagnostic preview only, not a production engine.
# Do not remove this interlock as a substitute for completing the readiness work.
if [ "$APPLY" = 1 ]; then
  printf '%s\n' 'APPLY BLOCKED: diagnostic preview only; production safety gates remain incomplete.' >&2
  exit 78
fi

log() { # level message
  local level="$1"; shift; local color="36"; case "$level" in OK) color="32";; WARN) color="33";; FAIL) color="31";; STEP) color="35";; PLAN) color="36";; esac
  printf '\033[%sm[%s] [%-4s] %s\033[0m\n' "$color" "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$level" "$*" | tee -a "$LOG_PATH"
}
contains_csv() { # needle list
  local needle="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" item
  IFS=',' read -r -a _items <<< "$2"
  for item in "${_items[@]}"; do [ "$needle" = "$(printf '%s' "$item"|tr '[:upper:]' '[:lower:]')" ] && return 0; done
  return 1
}
trim_space() { local v="$1"; v="${v#${v%%[![:space:]]*}}"; v="${v%${v##*[![:space:]]}}"; printf '%s' "$v"; }
validate_config_trust() {
  [ -L "$CONFIG" ] && { log FAIL "Refusing symlinked policy file: $CONFIG"; return 1; }
  local owner mode mode_num; owner="$(stat -f '%u' "$CONFIG")"; mode="$(stat -f '%OLp' "$CONFIG")"
  # BSD stat normally prints 600; allow a leading special-bit digit, but reject
  # non-octal output before arithmetic conversion. 8#0600 is valid Bash octal.
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || { log FAIL "Unable to parse policy mode safely: $mode"; return 1; }
  mode_num=$((8#$mode))
  { [ "$owner" = 0 ] || [ "$owner" = "$(id -u)" ]; } || { log FAIL "Policy owner must be root or the invoking user: $CONFIG"; return 1; }
  [ $((mode_num & 18)) -eq 0 ] || { log FAIL "Policy must not be group/world writable: $CONFIG (mode $mode)"; return 1; }
}
is_valid_ipv4() {
  local IFS=. o; local -a parts=(); read -r -a parts <<< "$1"; [ "${#parts[@]}" -eq 4 ] || return 1
  for o in "${parts[@]}"; do [[ "$o" =~ ^[0-9]{1,3}$ ]] || return 1; [ "$o" -le 255 ] 2>/dev/null || return 1; done
}
is_valid_target() {
  local h="$1"; [ -n "$h" ] && [ "${#h}" -le 253 ] || return 1
  is_valid_ipv4 "$h" && return 0
  # Permit a managed OpenSSH Host alias as a safe token. user@host, whitespace, slashes,
  # shell metacharacters, option-like names, and bracketed/inline IPv6 syntax remain rejected.
  [[ "$h" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$ ]]
}
load_config() {
  [ -f "$CONFIG" ] || { log FAIL "Config missing or not a regular file: $CONFIG"; return 1; }
  # This is a data parser, not 'source': shell metacharacters in values are never evaluated here.
  validate_config_trust
  local line key value
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#${line%%[![:space:]]*}}"; [ -z "$line" ] && continue; [ "${line#\#}" != "$line" ] && continue
    key="${line%%=*}"; value="${line#*=}"; [ "$key" = "$line" ] && { log WARN "Ignoring malformed config line"; continue; }
    case "$key" in
      REQUIRED_PORTS|OBSERVE_PORTS|PROTECTED_PROCESSES|SAFE_PROCESSES|CRITICAL_BINARIES|EXPECTED_POST_HASHES_FILE|LOG_SUBSYSTEM|BREW_INCLUDE|BREW_EXCLUDE|ALLOW_OS_UPDATES_WORKSTATION|ALLOW_OS_UPDATES_SERVER|ALLOW_NO_SNAPSHOT|ENABLE_DEPENDENCY_REPAIR|RECYCLE_SAFE_APPS|ERROR_RATE_PERCENT|MIN_NEW_ERRORS|MAX_DISK_LATENCY_MS|HISTORICAL_METRICS_FILE|QUARANTINED_PACKAGES|QUARANTINED_CVES|THREAT_FEED_URL|THREAT_CACHE_TTL_SECONDS|THREAT_CACHE_FILE|CACHE_URL|DRAIN_COMMAND|ACTIVE_CONNECTIONS_COMMAND|ENABLE_COMMAND|ROLLBACK_COMMAND|NETWORK_QUARANTINE_COMMAND|FORENSIC_RECIPIENT_CERT|DATABASE_CHANGE_WINDOW_APPROVED|DATABASE_TRANSACTION_CHECK_COMMAND|DATABASE_BACKUP_COMMAND|CANARY_HOST|MIN_HEALTHY_NODES|CLUSTER_CAPACITY_COMMAND|MIN_OS_VERSION|COMPLIANCE_REQUIRED)
        # Assignment data is not evaluated as shell syntax; declare -g sets the
        # approved policy variable in this function's caller-visible global scope.
        export "$key=$value";;
      *) log WARN "Ignoring unsupported config key: $key";;
    esac
  done < "$CONFIG"
  [[ "$LOG_SUBSYSTEM" =~ ^[A-Za-z0-9._-]+$ ]] || {
    log FAIL "LOG_SUBSYSTEM must contain only letters, digits, dots, underscores, or hyphens."
    return 1
  }
  log INFO "Loaded policy file $CONFIG"
}
root() { if [ "${EUID:-$(id -u)}" -eq 0 ]; then "$@"; else sudo "$@"; fi; }
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/\\r/g; s/\n/\\n/g'; }
send_webhook() {
  local status="$1" detail="$2"; [ -n "${ZDU_WEBHOOK_URL:-}" ] || return 0
  local payload; payload=$(printf '{"text":"ZDU macOS %s — %s","run_id":"%s","status":"%s","host":"%s","detail":"%s","timestamp":"%s"}' "$(json_escape "$status")" "$(json_escape "$(hostname)")" "$(json_escape "$RUN_ID")" "$(json_escape "$status")" "$(json_escape "$(hostname)")" "$(json_escape "$detail")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)")
  curl --connect-timeout 8 --max-time 15 -fsS -H 'Content-Type: application/json' -d "$payload" "$ZDU_WEBHOOK_URL" >/dev/null || log WARN "Webhook delivery failed"
}
run_hook() { # name command required[0|1]
  local name="$1" command="$2" required="$3" output rc
  if [ -z "$command" ]; then [ "$required" = 1 ] && { log FAIL "Required adapter not configured: $name" >&2; return 1; }; log WARN "No adapter configured: $name" >&2; return 0; fi
  log STEP "Adapter: $name" >&2
  set +e; output=$(/bin/sh -c "$command" 2>&1); rc=$?; set -e
  printf 'HOOK %s:\n%s\n' "$name" "$output" >> "$LOG_PATH"
  [ "$rc" -eq 0 ] || { log FAIL "Adapter '$name' exited $rc" >&2; return "$rc"; }
  printf '%s' "$output"
}
require_apply_privilege() { [ "$APPLY" -eq 0 ] && return 0; [ "${EUID:-$(id -u)}" -eq 0 ] && return 0; sudo -v; }

get_environment() {
  OS_VERSION="$(sw_vers -productVersion)"; HOST_NAME="$(hostname)"
  CPU_PCT="$(top -l 1 -n 0 2>/dev/null | awk '/CPU usage/ {gsub(/%/,"",$7); printf "%.1f",100-$7; found=1; exit} END {if (!found) print "0"}' | tail -1)"
  local pagesize free speculative total
  pagesize="$(sysctl -n hw.pagesize 2>/dev/null || echo 4096)"; total="$(sysctl -n hw.memsize 2>/dev/null || echo 1)"
  free="$(vm_stat 2>/dev/null | awk -F: '/Pages free/ {gsub("\\.","",$2);print $2}')"; speculative="$(vm_stat 2>/dev/null | awk -F: '/Pages speculative/ {gsub("\\.","",$2);print $2}')"
  FREE_RAM_PCT="$(awk -v f="${free:-0}" -v s="${speculative:-0}" -v p="$pagesize" -v t="$total" 'BEGIN {printf "%.1f", ((f+s)*p/t)*100}')"
  # A listening service or server-management profile means "production-like" and receives server policy.
  if lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -Eqi 'nginx|httpd|postgres|mysql|mariadb|mongod|redis|docker|kubelet'; then IS_SERVER=1; else IS_SERVER=0; fi
  log INFO "Fingerprint: macOS $OS_VERSION; CPU ${CPU_PCT}%; free RAM ${FREE_RAM_PCT}%; production-like=$IS_SERVER"
}
version_lt() { awk -v a="$1" -v b="$2" 'BEGIN {split(a,A,".");split(b,B,".");for(i=1;i<=3;i++){x=A[i]+0;y=B[i]+0;if(x<y)exit 0;if(x>y)exit 1}exit 1}'; }
resource_gate() {
  awk -v c="$CPU_PCT" -v m="$FREE_RAM_PCT" 'BEGIN {exit !(c>85 || m<10)}' && {
    log FAIL 'Resource Constrained: CPU >85% or free RAM <10%.'; return 1
  }
  if [ -n "$HISTORICAL_METRICS_FILE" ]; then
    [ -f "$HISTORICAL_METRICS_FILE" ] && [ -r "$HISTORICAL_METRICS_FILE" ] || {
      log FAIL 'Configured historical metrics file is missing or unreadable.'; return 1
    }
    local latency
    latency="$(grep -Eo '"DiskLatencyP95Ms"[[:space:]]*:[[:space:]]*[0-9.]+' "$HISTORICAL_METRICS_FILE" | head -1 | grep -Eo '[0-9.]+$' || true)"
    [[ "$latency" =~ ^[0-9]+([.][0-9]+)?$ ]] && [[ "$MAX_DISK_LATENCY_MS" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
      log FAIL 'Historical disk latency or threshold is missing or malformed.'; return 1
    }
    if awk -v x="$latency" -v max="$MAX_DISK_LATENCY_MS" 'BEGIN {exit !(x>max)}'; then
      log FAIL "Predictive gate: disk latency P95 ${latency}ms exceeds ${MAX_DISK_LATENCY_MS}ms."; return 1
    fi
  fi
  return 0
}
process_fence() {
  local procs name matched="" safe=""; procs="$(ps -axo comm= 2>/dev/null || true)"
  while IFS= read -r name; do
    name="$(basename "$name")"; [ -z "$name" ] && continue
    contains_csv "$name" "$PROTECTED_PROCESSES" && matched="${matched}${matched:+,}$name"
    contains_csv "$name" "$SAFE_PROCESSES" && safe="${safe}${safe:+,}$name"
  done <<< "$procs"
  PROTECTED_FOUND="$matched"; SAFE_FOUND="$safe"; log INFO "Process fence: protected=[${PROTECTED_FOUND:-none}]; recyclable=[${SAFE_FOUND:-none}]"
  if [ "$RECYCLE_SAFE_APPS" = 1 ] && [ -n "$SAFE_FOUND" ] && [ "$APPLY" = 1 ]; then
    log WARN "Safe application recycle approved; graceful TERM begins in 15 seconds."; sleep 15
    local n; IFS=',' read -r -a _safe <<< "$SAFE_FOUND"; for n in "${_safe[@]}"; do pkill -TERM -x "$n" 2>/dev/null || true; done
  fi
}
database_guard() {
  local db; db="$(ps -axo comm= 2>/dev/null|grep -Ei '/(postgres|mysqld|mariadbd|mongod|oracle|redis-server)$' || true)"
  [ -z "$db" ] && return 0
  log WARN "DBA Guard: active engine(s): $(printf '%s' "$db"|tr '\n' ',')"
  [ "$APPLY" = 1 ] || { log PLAN "Would require DBA approval and invoke transaction/backup adapters; no DB command runs in plan mode."; return 0; }
  [ "$DATABASE_CHANGE_WINDOW_APPROVED" = 1 ] || { log FAIL "Database patching is blocked: DATABASE_CHANGE_WINDOW_APPROVED=1 is required."; return 1; }
  run_hook "database transaction check" "$DATABASE_TRANSACTION_CHECK_COMMAND" 1 >/dev/null
  run_hook "database backup/read-lock adapter" "$DATABASE_BACKUP_COMMAND" 1 >/dev/null
}
create_sbom() { # phase
  local phase f out; phase="$1"; out="$RUN_ROOT/sbom-${phase}.json"; printf '{"schema":"zdu-sbom-v1","phase":"%s","host":"%s","generated_at":"%s","brew":[' "$phase" "$(json_escape "$HOST_NAME")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out"
  if command -v brew >/dev/null 2>&1; then brew list --versions 2>/dev/null | awk 'BEGIN{s=""}{gsub(/\\/,"\\\\");gsub(/"/,"\\\"");printf "%s{\"name\":\"%s\"}",s,$0;s=","}' >> "$out"; fi
  printf '],"critical_binaries":[' >> "$out"; local first=1
  IFS=',' read -r -a _bins <<< "$CRITICAL_BINARIES"; for f in "${_bins[@]}"; do
    [ -n "$f" ] && [ -e "$f" ] || continue; [ "$first" = 1 ] || printf ',' >> "$out"; first=0
    local sha sig; sha="$(shasum -a 256 "$f"|awk '{print $1}')"; sig="$(codesign --verify --deep --strict "$f" >/dev/null 2>&1 && echo valid || echo invalid)"
    printf '{"path":"%s","sha256":"%s","signature":"%s"}' "$(json_escape "$f")" "$sha" "$sig" >> "$out"
  done; printf ']}' >> "$out"; log INFO "SBOM written: $out"
}
post_sbom_gate() {
  local f sha expected
  IFS=',' read -r -a _bins <<< "$CRITICAL_BINARIES"; for f in "${_bins[@]}"; do
    [ -n "$f" ] && [ -e "$f" ] || continue
    codesign --verify --deep --strict "$f" >/dev/null 2>&1 || { log FAIL "Supply-chain gate: invalid code signature: $f"; return 1; }
    if [ -n "$EXPECTED_POST_HASHES_FILE" ] && [ -f "$EXPECTED_POST_HASHES_FILE" ]; then
      sha="$(shasum -a 256 "$f"|awk '{print $1}')"; expected="$(awk -F= -v p="$f" '$1==p {print $2}' "$EXPECTED_POST_HASHES_FILE"|tail -1)"
      [ -z "$expected" ] || [ "$sha" = "$expected" ] || { log FAIL "Supply-chain gate: unexpected SHA-256 for $f"; return 1; }
    fi
  done
}
fetch_threat_feed() {
  [ -n "$THREAT_FEED_URL" ] || return 0
  local out="$RUN_ROOT/cisa-kev.json" cache="$THREAT_CACHE_FILE" age now
  [[ "$THREAT_CACHE_TTL_SECONDS" =~ ^[0-9]+$ ]] || { log FAIL "THREAT_CACHE_TTL_SECONDS must be an integer."; return 1; }
  [ -n "$cache" ] || { [ "$APPLY" = 1 ] && cache="/Library/Caches/ZDU/cisa-kev.json"; }
  if [ -n "$cache" ] && [ -r "$cache" ]; then
    now="$(date +%s)"; age=$((now-$(stat -f '%m' "$cache")))
    if [ "$age" -ge 0 ] && [ "$age" -le "$THREAT_CACHE_TTL_SECONDS" ]; then cp "$cache" "$out"; log INFO "Using cached CISA KEV feed (${age}s old)."; return 0; fi
  fi
  local staged="$RUN_ROOT/cisa-kev.json.part"
  rm -f "$staged"
  if ! curl --connect-timeout 10 --max-time 20 --fail --silent --show-error --location \
      --output "$staged" "$THREAT_FEED_URL"; then
    rm -f "$staged"
    if [ -n "$cache" ] && [ -r "$cache" ]; then
      cp "$cache" "$out"
      log WARN "Threat feed refresh failed; using stale cache."
      return 0
    fi
    log WARN "Threat feed refresh failed and no readable cache is available."
    return 1
  fi
  if [ ! -s "$staged" ] || ! grep -q '"vulnerabilities"' "$staged"; then
    rm -f "$staged"
    log WARN "Threat feed response was empty or did not resemble the expected CISA KEV JSON; refusing to cache it."
    if [ -n "$cache" ] && [ -r "$cache" ]; then cp "$cache" "$out"; log WARN "Using previously cached threat feed."; return 0; fi
    return 1
  fi
  mv "$staged" "$out"
  if [ "$APPLY" = 1 ] && [ -n "$cache" ]; then
    root install -d -o root -g wheel -m 0755 "$(dirname "$cache")"
    root install -o root -g wheel -m 0644 "$out" "$cache"
  fi
  log INFO "CISA KEV feed refreshed (evidence, not a vendor-recall feed)."
}
threat_gate() {
  if [ -n "$CACHE_URL" ] && ! printf '%s' "$CACHE_URL"|grep -Eq '^https://'; then log FAIL "CACHE_URL must be HTTPS; unauthenticated local P2P mirrors are refused."; return 1; fi
  fetch_threat_feed || log WARN "Threat feed unavailable"
  [ -z "$QUARANTINED_PACKAGES$QUARANTINED_CVES" ] || log WARN "Policy quarantine active; direct package/CVE mappings must come from the approved change record."
}
create_snapshot() {
  [ "$APPLY" = 1 ] || { log PLAN "Would attempt a local Time Machine snapshot."; return 0; }
  if diskutil apfs list >/dev/null 2>&1 && root tmutil localsnapshot >/dev/null 2>&1; then
    SNAPSHOT_CREATED=1; log OK "Local Time Machine snapshot command succeeded; verify backups independently."; return 0
  fi
  [ "$ALLOW_NO_SNAPSHOT" = 1 ] && { log WARN "Snapshot unavailable; policy permits continuation."; return 0; }
  log WARN "No supported snapshot was created. Updates cannot be automatically rolled back."
  if [ -t 0 ] && [ -t 1 ]; then
    local answer
    printf 'Continue without a snapshot? Type yes to continue: ' >&2
    if IFS= read -r answer && [ "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" = yes ]; then
      log WARN "Operator approved continuing without a snapshot for this run."; return 0
    fi
  else
    log WARN "No interactive terminal available; cannot request snapshot override."
  fi
  log FAIL "Snapshot gate failed; updates were not installed."; return 1
}
start_drain() {
  [ "$APPLY" = 1 ] || { log PLAN "Would drain the node and wait for zero inflight connections; no proxy command runs in plan mode."; return 0; }
  if [ -z "$DRAIN_COMMAND" ]; then
    if [ "${IS_SERVER:-0}" = 1 ] || [ -n "${PROTECTED_FOUND:-}" ]; then log FAIL "Refusing updates: production/protected workload requires a configured DRAIN_COMMAND and ACTIVE_CONNECTIONS_COMMAND."; return 1; fi
    log WARN "No drain adapter configured; continuing only because no protected workload was detected."; return 0
  fi
  run_hook "proxy drain" "$DRAIN_COMMAND" 1 >/dev/null; DRAINED=1
  [ -n "$ACTIVE_CONNECTIONS_COMMAND" ] || { log FAIL "Drain adapter requires ACTIVE_CONNECTIONS_COMMAND."; return 1; }
  local end=$(( $(date +%s) + 1200 )) n
  while :; do n="$(run_hook "active connection probe" "$ACTIVE_CONNECTIONS_COMMAND" 1|tr -d '[:space:]')"; [[ "$n" =~ ^[0-9]+$ ]] || { log FAIL "Active connection adapter must return an integer."; return 1; }; [ "$n" -eq 0 ] && break
    [ "$(date +%s)" -lt "$end" ] || { log FAIL "Drain timeout: $n inflight connections remain."; return 1; }; log INFO "Waiting for $n inflight request(s) to complete."; sleep 10
  done
}
rejoin_node() { [ "$DRAINED" = 0 ] && return 0; run_hook "proxy rejoin" "$ENABLE_COMMAND" 1 >/dev/null; DRAINED=0; }
list_nonrestart_updates() {
  local raw="$RUN_ROOT/softwareupdate-list.txt"; softwareupdate -l >"$raw" 2>&1 || true
  # Each update block ending in restart is withheld. No --restart flag is ever passed.
  awk '
    /^[[:space:]]*\*[[:space:]]/ { if (label!="" && !restart) print label; line=$0; sub(/^[[:space:]]*\*[[:space:]]*/,"",line); sub(/^Label:[[:space:]]*/,"",line); label=line; restart=0; next }
    tolower($0) ~ /\[restart\]|action:[[:space:]]*restart/ {restart=1}
    END {if(label!="" && !restart) print label}
  ' "$raw" > "$RUN_ROOT/nonrestart-labels.txt"
  grep -Ei '\[restart\]|action:[[:space:]]*restart' "$raw" >> "$RUN_ROOT/restart-deferred.txt" || true
}
update_softwareupdate() {
  [ "$APPLY" = 1 ] || { log PLAN "Would install available Apple software updates without requesting an automatic restart; some updates may require a restart or user authorization."; return 0; }
  log WARN "Installing Apple updates; restart-required updates may remain pending or require user authorization. No automatic restart is requested."
  root softwareupdate --install --all
}
update_brew() {
  local brew_bin="" brew_user="${SUDO_USER:-}"
  if [ -x /opt/homebrew/bin/brew ]; then brew_bin=/opt/homebrew/bin/brew
  elif [ -x /usr/local/bin/brew ]; then brew_bin=/usr/local/bin/brew
  elif command -v brew >/dev/null 2>&1; then brew_bin="$(command -v brew)"; fi
  [ -n "$brew_bin" ] || { log INFO "Homebrew absent; Homebrew update phase skipped."; return 0; }
  [ "$APPLY" = 1 ] || { log PLAN "Would update Homebrew and upgrade installed formulae and casks."; return 0; }
  log WARN "Homebrew upgrades can restart services or close applications."
  if [ "$(id -u)" -eq 0 ]; then
    [ -n "$brew_user" ] && [ "$brew_user" != root ] || { log FAIL "Homebrew must run as a non-root user. Run the script with sudo from the Homebrew user's account."; return 1; }
    sudo -u "$brew_user" -H "$brew_bin" update || return $?
    sudo -u "$brew_user" -H "$brew_bin" upgrade --formula || return $?
    sudo -u "$brew_user" -H "$brew_bin" upgrade --cask || return $?
  else
    "$brew_bin" update || return $?
    "$brew_bin" upgrade --formula || return $?
    "$brew_bin" upgrade --cask || return $?
  fi
}
controlled_deployment() { start_drain; update_brew; update_softwareupdate; }
listening_ports() {
  local sockets rc=0 err="$RUN_ROOT/lsof-errors.txt"
  sockets="$(lsof -nP -iTCP -sTCP:LISTEN 2>"$err")" || rc=$?
  if [ "$rc" -ne 0 ] && { [ "$rc" -ne 1 ] || [ -s "$err" ]; }; then
    cat "$err" >&2; echo "Failed to collect listening TCP ports with lsof (exit $rc)." >&2; return "$rc"
  fi
  printf '%s\n' "$sockets" | awk 'NR>1 {n=split($9,a,":"); if (a[n] ~ /^[0-9]+$/) print a[n]}' | sort -nu
}
health_check() {
  local ports="$REQUIRED_PORTS" observed="" p missing=""
  if [ -z "$ports" ]; then IFS=',' read -r -a _observe <<< "$OBSERVE_PORTS"; for p in "${_observe[@]}"; do printf '%s\n' "$BEFORE_PORTS"|grep -qx "$p" && observed="${observed}${observed:+,}$p"; done; ports="$observed"; fi
  IFS=',' read -r -a _ports <<< "$ports"; for p in "${_ports[@]}"; do [ -z "$p" ] && continue; if ! listening_ports | grep -qx "$p" || ! nc -z -G 3 127.0.0.1 "$p" >/dev/null 2>&1; then missing="${missing}${missing:+,}$p"; fi; done
  log INFO "Port smoke test: required=[${ports:-none}], missing=[${missing:-none}]"; [ -z "$missing" ] || { log FAIL "Health gate failed: port(s) not accepting TCP: $missing"; return 1; }
}
error_count() {
  local predicate output
  # LOG_SUBSYSTEM is validated as a restricted token in load_config; no shell evaluation.
  predicate="subsystem == \"$LOG_SUBSYSTEM\" AND eventMessage CONTAINS[c] \"error\""
  output="$(/usr/bin/log show --style compact --last 5m --predicate "$predicate" 2>/dev/null)" || {
    log FAIL "Unified Logging query failed for subsystem $LOG_SUBSYSTEM."
    return 1
  }
  printf '%s\n' "$output" | awk 'NF {n++} END {print n+0}'
}
log_anomaly_gate() {
  local after
  after="$(error_count)" || return 1
  [[ "$after" =~ ^[0-9]+$ ]] || { log FAIL "Unified Logging returned a non-numeric count."; return 1; }
  if [ "$after" -ge "$MIN_NEW_ERRORS" ] && awk -v a="$after" -v b="$BASELINE_ERRORS" -v p="$ERROR_RATE_PERCENT" 'BEGIN{exit !(a>b*(1+p/100))}'; then
    log FAIL "Unified log anomaly in $LOG_SUBSYSTEM: $after errors vs preflight baseline $BASELINE_ERRORS."
    return 1
  fi
  log INFO "Unified-log health: subsystem=$LOG_SUBSYSTEM baseline=$BASELINE_ERRORS current=$after"
}
forensic_bundle() {
  local why="$1" dir="$RUN_ROOT/evidence" archive="$RUN_ROOT/forensic-${RUN_ID}.tar.gz"; mkdir -p "$dir"; chmod 700 "$dir"
  printf '%s\n' "$why" > "$dir/reason.txt"; ps -axo pid,ppid,%cpu,%mem,rss,command > "$dir/processes.txt" || true; lsof -nP -i > "$dir/sockets.txt" 2>/dev/null || true; vm_stat > "$dir/vm_stat.txt" || true
  cp "$LOG_PATH" "$dir/" 2>/dev/null || true; cp "$RUN_ROOT"/sbom-*.json "$dir/" 2>/dev/null || true; tar -czf "$archive" -C "$RUN_ROOT" evidence
  if [ -n "$FORENSIC_RECIPIENT_CERT" ] && [ -r "$FORENSIC_RECIPIENT_CERT" ]; then openssl cms -encrypt -binary -aes-256-cbc -in "$archive" -out "${archive}.p7m" -outform DER "$FORENSIC_RECIPIENT_CERT" && rm -f "$archive" && log OK "CMS-encrypted forensic bundle created." || log WARN "Forensic encryption failed; archive ACL is restricted."; else log WARN "Forensic archive is unencrypted: configure FORENSIC_RECIPIENT_CERT to a CMS recipient cert."; fi
}
emergency_response() { local why="$1"; log FAIL "Emergency response: $why"; forensic_bundle "$why"; [ -n "$ROLLBACK_COMMAND" ] && run_hook "approved rollback" "$ROLLBACK_COMMAND" 1 >/dev/null || log WARN "Node is left drained/quarantined; APFS snapshots cannot be restored online. Configure a tested ROLLBACK_COMMAND."; }
on_error() { local rc="$?" line="$1" cmd="$2"; [ "$IN_FAILURE" = 1 ] && exit "$rc"; IN_FAILURE=1; trap - ERR; if [ "$EMERGENCY_ARMED" != 1 ]; then log FAIL "Pre-deployment failure at line $line: $cmd (package deployment not started; earlier checks or snapshot may have changed files)."; send_webhook failure "Pre-deployment failure at line $line"; exit "$rc"; fi; emergency_response "Unexpected failure at line $line: $cmd" || true; send_webhook failure "Unexpected failure at line $line"; exit "$rc"; }
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

compliance_gate() {
  [ "$COMPLIANCE_REQUIRED" = 1 ] || return 0
  [ -n "$MIN_OS_VERSION" ] || { log FAIL 'Compliance requires MIN_OS_VERSION.'; return 1; }
  if version_lt "$OS_VERSION" "$MIN_OS_VERSION"; then
    log FAIL "Non-compliant macOS $OS_VERSION is below $MIN_OS_VERSION."
    if [ "$APPLY" = 1 ]; then
      [ -n "$NETWORK_QUARANTINE_COMMAND" ] || { log FAIL 'No NAC adapter configured.'; return 1; }
      run_hook 'NAC quarantine' "$NETWORK_QUARANTINE_COMMAND" 1 >/dev/null || return 1
    fi
    return 1
  fi
  return 0
}
local_main() {
  load_config; require_apply_privilege; get_environment; compliance_gate; resource_gate; process_fence; BASELINE_ERRORS="$(error_count)"; BEFORE_PORTS="$(listening_ports)"
  log STEP "[1/9] Threat/SBOM preflight"; threat_gate; create_sbom pre
  log STEP "[2/9] APFS snapshot gate"; create_snapshot
  log STEP "[3/9] DBA transaction gate"; database_guard
  log STEP "[4/9] Controlled no-reboot deployment"; [ "$APPLY" = 1 ] && EMERGENCY_ARMED=1; controlled_deployment
  log STEP "[5/9] Cryptographic SBOM validation"; create_sbom post; post_sbom_gate
  log STEP "[6/9] TCP smoke checks"; health_check
  log STEP "[7/9] Event-loop anomaly check"; log_anomaly_gate
  log STEP "[8/9] Hot-swap rejoin"; rejoin_node
  log STEP "[9/9] Reboot status"; log OK "Update steps completed. Some updates may still need a restart or user action; no reboot was invoked."; send_webhook success "Completed without invoking a reboot."
}
expand_cidr() { perl -MSocket -e 'my($ip,$bits)=split m!/!,shift; die "CIDR /16-/32 only\n" if $bits<16||$bits>32; my $n=unpack("N",inet_aton($ip));my $count=2**(32-$bits);die "CIDR >4096 hosts\n" if $count>4096;my $mask=(0xffffffff << (32-$bits)) & 0xffffffff;for my $i (1..$count-2){print inet_ntoa(pack("N",($n&$mask)+$i)),"\n"}' "$1"; }
cluster_capacity_gate() { [ -z "$CLUSTER_CAPACITY_COMMAND" ] && return 0; local n; n="$(run_hook "cluster HA capacity" "$CLUSTER_CAPACITY_COMMAND" 1|tr -d '[:space:]')"; [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge "$MIN_HEALTHY_NODES" ] || { log FAIL "HA capacity gate: healthy=$n, minimum=$MIN_HEALTHY_NODES"; return 1; }; }
remote_worker() { # validated hostname/IP; target needs sudo NOPASSWD for cluster operation
  local h="$1" safe_id remote_cfg="" args="--mode local" rc=0
  is_valid_target "$h" || { log FAIL "Rejected invalid SSH target: $h"; return 64; }
  safe_id="${RUN_ID//[^A-Za-z0-9_.-]/_}"
  if [ -f "$CONFIG" ]; then
    remote_cfg="$REMOTE_RUNTIME_DIR/${safe_id}.conf"
    # Stream directly through the authenticated channel into a root-only directory. No /tmp,
    # no scp staging, and no target-controlled path is ever used.
    ssh -T -o BatchMode=yes -o ConnectTimeout=15 -- "$h" "sudo -n install -d -o root -g root -m 0700 -- '$REMOTE_RUNTIME_DIR' && sudo -n tee -- '$remote_cfg' >/dev/null && sudo -n chmod 600 -- '$remote_cfg'" < "$CONFIG" || return $?
    args="$args --config '$remote_cfg'"
  fi
  if [ "$APPLY" = 1 ]; then args="$args --apply"; else args="$args --plan"; fi
  set +e
  ssh -tt -o BatchMode=yes -o ConnectTimeout=15 -- "$h" "sudo -n bash -s -- $args" < "$SCRIPT_PATH"
  rc=$?
  set -e
  [ -z "$remote_cfg" ] || ssh -T -o BatchMode=yes -o ConnectTimeout=15 -- "$h" "sudo -n rm -f -- '$remote_cfg'" >/dev/null 2>&1 || log WARN "Could not remove remote policy file on $h"
  return "$rc"
}
run_batch() {
  local failures=0 h i safe_log
  local -a pids=() hosts=()
  for h in "$@"; do
    is_valid_target "$h" || { log FAIL "Rejected invalid batch target: $h"; return 64; }
    safe_log="${h//[^A-Za-z0-9_.-]/_}"
    (
      remote_worker "$h" >"$RUN_ROOT/remote-${safe_log}.log" 2>&1
    ) &
    pids+=("$!")
    hosts+=("$h")
  done
  for i in "${!pids[@]}"; do
    wait "${pids[$i]}" || { log FAIL "Remote node failed: ${hosts[$i]}"; failures=$((failures+1)); }
  done
  return "$failures"
}
cluster_main() {
  load_config; [ "$APPLY" = 0 ] || [ -n "$CLUSTER_CAPACITY_COMMAND" ] || { log FAIL "Apply-mode cluster rollout requires CLUSTER_CAPACITY_COMMAND to enforce minimum HA capacity."; return 1; }; local -a targets=(); local h
  [ -z "$HOST_FILE" ] || { [ -f "$HOST_FILE" ] || { log FAIL "Host file not found: $HOST_FILE"; return 1; }; while IFS= read -r h; do h="$(trim_space "${h%%#*}")"; [ -z "$h" ] && continue; is_valid_target "$h" || { log FAIL "Invalid host-file target: $h"; return 64; }; targets+=("$h"); done < "$HOST_FILE"; }
  [ -z "$CIDR" ] || while IFS= read -r h; do is_valid_target "$h" || { log FAIL "Invalid CIDR-expanded target: $h"; return 64; }; targets+=("$h"); done < <(expand_cidr "$CIDR")
  [ "${#targets[@]}" -ge 2 ] || { log FAIL "Cluster mode requires two or more targets."; return 1; }
  [ -n "$CANARY" ] || CANARY="$CANARY_HOST"; [ -n "$CANARY" ] || { log FAIL "A pre-designated non-critical --canary is mandatory; criticality is never guessed."; return 1; }; is_valid_target "$CANARY" || { log FAIL "Invalid canary target."; return 64; }
  local found=0; for h in "${targets[@]}"; do [ "$h" = "$CANARY" ] && found=1; done; [ "$found" = 1 ] || { log FAIL "Canary is not in target list."; return 1; }
  log STEP "Canary deployment: $CANARY (one node only)"; cluster_capacity_gate; run_batch "$CANARY" || { log FAIL "Canary failed: rollout aborted."; return 1; }
  log INFO "Canary passed; observing for ${CANARY_WAIT}s."; sleep "$CANARY_WAIT"
  local -a remaining=() batch=(); for h in "${targets[@]}"; do [ "$h" = "$CANARY" ] || remaining+=("$h"); done
  for h in "${remaining[@]}"; do batch+=("$h"); if [ "${#batch[@]}" -ge "$BATCH_SIZE" ]; then cluster_capacity_gate; log STEP "Rolling batch: ${batch[*]}"; run_batch "${batch[@]}" || { log FAIL "Batch failed; remaining fleet untouched."; return 1; }; batch=(); fi; done
  [ "${#batch[@]}" -eq 0 ] || { cluster_capacity_gate; log STEP "Rolling batch: ${batch[*]}"; run_batch "${batch[@]}" || return 1; }
  log OK "Cluster rollout complete."; send_webhook success "macOS cluster rollout complete."
}
if [ "$MODE" = local ]; then local_main; else cluster_main; fi
