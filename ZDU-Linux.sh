#!/usr/bin/env bash
# ZDU-Linux.sh — Debian/Ubuntu + RHEL/CentOS/Rocky/Alma universal local worker and SSH control plane.
#
# This engine never calls reboot/shutdown/systemctl reboot. Full upgrades include kernel and
# service packages and can restart services or require a reboot. A Btrfs/ZFS/LVM snapshot is a recovery artifact,
# NOT an online root-volume rollback. A health failure drains/quarantines the node and executes
# only an explicit, tested ROLLBACK_COMMAND. Use signed OS repositories and change-approved
# proxy/DB adapters; do not treat this file as a replacement for a HA topology.
#
# Updates apply by default. Use --plan for a non-deployment preview.
set -Eeuo pipefail
umask 077
IFS=$'\n\t'
ENGINE_VERSION="1.0.0-readiness-preview"
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
MODE="local"; APPLY=0; CONFIG="$(dirname "$SCRIPT_PATH")/zdu-linux.conf"; HOST_FILE=""; CIDR=""; CANARY=""; BATCH_SIZE=2; CANARY_WAIT=300
RUN_ID="zdu-linux-$(date +%Y%m%d-%H%M%S)-$(hostname -s)-$$"; RUN_ROOT="$(mktemp -d /var/tmp/zdu-linux.XXXXXXXX)"; LOG_PATH="$RUN_ROOT/engine.log"
mkdir -p "$RUN_ROOT"; chmod 700 "$RUN_ROOT"; SNAPSHOT_CREATED=0; DRAINED=0; IN_FAILURE=0; EMERGENCY_ARMED=0; RUN_EPOCH="$(date +%s)"; POLICY_RC_CREATED=0

# Strict data-only KEY=value policy defaults. Lists use comma separation. No config is sourced.
REQUIRED_PORTS=""; OBSERVE_PORTS="80,443,3306,5432,8080"
PROTECTED_PROCESSES="nginx,apache2,httpd,docker,containerd,podman,kubelet,postgres,mysqld,mariadbd,mongod,oracle,redis-server,haproxy,pgbouncer,proxysql"
SAFE_PROCESSES="firefox,chrome,chromium,code,slack,teams"
CRITICAL_BINARIES=""; EXPECTED_POST_HASHES_FILE=""; PACKAGE_ALLOWLIST=""; PACKAGE_DENYLIST=""; ALLOW_OS_UPDATES_WORKSTATION=0; ALLOW_OS_UPDATES_SERVER=0; ALLOW_NO_SNAPSHOT=0; ENABLE_DEPENDENCY_REPAIR=0; ALLOW_SNAP=0
ERROR_RATE_PERCENT=10; MIN_NEW_ERRORS=2; MAX_DISK_LATENCY_MS=40; HISTORICAL_METRICS_FILE=""
QUARANTINED_PACKAGES=""; QUARANTINED_CVES=""; THREAT_FEED_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"; THREAT_CACHE_TTL_SECONDS=21600; THREAT_CACHE_FILE=""; CACHE_URL=""
SNAPSHOT_DIR="/var/lib/zdu/snapshots"; LVM_SNAPSHOT_SIZE="10G"; DRAIN_COMMAND=""; ACTIVE_CONNECTIONS_COMMAND=""; ENABLE_COMMAND=""; ROLLBACK_COMMAND=""; NETWORK_QUARANTINE_COMMAND=""; FORENSIC_RECIPIENT_CERT=""
DATABASE_CHANGE_WINDOW_APPROVED=0; DATABASE_TRANSACTION_CHECK_COMMAND=""; DATABASE_BACKUP_COMMAND=""
CANARY_HOST=""; MIN_HEALTHY_NODES=1; CLUSTER_CAPACITY_COMMAND=""; MIN_KERNEL_VERSION=""; COMPLIANCE_REQUIRED=0
REMOTE_RUNTIME_DIR="/run/zdu" # fixed, root-owned; never operator-configurable

usage() { cat <<'EOF'
ZDU Linux
  --mode local|cluster | --apply | --plan | --config FILE
  Updates are applied by default; --plan previews without deploying.
  --hosts FILE          SSH target list; one hostname/IP per line
  --cidr A.B.C.D/N      IPv4 /16-/32, maximum 4096 nodes
  --canary HOST         REQUIRED, explicitly designated non-critical host
  --batch-size N        Progressive rolling batch size (default 2)
  --canary-wait N       Post-canary observation seconds (default 300)
EOF
}
while [ "$#" -gt 0 ]; do case "$1" in
  --mode) MODE="$2"; shift 2;; --apply) APPLY=1; shift;; --plan) APPLY=0; shift;; --config) CONFIG="$2"; shift 2;; --hosts) HOST_FILE="$2"; shift 2;; --cidr) CIDR="$2"; shift 2;; --canary) CANARY="$2"; shift 2;; --batch-size) BATCH_SIZE="$2"; shift 2;; --canary-wait) CANARY_WAIT="$2"; shift 2;; -h|--help) usage; exit 0;; *) echo "Unknown argument: $1" >&2; usage >&2; exit 64;; esac; done
[ "$MODE" = local ] || [ "$MODE" = cluster ] || { echo 'Invalid --mode' >&2; exit 64; }

# SAFETY INTERLOCK: targeted diagnostic preview only, not a production engine.
# Do not remove this interlock as a substitute for completing the readiness work.
if [ "$APPLY" = 1 ]; then
  printf '%s\n' 'APPLY BLOCKED: diagnostic preview only; production safety gates remain incomplete.' >&2
  exit 78
fi

log() { local level="$1"; shift; local color=36; case "$level" in OK) color=32;; WARN) color=33;; FAIL) color=31;; STEP) color=35;; PLAN) color=36;; esac; printf '\033[%sm[%s] [%-4s] %s\033[0m\n' "$color" "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$level" "$*" | tee -a "$LOG_PATH"; }
contains_csv() { local needle="$(printf %s "$1"|tr '[:upper:]' '[:lower:]')" item; IFS=',' read -r -a _items <<< "$2"; for item in "${_items[@]}"; do [ "$needle" = "$(printf %s "$item"|tr '[:upper:]' '[:lower:]')" ] && return 0; done; return 1; }
trim_space() { local v="$1"; v="${v#${v%%[![:space:]]*}}"; v="${v%${v##*[![:space:]]}}"; printf '%s' "$v"; }
validate_config_trust() {
  [ -L "$CONFIG" ] && { log FAIL "Refusing symlinked policy file: $CONFIG"; return 1; }
  local owner mode mode_num; owner="$(stat -c '%u' "$CONFIG")"; mode="$(stat -c '%a' "$CONFIG")"
  # GNU/BSD stat normally prints 600; allow a leading special-bit digit, but reject
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
  validate_config_trust
  local line key value
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#${line%%[![:space:]]*}}"; [ -z "$line" ] && continue; [ "${line#\#}" != "$line" ] && continue; key="${line%%=*}"; value="${line#*=}"; [ "$key" = "$line" ] && { log WARN 'Ignoring malformed config line'; continue; }
    case "$key" in
      REQUIRED_PORTS|OBSERVE_PORTS|PROTECTED_PROCESSES|SAFE_PROCESSES|CRITICAL_BINARIES|EXPECTED_POST_HASHES_FILE|PACKAGE_ALLOWLIST|PACKAGE_DENYLIST|ALLOW_OS_UPDATES_WORKSTATION|ALLOW_OS_UPDATES_SERVER|ALLOW_NO_SNAPSHOT|ENABLE_DEPENDENCY_REPAIR|ALLOW_SNAP|ERROR_RATE_PERCENT|MIN_NEW_ERRORS|MAX_DISK_LATENCY_MS|HISTORICAL_METRICS_FILE|QUARANTINED_PACKAGES|QUARANTINED_CVES|THREAT_FEED_URL|THREAT_CACHE_TTL_SECONDS|THREAT_CACHE_FILE|CACHE_URL|SNAPSHOT_DIR|LVM_SNAPSHOT_SIZE|DRAIN_COMMAND|ACTIVE_CONNECTIONS_COMMAND|ENABLE_COMMAND|ROLLBACK_COMMAND|NETWORK_QUARANTINE_COMMAND|FORENSIC_RECIPIENT_CERT|DATABASE_CHANGE_WINDOW_APPROVED|DATABASE_TRANSACTION_CHECK_COMMAND|DATABASE_BACKUP_COMMAND|CANARY_HOST|MIN_HEALTHY_NODES|CLUSTER_CAPACITY_COMMAND|MIN_KERNEL_VERSION|COMPLIANCE_REQUIRED) export "$key=$value";;
      *) log WARN "Ignoring unsupported config key: $key";;
    esac
  done < "$CONFIG"; log INFO "Loaded policy file $CONFIG"
}
json_escape() { printf '%s' "$1"|sed 's/\\/\\\\/g;s/"/\\"/g;s/\r/\\r/g;s/\n/\\n/g'; }
send_webhook() { local status="$1" detail="$2"; [ -n "${ZDU_WEBHOOK_URL:-}" ] || return 0; local p; p=$(printf '{"text":"ZDU Linux %s — %s","run_id":"%s","status":"%s","host":"%s","detail":"%s","timestamp":"%s"}' "$(json_escape "$status")" "$(json_escape "$(hostname)")" "$(json_escape "$RUN_ID")" "$(json_escape "$status")" "$(json_escape "$(hostname)")" "$(json_escape "$detail")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"); curl --connect-timeout 8 --max-time 15 -fsS -H 'Content-Type: application/json' -d "$p" "$ZDU_WEBHOOK_URL" >/dev/null || log WARN 'Webhook delivery failed'; }
run_hook() { # name command required; do not put secrets in the config
  local name="$1" command="$2" required="$3" out rc
  if [ -z "$command" ]; then [ "$required" = 1 ] && { log FAIL "Required adapter not configured: $name" >&2; return 1; }; log WARN "No adapter configured: $name" >&2; return 0; fi
  log STEP "Adapter: $name" >&2; set +e; out=$(/bin/sh -c "$command" 2>&1); rc=$?; set -e; printf 'HOOK %s:\n%s\n' "$name" "$out" >> "$LOG_PATH"; [ "$rc" -eq 0 ] || { log FAIL "Adapter '$name' exited $rc" >&2; return "$rc"; }; printf '%s' "$out"
}
require_apply_privilege() { [ "$APPLY" = 0 ] || [ "$(id -u)" -eq 0 ] || { log FAIL 'Apply mode must run as root (use sudo).'; return 1; }; }

cpu_percent() { local a b; a="$(awk '/^cpu /{for(i=2;i<=NF;i++)s+=$i; idle=$5; print s,idle}' /proc/stat)"; sleep 1; b="$(awk '/^cpu /{for(i=2;i<=NF;i++)s+=$i; idle=$5; print s,idle}' /proc/stat)"; awk -v a="$a" -v b="$b" 'BEGIN{split(a,A," ");split(b,B," ");t=B[1]-A[1];i=B[2]-A[2];if(t<=0)print 0;else printf "%.1f",100-(100*i/t)}'; }
get_environment() {
  . /etc/os-release; OS_ID="${ID:-unknown}"; OS_PRETTY="${PRETTY_NAME:-$OS_ID}"; CPU_PCT="$(cpu_percent)"; FREE_RAM_PCT="$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2} END {if(t)printf "%.1f",a*100/t;else print 0}' /proc/meminfo)"
  if ss -ltnp 2>/dev/null|grep -Eqi 'nginx|apache|httpd|postgres|mysql|mariadb|mongod|redis|docker|kubelet|haproxy|pgbouncer|proxysql'; then IS_SERVER=1; elif systemctl is-active --quiet multi-user.target 2>/dev/null && ! systemctl is-active --quiet graphical.target 2>/dev/null; then IS_SERVER=1; else IS_SERVER=0; fi
  log INFO "Fingerprint: $OS_PRETTY; kernel $(uname -r); CPU ${CPU_PCT}%; free RAM ${FREE_RAM_PCT}%; production-like=$IS_SERVER"
}
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
  local pid comm base exe pkg; PROTECTED_FOUND=""; SAFE_FOUND=""; PROTECTED_PACKAGES=""
  while IFS=' ' read -r pid comm; do
    base="$(basename "$comm")"; [ -z "$base" ] && continue
    if contains_csv "$base" "$PROTECTED_PROCESSES"; then
      PROTECTED_FOUND="${PROTECTED_FOUND}${PROTECTED_FOUND:+,}$base"; exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null||true)"; pkg=""
      if [ -n "$exe" ]; then if command -v dpkg-query >/dev/null 2>&1; then pkg="$(dpkg-query -S "$exe" 2>/dev/null|head -1|cut -d: -f1||true)"; elif command -v rpm >/dev/null 2>&1; then pkg="$(rpm -qf "$exe" 2>/dev/null||true)"; fi; fi
      [ -z "$pkg" ] || PROTECTED_PACKAGES="${PROTECTED_PACKAGES}${PROTECTED_PACKAGES:+,}$pkg"
    fi
    contains_csv "$base" "$SAFE_PROCESSES" && SAFE_FOUND="${SAFE_FOUND}${SAFE_FOUND:+,}$base"
  done < <(ps -eo pid=,comm= 2>/dev/null)
  PROTECTED_FOUND="$(printf '%s' "$PROTECTED_FOUND"|awk -F, '{for(i=1;i<=NF;i++)if(!s[$i]++)printf (o++?",":"")$i}')"; PROTECTED_PACKAGES="$(printf '%s' "$PROTECTED_PACKAGES"|awk -F, '{for(i=1;i<=NF;i++)if($i!=""&&!s[$i]++)printf (o++?",":"")$i}')"
  log INFO "Process fence: protected=[${PROTECTED_FOUND:-none}], mapped packages=[${PROTECTED_PACKAGES:-none}], safe=[${SAFE_FOUND:-none}]"
}
database_guard() { local db; db="$(ps -eo comm=|grep -E '/?(postgres|mysqld|mariadbd|mongod|oracle|redis-server)$' || true)"; [ -z "$db" ] && return 0; log WARN "DBA Guard: active engine(s): $(printf '%s' "$db"|tr '\n' ',')"; [ "$APPLY" = 1 ] || { log PLAN 'Would require DBA approval and invoke transaction/backup adapters; no DB command runs in plan mode.'; return 0; }; [ "$DATABASE_CHANGE_WINDOW_APPROVED" = 1 ] || { log FAIL 'Database changes blocked: DATABASE_CHANGE_WINDOW_APPROVED=1 is required.'; return 1; }; run_hook 'database transaction check' "$DATABASE_TRANSACTION_CHECK_COMMAND" 1 >/dev/null; run_hook 'database backup/read-lock adapter' "$DATABASE_BACKUP_COMMAND" 1 >/dev/null; }
create_sbom() { local phase out f first; phase="$1"; out="$RUN_ROOT/sbom-${phase}.json"; first=1; printf '{"schema":"zdu-sbom-v1","phase":"%s","host":"%s","generated_at":"%s","packages":[' "$phase" "$(json_escape "$(hostname)")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out"; if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null|awk 'BEGIN{s=""}{gsub(/\\/,"\\\\");gsub(/"/,"\\\"");printf "%s{\"name\":\"%s\",\"version\":\"%s\"}",s,$1,$2;s=","}' >> "$out"; else rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null|awk 'BEGIN{s=""}{gsub(/\\/,"\\\\");gsub(/"/,"\\\"");printf "%s{\"name\":\"%s\",\"version\":\"%s\"}",s,$1,$2;s=","}' >> "$out"; fi; printf '],"critical_binaries":[' >> "$out"; IFS=',' read -r -a _bins <<< "$CRITICAL_BINARIES"; for f in "${_bins[@]}"; do [ -n "$f" ] && [ -f "$f" ] || continue; [ "$first" = 1 ] || printf ',' >> "$out"; first=0; printf '{"path":"%s","sha256":"%s"}' "$(json_escape "$f")" "$(sha256sum "$f"|awk '{print $1}')" >> "$out"; done; printf ']}' >> "$out"; log INFO "SBOM written: $out"; }
post_sbom_gate() { local f sha expected; IFS=',' read -r -a _bins <<< "$CRITICAL_BINARIES"; for f in "${_bins[@]}"; do [ -n "$f" ] && [ -f "$f" ] || continue; sha="$(sha256sum "$f"|awk '{print $1}')"; if [ -n "$EXPECTED_POST_HASHES_FILE" ] && [ -f "$EXPECTED_POST_HASHES_FILE" ]; then expected="$(awk -F= -v p="$f" '$1==p{print $2}' "$EXPECTED_POST_HASHES_FILE"|tail -1)"; [ -z "$expected" ] || [ "$expected" = "$sha" ] || { log FAIL "Supply-chain gate: unexpected SHA-256 for $f"; return 1; }; fi; done; }
fetch_threat_feed() {
  [ -n "$THREAT_FEED_URL" ] || return 0
  local out="$RUN_ROOT/cisa-kev.json" cache="$THREAT_CACHE_FILE" age now
  [[ "$THREAT_CACHE_TTL_SECONDS" =~ ^[0-9]+$ ]] || { log FAIL 'THREAT_CACHE_TTL_SECONDS must be an integer.'; return 1; }
  [ -n "$cache" ] || { [ "$APPLY" = 1 ] && cache="/var/cache/zdu/cisa-kev.json"; }
  if [ -n "$cache" ] && [ -r "$cache" ]; then
    now="$(date +%s)"; age=$((now-$(stat -c '%Y' "$cache")))
    if [ "$age" -ge 0 ] && [ "$age" -le "$THREAT_CACHE_TTL_SECONDS" ]; then cp "$cache" "$out"; log INFO "Using cached CISA KEV feed (${age}s old)."; return 0; fi
  fi
  if command -v curl >/dev/null 2>&1; then curl --connect-timeout 10 --max-time 20 -fsSL "$THREAT_FEED_URL" -o "$out"; else wget -T 20 -qO "$out" "$THREAT_FEED_URL"; fi || { [ -n "$cache" ] && [ -r "$cache" ] && { cp "$cache" "$out"; log WARN 'Threat feed refresh failed; using stale cache.'; return 0; }; return 1; }
  if [ "$APPLY" = 1 ] && [ -n "$cache" ]; then install -d -o root -g root -m 0755 "$(dirname "$cache")"; install -o root -g root -m 0644 "$out" "$cache"; fi
  log INFO 'CISA KEV feed refreshed.'
}
threat_gate() { [ -z "$CACHE_URL" ] || printf %s "$CACHE_URL"|grep -Eq '^https://' || { log FAIL 'CACHE_URL must be HTTPS; raw LAN P2P/HTTP mirrors are refused.'; return 1; }; fetch_threat_feed || log WARN 'Threat feed unavailable'; [ -z "$QUARANTINED_PACKAGES$QUARANTINED_CVES" ] || log WARN 'Explicit threat quarantine policy is active; package/CVE mapping must be change-approved.'; }
create_snapshot() {
  [ "$APPLY" = 1 ] || { log PLAN 'Would create Btrfs/ZFS/LVM snapshot before deployment.'; return 0; }; local fs source dataset vg lv snap
  fs="$(findmnt -n -o FSTYPE /)"; source="$(findmnt -n -o SOURCE /)"; case "$fs" in
    btrfs) mkdir -p "$SNAPSHOT_DIR"; btrfs subvolume show / >/dev/null && btrfs subvolume snapshot -r / "$SNAPSHOT_DIR/$RUN_ID" && SNAPSHOT_CREATED=1;;
    zfs) dataset="$(zfs list -H -o name,mountpoint 2>/dev/null|awk '$2=="/"{print $1;exit}')"; [ -n "$dataset" ] && zfs snapshot "${dataset}@${RUN_ID}" && SNAPSHOT_CREATED=1;;
    ext4|xfs) if lvs "$source" >/dev/null 2>&1; then snap="zdu_${RUN_ID//[^A-Za-z0-9_]/_}"; lvcreate -s -n "$snap" -L "$LVM_SNAPSHOT_SIZE" "$source" && SNAPSHOT_CREATED=1; fi;;
  esac
  [ "$SNAPSHOT_CREATED" = 1 ] && { log OK "Preflight $fs snapshot created."; return 0; }
  [ "$ALLOW_NO_SNAPSHOT" = 1 ] && { log WARN "No compatible snapshot; policy permits continuation."; return 0; }
  log WARN "No supported snapshot was created for root filesystem $fs. Updates cannot be automatically rolled back."
  if [ -t 0 ] && [ -t 1 ]; then
    local answer
    printf 'Continue installing updates without a snapshot? Type YES to continue: ' >&2
    if IFS= read -r answer && [ "$answer" = YES ]; then
      log WARN 'Operator approved continuing without a snapshot for this run.'
      return 0
    fi
  else
    log WARN 'No interactive terminal available; cannot request snapshot override.'
  fi
  log FAIL 'Snapshot gate failed; updates were not installed.'
  return 1
}
start_drain() { [ "$APPLY" = 1 ] || { log PLAN 'Would drain the node if a proxy adapter is configured; no proxy command runs in plan mode.'; return 0; }; [ -n "$DRAIN_COMMAND" ] || { log WARN 'No proxy adapter configured; package updates may restart services.'; return 0; }; run_hook 'proxy drain' "$DRAIN_COMMAND" 1 >/dev/null; DRAINED=1; [ -n "$ACTIVE_CONNECTIONS_COMMAND" ] || { log FAIL 'Drain requires ACTIVE_CONNECTIONS_COMMAND.'; return 1; }; local until=$(( $(date +%s)+1200 )) n; while :; do n="$(run_hook 'active connection probe' "$ACTIVE_CONNECTIONS_COMMAND" 1|tr -d '[:space:]')"; [[ "$n" =~ ^[0-9]+$ ]] || { log FAIL 'Active connection adapter must print integer only.'; return 1; }; [ "$n" -eq 0 ] && break; [ "$(date +%s)" -lt "$until" ] || { log FAIL "Drain timeout; $n inflight remain."; return 1; }; log INFO "Waiting for $n inflight request(s)."; sleep 10; done; }
rejoin_node() { [ "$DRAINED" = 0 ] && return 0; run_hook 'proxy rejoin' "$ENABLE_COMMAND" 1 >/dev/null; DRAINED=0; }
protect_debian_services() { [ "$IS_SERVER" = 1 ] || return 0; [ -e /usr/sbin/policy-rc.d ] && { cp -a /usr/sbin/policy-rc.d "$RUN_ROOT/policy-rc.d.original"; }; printf '#!/bin/sh\n# Temporary ZDU no-service-restart gate\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d; POLICY_RC_CREATED=1; }
restore_debian_services() { [ "$POLICY_RC_CREATED" = 1 ] || return 0; [ -e "$RUN_ROOT/policy-rc.d.original" ] && mv "$RUN_ROOT/policy-rc.d.original" /usr/sbin/policy-rc.d || rm -f /usr/sbin/policy-rc.d; POLICY_RC_CREATED=0; }
package_excluded() { local pkg="$1" p; [[ "$pkg" =~ ^(linux-image|linux-headers|linux-modules|linux-generic|kernel|kernel-core|kernel-modules|kernel-devel) ]] && return 0; contains_csv "$pkg" "$PACKAGE_DENYLIST" && return 0; contains_csv "$pkg" "$QUARANTINED_PACKAGES" && return 0; contains_csv "$pkg" "$PROTECTED_PACKAGES" && return 0; return 1; }
apt_update() {
  if [ "$APPLY" != 1 ]; then
    log PLAN 'Would refresh APT metadata and run a full upgrade, including kernel and service packages; dependencies may be installed or removed.'
    return 0
  fi
  log WARN 'Full upgrade includes kernels and services; services may restart and packages may be removed.'
  apt-get update || return $?
  apt-get -s full-upgrade > "$RUN_ROOT/apt-simulation.txt" || return $?
  log INFO "APT transaction preview: $RUN_ROOT/apt-simulation.txt"
  cat "$RUN_ROOT/apt-simulation.txt"
  DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confold full-upgrade
}
rpm_update() {
  local pm="$1"
  if [ "$APPLY" != 1 ]; then
    log PLAN "Would run $pm upgrade including kernel and service packages."
    return 0
  fi
  log WARN 'Full upgrade includes kernels and services; services may restart and dependencies may change.'
  "$pm" -y upgrade
}
package_update_once() { if command -v apt-get >/dev/null 2>&1; then apt_update; elif command -v dnf >/dev/null 2>&1; then rpm_update dnf; elif command -v yum >/dev/null 2>&1; then rpm_update yum; else log FAIL 'No supported package manager (apt/dnf/yum) found.'; return 1; fi; }
package_update() { if package_update_once; then :; elif [ "$ENABLE_DEPENDENCY_REPAIR" = 1 ]; then log WARN 'Approved dependency repair: attempting one native repair and one retry.'; if command -v apt-get >/dev/null; then apt-get -f install -y; elif command -v dnf >/dev/null; then dnf -y distro-sync; else yum -y distro-sync; fi; package_update_once; else log FAIL 'Package deployment failed; autonomous dependency repair is disabled.'; return 1; fi; }
controlled_deployment() { start_drain; package_update; if [ "$APPLY" = 1 ] && [ "$ALLOW_SNAP" = 1 ] && [ "$IS_SERVER" = 0 ] && command -v snap >/dev/null; then snap refresh; fi; }
listening_ports() {
  local sockets
  if ! sockets="$(ss -ltnH)"; then
    echo "Failed to collect listening TCP ports with ss" >&2
    return 1
  fi
  printf '%s\n' "$sockets" |
    awk '{a=$4; sub(/^.*:/, "", a); if (a ~ /^[0-9]+$/) print a}' |
    sort -nu
}
tcp_probe() { # listener plus active loopback connect; listener-only fallback when no client is installed
  local p="$1"
  if command -v nc >/dev/null 2>&1; then nc -z -w 3 127.0.0.1 "$p" >/dev/null 2>&1
  elif command -v timeout >/dev/null 2>&1; then timeout 3 bash -c "</dev/tcp/127.0.0.1/$p" >/dev/null 2>&1
  else log WARN 'No nc/timeout available; using listening-socket-only smoke validation.'; return 0; fi
}
health_check() { local ports="$REQUIRED_PORTS" p missing="" observed=""; if [ -z "$ports" ]; then IFS=',' read -r -a _observe <<< "$OBSERVE_PORTS"; for p in "${_observe[@]}"; do printf '%s\n' "$BEFORE_PORTS"|grep -qx "$p" && observed="${observed}${observed:+,}$p"; done; ports="$observed"; fi; IFS=',' read -r -a _ports <<< "$ports"; for p in "${_ports[@]}"; do [ -z "$p" ] && continue; if ! listening_ports|grep -qx "$p" || ! tcp_probe "$p"; then missing="${missing}${missing:+,}$p"; fi; done; log INFO "Port smoke test: required=[${ports:-none}], missing=[${missing:-none}]"; [ -z "$missing" ] || { log FAIL "Health gate: no TCP acceptance on $missing"; return 1; }; }
error_count() { journalctl --no-pager -p err --since '5 minutes ago' 2>/dev/null|wc -l|tr -d ' '; }
log_anomaly_gate() { local after; after="$(error_count)"; if [ "$after" -ge "$MIN_NEW_ERRORS" ] && awk -v a="$after" -v b="$BASELINE_ERRORS" -v p="$ERROR_RATE_PERCENT" 'BEGIN{exit !(a>b*(1+p/100))}'; then log FAIL "Journal anomaly: $after errors vs baseline $BASELINE_ERRORS."; return 1; fi; log INFO "Journal health: baseline=$BASELINE_ERRORS current=$after"; }
forensic_bundle() { local why="$1" dir="$RUN_ROOT/evidence" archive="$RUN_ROOT/forensic-${RUN_ID}.tar.gz"; mkdir -p "$dir"; chmod 700 "$dir"; printf '%s\n' "$why" > "$dir/reason.txt"; ps -eo pid,ppid,%cpu,%mem,rss,cmd > "$dir/processes.txt"; ss -ltnp > "$dir/sockets.txt" 2>/dev/null||true; cat /proc/meminfo > "$dir/meminfo.txt"; cp "$LOG_PATH" "$dir/" 2>/dev/null||true; cp "$RUN_ROOT"/sbom-*.json "$dir/" 2>/dev/null||true; tar -czf "$archive" -C "$RUN_ROOT" evidence; if [ -n "$FORENSIC_RECIPIENT_CERT" ] && [ -r "$FORENSIC_RECIPIENT_CERT" ]; then openssl cms -encrypt -binary -aes-256-cbc -in "$archive" -out "${archive}.p7m" -outform DER "$FORENSIC_RECIPIENT_CERT" && rm -f "$archive" && log OK 'CMS-encrypted forensic bundle created.' || log WARN 'Forensic encryption failed; archive ACL is restricted.'; else log WARN 'Forensic archive is unencrypted: configure FORENSIC_RECIPIENT_CERT.'; fi; }
emergency_response() { local why="$1"; log FAIL "Emergency response: $why"; restore_debian_services || true; forensic_bundle "$why"; [ -n "$ROLLBACK_COMMAND" ] && run_hook 'approved rollback' "$ROLLBACK_COMMAND" 1 >/dev/null || log WARN 'Node remains drained/quarantined. Root snapshots cannot be reverted online; configure a tested ROLLBACK_COMMAND.'; }
on_error() { local rc="$?" line="$1" cmd="$2"; [ "$IN_FAILURE" = 1 ] && exit "$rc"; IN_FAILURE=1; trap - ERR; if [ "$EMERGENCY_ARMED" != 1 ]; then log FAIL "Pre-deployment failure at line $line: $cmd (no node mutation; no rollback required)."; send_webhook failure "Pre-deployment failure at line $line"; exit "$rc"; fi; emergency_response "Unexpected failure at line $line: $cmd" || true; send_webhook failure "Unexpected failure at line $line"; exit "$rc"; }
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR
kernel_lt() { # true only when the running version sorts before the policy minimum
  local low; low="$(printf '%s\n%s\n' "$1" "$2"|sort -V|head -1)"; [ "$low" = "$1" ] && [ "$1" != "$2" ]
}
compliance_gate() {
  [ "$COMPLIANCE_REQUIRED" = 1 ] || return 0
  [ -n "$MIN_KERNEL_VERSION" ] || { log FAIL 'Compliance requires MIN_KERNEL_VERSION.'; return 1; }
  if kernel_lt "$(uname -r)" "$MIN_KERNEL_VERSION"; then
    log FAIL "Non-compliant kernel $(uname -r) is below $MIN_KERNEL_VERSION."
    if [ "$APPLY" = 1 ]; then
      [ -n "$NETWORK_QUARANTINE_COMMAND" ] || { log FAIL 'No NAC adapter configured.'; return 1; }
      run_hook 'NAC quarantine' "$NETWORK_QUARANTINE_COMMAND" 1 >/dev/null || return 1
    fi
    return 1
  fi
  return 0
}
local_main() { load_config; require_apply_privilege; get_environment; compliance_gate; resource_gate; process_fence; BASELINE_ERRORS="$(error_count)"; BEFORE_PORTS="$(listening_ports)"; log STEP '[1/9] Threat/SBOM preflight'; threat_gate; create_sbom pre; log STEP '[2/9] Snapshot gate'; create_snapshot; log STEP '[3/9] DBA transaction gate'; database_guard; log STEP '[4/9] Full package upgrade'; [ "$APPLY" = 1 ] && EMERGENCY_ARMED=1; controlled_deployment; log STEP '[5/9] Postflight SBOM'; create_sbom post; post_sbom_gate; log STEP '[6/9] TCP smoke tests'; health_check; log STEP '[7/9] Journal anomaly scan'; log_anomaly_gate; log STEP '[8/9] Hot-swap rejoin'; rejoin_node; log STEP '[9/9] Reboot status'; [ -e /var/run/reboot-required ] && log WARN 'Reboot-required marker present; reboot is deferred, never invoked.' || log OK 'Success. No reboot was invoked.'; send_webhook success 'Completed without invoking a reboot.'; }
expand_cidr() { perl -MSocket -e 'my($ip,$bits)=split m!/!,shift;die "CIDR /16-/32 only\n" if $bits<16||$bits>32;my$n=unpack("N",inet_aton($ip));my$c=2**(32-$bits);die "CIDR >4096 hosts\n" if$c>4096;my$m=(0xffffffff<<(32-$bits))&0xffffffff;for my$i(1..$c-2){print inet_ntoa(pack("N",($n&$m)+$i)),"\n"}' "$1"; }
cluster_capacity_gate() { [ -z "$CLUSTER_CAPACITY_COMMAND" ] && return 0; local n; n="$(run_hook 'cluster HA capacity' "$CLUSTER_CAPACITY_COMMAND" 1|tr -d '[:space:]')"; [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge "$MIN_HEALTHY_NODES" ] || { log FAIL "HA capacity gate: healthy=$n minimum=$MIN_HEALTHY_NODES"; return 1; }; }
remote_worker() { # validated hostname/IP; target needs sudo NOPASSWD for cluster operation
  local h="$1" safe_id remote_cfg="" args="--mode local" rc=0
  is_valid_target "$h" || { log FAIL "Rejected invalid SSH target: $h"; return 64; }
  safe_id="${RUN_ID//[^A-Za-z0-9_.-]/_}"
  if [ -f "$CONFIG" ]; then
    remote_cfg="$REMOTE_RUNTIME_DIR/${safe_id}.conf"
    # Stream policy over the authenticated SSH channel into a root-only runtime directory.
    # This eliminates /tmp TOCTOU and target-user write access before privileged parsing.
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
  load_config; [ "$APPLY" = 0 ] || [ -n "$CLUSTER_CAPACITY_COMMAND" ] || { log FAIL 'Apply-mode cluster rollout requires CLUSTER_CAPACITY_COMMAND to enforce minimum HA capacity.'; return 1; }
  local -a targets=() remaining=() batch=(); local h found=0
  [ -z "$HOST_FILE" ] || { [ -f "$HOST_FILE" ] || { log FAIL "Host file not found: $HOST_FILE"; return 1; }; while IFS= read -r h; do h="$(trim_space "${h%%#*}")"; [ -z "$h" ] && continue; is_valid_target "$h" || { log FAIL "Invalid host-file target: $h"; return 64; }; targets+=("$h"); done < "$HOST_FILE"; }
  [ -z "$CIDR" ] || while IFS= read -r h; do is_valid_target "$h" || { log FAIL "Invalid CIDR-expanded target: $h"; return 64; }; targets+=("$h"); done < <(expand_cidr "$CIDR")
  [ "${#targets[@]}" -ge 2 ] || { log FAIL 'Cluster needs two or more targets.'; return 1; }
  [ -n "$CANARY" ] || CANARY="$CANARY_HOST"; [ -n "$CANARY" ] || { log FAIL 'A manually designated non-critical --canary is mandatory.'; return 1; }; is_valid_target "$CANARY" || { log FAIL 'Invalid canary target.'; return 64; }
  for h in "${targets[@]}"; do [ "$h" = "$CANARY" ] && found=1; done; [ "$found" = 1 ] || { log FAIL 'Canary not in target list.'; return 1; }
  log STEP "Canary deployment: $CANARY (exactly one host)"; cluster_capacity_gate; run_batch "$CANARY" || { log FAIL 'Canary failed: rollout aborted.'; return 1; }
  log INFO "Canary passed; observing for ${CANARY_WAIT}s."; sleep "$CANARY_WAIT"
  for h in "${targets[@]}"; do [ "$h" = "$CANARY" ] || remaining+=("$h"); done
  for h in "${remaining[@]}"; do batch+=("$h"); if [ "${#batch[@]}" -ge "$BATCH_SIZE" ]; then cluster_capacity_gate; log STEP "Rolling batch: ${batch[*]}"; run_batch "${batch[@]}" || { log FAIL 'Batch failed; remaining nodes untouched.'; return 1; }; batch=(); fi; done
  [ "${#batch[@]}" -eq 0 ] || { cluster_capacity_gate; log STEP "Rolling batch: ${batch[*]}"; run_batch "${batch[@]}" || return 1; }
  log OK 'Cluster rollout complete.'; send_webhook success 'Linux cluster rollout complete.'
}
if [ "$MODE" = local ]; then local_main; else cluster_main; fi
