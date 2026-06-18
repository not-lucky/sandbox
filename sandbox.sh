#!/usr/bin/env bash
# ==============================================================================
# UNIFIED IDENTITY-BASED SECURE WORKSPACE MANAGER (ARCH SAFE)
# ==============================================================================
# Engineered for AI Agents & IDEs (Cursor, Trae, QoderCLI).
# Provides complete network isolation, persistent hardware spoofing (MAC/UUID),
# and dedicated identity state folders to prevent account cross-contamination.
#
# Each identity gets:
#   - A Linux network namespace with a spoofed MAC address and machine-id
#   - Traffic routed through tun2socks -> host SOCKS5 proxy for IP isolation
#   - A Firejail sandbox with a private home dir, blocking hardware telemetry
#   - Persistent state across restarts (logins, configs, caches survive)
# ==============================================================================

set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true

# Bash 4.4+ required for printf %T (epoch-based date formatting without forking date(1))
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4))); then
  printf '[FATAL] Bash 4.4+ required (have %s)\n' "$BASH_VERSION" >&2
  exit 1
fi

# --- Constants ---
readonly SCRIPT_VERSION="1.0.0"
# shellcheck disable=SC2155
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"

# Exit codes: distinct values let callers programmatically identify failure modes
readonly EXIT_OK=0
readonly EXIT_GENERAL=1
readonly EXIT_USAGE=2
readonly EXIT_MISSING_DEPS=3
readonly EXIT_PERMISSION=4
readonly EXIT_NETWORK=5
readonly EXIT_PORT_CONFLICT=6
readonly EXIT_LOCK_CONFLICT=7

# Tunable constants
readonly MAX_SYNC_ATTEMPTS=50
readonly SYNC_POLL_INTERVAL="0.1"
readonly TUN2SOCKS_KILL_WAIT=5
readonly DEFAULT_SOCKS_PORT=10808
readonly DEFAULT_DNS_SERVER="1.1.1.1"
readonly MAX_IDENTITY_LEN=64
readonly STALE_TEMP_DAYS=1
readonly SEPARATOR="--------------------------------------------------------"

# Network configuration constants
readonly PROXY_NETWORK_BASE="10.250"
readonly PROXY_NETMASK="24"
readonly IDENTITY_HASH_LENGTH=6
readonly DNS_PORT=53
readonly DNS_TIMEOUT=4

# Process management constants
readonly SIGTERM_WAIT=0.5
readonly SIGKILL_WAIT=0.5

# Global State (set during execution, consumed by cleanup trap)
IDENTITY=""
TUN_PID=""
SOCAT_PID=""
DNS_PID=""
PROFILE_PATH=""
DNS_PROXY_PY=""
NS_NAME=""
VETH_HOST=""
NS_CREATED=false
VETH_CREATED=false
LOCK_FD=""
COMMAND_ARGS=()

# Command cache for performance optimization
declare -A CMD_CACHE=()

# Identity hash cache to avoid repeated md5sum calculations
declare -A HASH_CACHE=()

# Global Flags
VERBOSE_ENABLED=false
TRACE_ENABLED=false
DRY_RUN=false
FORCE=false
DNS_SERVER="$DEFAULT_DNS_SERVER"
TIMEOUT=0
NO_SANDBOX=false
CONFIG_FILE=""
SHOW_CONFIG=false
CLEANUP_ONLY=false

# Progress indicator state
PROGRESS_ENABLED=false
PROGRESS_PID=""

# Audit logging
AUDIT_ENABLED=false
AUDIT_FILE=""

# Identity export/import
EXPORT_TARGET=""
IMPORT_TARGET=""
CLONE_TARGET=""

# Logging levels
declare -r LOG_LEVEL_DEBUG=0
declare -r LOG_LEVEL_INFO=1
declare -r LOG_LEVEL_WARN=2
declare -r LOG_LEVEL_ERROR=3
CURRENT_LOG_LEVEL=$LOG_LEVEL_INFO

# --- Color Setup ---
# Only emit ANSI color codes when stdout is a terminal. Pipes, redirects, and
# CI loggers get plain text to avoid garbled escape sequences in output.
setup_colors() {
  if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    CLR_RESET=$'\033[0m'
    CLR_INFO=$'\033[32m'
    CLR_WARN=$'\033[33m'
    CLR_ERROR=$'\033[31m'
    CLR_DEBUG=$'\033[36m'
  else
    CLR_RESET="" CLR_INFO="" CLR_WARN="" CLR_ERROR="" CLR_DEBUG=""
  fi
}
setup_colors

# --- Config File Loading ---
load_config_file() {
  local config_path=""

  # Check XDG_CONFIG_HOME first, then ~/.sandboxrc
  if [[ -n "${XDG_CONFIG_HOME:-}" ]] && [[ -f "$XDG_CONFIG_HOME/sandbox/config" ]]; then
    config_path="$XDG_CONFIG_HOME/sandbox/config"
  elif [[ -f "$HOME/.sandboxrc" ]]; then
    config_path="$HOME/.sandboxrc"
  fi

  if [[ -n "$config_path" ]]; then
    verbose "Loading config from: $config_path"
    check_file_permission "$config_path" "read"
    CONFIG_FILE="$config_path"

    # Read config file line by line, skipping comments and empty lines
    while IFS='=' read -r key value; do
      # Skip comments and empty lines
      [[ "$key" =~ ^[[:space:]]*# ]] && continue
      [[ -z "$key" ]] && continue

      # Trim whitespace
      key="${key// /}"
      value="${value// /}"

      # Apply config values that match our global flags
      case "$key" in
        default_identity)
          # Only set if not already specified via command line
          [[ -z "${IDENTITY:-}" ]] && IDENTITY="$value"
          ;;
        default_dns)
          # Only set if not already specified via command line
          [[ "$DNS_SERVER" == "$DEFAULT_DNS_SERVER" ]] && DNS_SERVER="$value"
          ;;
        default_socks_port)
          # Only set if not already specified via command line
          [[ "$SOCKS_PORT" == "$DEFAULT_SOCKS_PORT" ]] && SOCKS_PORT="$value"
          ;;
        default_timeout)
          # Only set if not already specified via command line
          [[ "$TIMEOUT" == 0 ]] && TIMEOUT="$value"
          ;;
        verbose)
          [[ "$value" == "true" ]] && VERBOSE_ENABLED=true
          ;;
        no_sandbox)
          [[ "$value" == "true" ]] && NO_SANDBOX=true
          ;;
        *)
          verbose "Unknown config key: $key"
          ;;
      esac
    done < "$config_path"
  fi
}

# --- Structured Logging ---
# printf %T avoids forking date(1) on every log call (significant in tight loops)
log() {
  ((CURRENT_LOG_LEVEL <= LOG_LEVEL_INFO)) || return 0
  printf '%s[%(%Y-%m-%d %H:%M:%S)T] %s%s\n' "$CLR_INFO" -1 "$*" "$CLR_RESET"
}
warn() {
  ((CURRENT_LOG_LEVEL <= LOG_LEVEL_WARN)) || return 0
  printf '%s[%(%Y-%m-%d %H:%M:%S)T] WARN: %s%s\n' "$CLR_WARN" -1 "$*" "$CLR_RESET" >&2
}
error() {
  local message="$1"
  local exit_code="${2:-$EXIT_GENERAL}"
  local suggestion="${3:-}"

  ((CURRENT_LOG_LEVEL <= LOG_LEVEL_ERROR)) || return 0
  printf '%s[%(%Y-%m-%d %H:%M:%S)T] ERROR: %s%s\n' "$CLR_ERROR" -1 "$message" "$CLR_RESET" >&2
  if [[ -n "$suggestion" ]]; then
    printf '%s[%(%Y-%m-%d %H:%M:%S)T] SUGGESTION: %s%s\n' "$CLR_INFO" -1 "$suggestion" "$CLR_RESET" >&2
  fi
  exit "$exit_code"
}
verbose() {
  ((CURRENT_LOG_LEVEL <= LOG_LEVEL_DEBUG)) || return 0
  printf '%s[%(%Y-%m-%d %H:%M:%S)T] DEBUG: %s%s\n' "$CLR_DEBUG" -1 "$*" "$CLR_RESET"
}

# --- Audit Logging ---
init_audit_log() {
  [[ "$AUDIT_ENABLED" == true ]] || return 0

  local audit_dir
  if [[ -n "${XDG_STATE_HOME:-}" ]]; then
    audit_dir="$XDG_STATE_HOME/sandbox"
  else
    audit_dir="$HOME/.local/state/sandbox"
  fi

  mkdir -p -- "$audit_dir"
  AUDIT_FILE="$audit_dir/audit.log"

  # Set restrictive permissions on audit log
  touch -- "$AUDIT_FILE"
  chmod 600 -- "$AUDIT_FILE"
}

audit_log() {
  [[ "$AUDIT_ENABLED" == true ]] || return 0
  [[ -n "$AUDIT_FILE" ]] || return 0

  local timestamp
  printf -v timestamp '%(%Y-%m-%d %H:%M:%S)T' -1

  printf '[%s] [%s] %s\n' "$timestamp" "$REAL_USER" "$*" >> "$AUDIT_FILE"
}
start_progress() {
  [[ "$PROGRESS_ENABLED" == true ]] || return 0
  local message="$1"
  printf '%s... ' "$message"
  # Start a background spinner
  (
    while true; do
      printf '.'
      sleep 0.5
    done
  ) &
  PROGRESS_PID=$!
}

stop_progress() {
  [[ "$PROGRESS_ENABLED" == true ]] || return 0
  [[ -n "${PROGRESS_PID:-}" ]] || return 0
  kill "$PROGRESS_PID" 2>/dev/null || true
  wait "$PROGRESS_PID" 2>/dev/null || true
  PROGRESS_PID=""
  printf ' done\n'
}

# --- Signal Handling ---
on_error() {
  local line="$1" exit_code="$2"
  ((exit_code != 0)) || return 0
  printf '%s[%(%Y-%m-%d %H:%M:%S)T] FATAL: script failed at line %d (exit %d)%s\n' \
    "$CLR_ERROR" -1 "$line" "$exit_code" "$CLR_RESET" >&2
}

# Cleanup trap for signals - ensures proper cleanup on termination
cleanup_on_signal() {
  local signal="$1"
  verbose "Received signal $signal, initiating cleanup..."
  cleanup
  exit 128
}

trap 'on_error "$LINENO" "$?"' ERR
trap 'cleanup_on_signal "TERM"' TERM
trap 'cleanup_on_signal "INT"' INT
trap 'cleanup_on_signal "PIPE"' PIPE

# --- Utility Functions ---

# Check if a command exists, with caching to avoid repeated lookups.
# Returns 0 if command exists, 1 otherwise.
has_command() {
  local cmd="$1"
  if [[ -n "${CMD_CACHE[$cmd]:-}" ]]; then
    [[ "${CMD_CACHE[$cmd]}" == "1" ]]
  else
    if command -v "$cmd" >/dev/null 2>&1; then
      CMD_CACHE[$cmd]="1"
      return 0
    else
      CMD_CACHE[$cmd]="0"
      return 1
    fi
  fi
}

# Check file permissions before operations
check_file_permission() {
  local file="$1" permission="$2"
  case "$permission" in
    read)
      [[ -r "$file" ]] || error "File not readable: $file" "$EXIT_PERMISSION"
      ;;
    write)
      [[ -w "$file" ]] || error "File not writable: $file" "$EXIT_PERMISSION"
      ;;
    execute)
      [[ -x "$file" ]] || error "File not executable: $file" "$EXIT_PERMISSION"
      ;;
    *)
      error "Invalid permission check: $permission" "$EXIT_GENERAL"
      ;;
  esac
}

# Check directory permissions and existence
check_directory() {
  local dir="$1" permission="${2:-read}"
  [[ -d "$dir" ]] || error "Directory does not exist: $dir" "$EXIT_PERMISSION"
  check_file_permission "$dir" "$permission"
}

# Check if a PID belongs to a sandbox-related process. Falls back to kill -0
# when /proc is unavailable (rare on Linux, but defensive).
is_sandbox_pid() {
  local pid="$1"
  kill -0 "$pid" 2>/dev/null || return 1
  [[ -r "/proc/$pid/cmdline" ]] || return 0
  grep -qZlE 'firejail|sandbox' "/proc/$pid/cmdline" 2>/dev/null
}

kill_if_set() {
  local pid="${1:-}" use_sudo="${2:-false}"
  [[ -n "$pid" ]] || return 0
  if [[ "$use_sudo" == true ]]; then
    sudo kill -- "$pid" 2>/dev/null || true
  else
    kill -- "$pid" 2>/dev/null || true
  fi
}

wait_if_set() {
  local pid="${1:-}"
  [[ -n "$pid" ]] || return 0
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  local had_state=false
  if [[ "$NS_CREATED" == true ]] || [[ "$VETH_CREATED" == true ]] ||
    [[ -n "${TUN_PID:-}" ]] || [[ -n "${PROFILE_PATH:-}" ]]; then
    had_state=true
    if [[ -n "${IDENTITY:-}" ]]; then
      log "Saving state and cleaning up identity [$IDENTITY]..."
    else
      log "Saving state and cleaning up sandbox resources..."
    fi
  fi

  # Kill proxies before tearing down the namespace they live in
  kill_if_set "${TUN_PID:-}" true
  kill_if_set "${SOCAT_PID:-}"
  kill_if_set "${DNS_PID:-}" true
  wait_if_set "${TUN_PID:-}"
  wait_if_set "${SOCAT_PID:-}"
  wait_if_set "${DNS_PID:-}"

  # Namespace deletion implicitly removes all interfaces inside it
  if [[ "$NS_CREATED" == true ]] && [[ -n "${NS_NAME:-}" ]]; then
    sudo ip netns delete "$NS_NAME" 2>/dev/null || true
  fi
  # Host-side veth is not inside the namespace, so delete it separately
  if [[ "$VETH_CREATED" == true ]] && [[ -n "${VETH_HOST:-}" ]]; then
    sudo ip link delete "$VETH_HOST" 2>/dev/null || true
  fi

  [[ -n "${PROFILE_PATH:-}" ]] && rm -f -- "$PROFILE_PATH"
  [[ -n "${DNS_PROXY_PY:-}" ]] && rm -f -- "$DNS_PROXY_PY"

  # Release the flock so another instance can acquire it
  if [[ -n "${LOCK_FD:-}" ]]; then
    flock -u "$LOCK_FD" 2>/dev/null || true
  fi

  if [[ "$had_state" == true ]]; then
    log "Cleanup complete."
  fi
}

# Remove orphaned temp files (DNS proxy scripts, firejail profiles) left behind
# by crashes. Only runs if the last cleanup was more than STALE_CHECK_INTERVAL
# seconds ago, to avoid forking find(1) on every invocation.
STALE_CHECK_INTERVAL=3600
cleanup_stale_temps() {
  local config_dir="$1"
  [[ -d "$config_dir" ]] || return 0

  local stamp_file="$config_dir/.last_stale_cleanup"
  if [[ -f "$stamp_file" ]]; then
    local now last age
    printf -v now '%(%s)T' -1
    last="$(stat -c %Y -- "$stamp_file" 2>/dev/null || echo 0)"
    age=$((now - last))
    if ((age < STALE_CHECK_INTERVAL)); then
      return 0
    fi
  fi

  find "$config_dir" -maxdepth 1 -type f \( -name 'dns_proxy_*.py' -o -name 'sandbox_*.profile' \) \
    -mtime +"$STALE_TEMP_DAYS" -delete 2>/dev/null || true
  touch -- "$stamp_file"
}

# Detect orphaned resources from a previous crash: a PID file pointing to a dead
# process, or a network namespace that outlived its sandbox. Cleans them up so
# a new launch doesn't fail with stale-state conflicts.
recover_stale_instance() {
  local identity_dir="$1" name="$2"
  local pid_file="$identity_dir/.sandbox.pid"

  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(<"$pid_file")"
    if ! is_sandbox_pid "$pid"; then
      warn "Found stale PID file (PID $pid is dead or not a sandbox). Removing."
      rm -f -- "$pid_file"
    fi
  fi

  local ns_name
  ns_name="ns-$(_identity_hash "$name")"
  if ip netns list 2>/dev/null | grep -q "^${ns_name}[[:space:]]"; then
    warn "Found lingering namespace '$ns_name' from a previous run. Cleaning up."
    local pids
    mapfile -t pids < <(sudo ip netns pids "$ns_name" 2>/dev/null || true)
    if [[ ${#pids[@]} -gt 0 ]]; then
      sudo kill -TERM "${pids[@]}" 2>/dev/null || true
      sleep "$SIGTERM_WAIT"
      sudo kill -KILL "${pids[@]}" 2>/dev/null || true
    fi
    sudo ip netns delete "$ns_name" 2>/dev/null || true

    local veth_host
    veth_host="vh-$(_identity_hash "$name")"
    sudo ip link delete "$veth_host" 2>/dev/null || true
  fi
}

suggest_install_command() {
  local missing_deps=("$@")
  local pkgs=()
  for dep in "${missing_deps[@]}"; do
    case "$dep" in
    ip) pkgs+=("iproute2") ;;
    *) pkgs+=("$dep") ;;
    esac
  done

  # Use associative array for package manager detection (cached via has_command)
  declare -A pkg_managers=(
    [apt-get]="sudo apt-get update && sudo apt-get install -y ${pkgs[*]}"
    [dnf]="sudo dnf install -y ${pkgs[*]}"
    [pacman]="sudo pacman -S --noconfirm ${pkgs[*]}"
    [yay]="yay -S --noconfirm ${pkgs[*]}"
    [paru]="paru -S --noconfirm ${pkgs[*]}"
    [zypper]="sudo zypper install -y ${pkgs[*]}"
    [apk]="sudo apk add ${pkgs[*]}"
  )

  local pm_found=false
  for pm in "${!pkg_managers[@]}"; do
    if has_command "$pm"; then
      log "To install: ${pkg_managers[$pm]}"
      pm_found=true
      break
    fi
  done

  [[ "$pm_found" == true ]] || log "Please install: ${pkgs[*]}"
}

# Mount a host path into the firejail sandbox. Also creates a symlink inside the
# fake home so relative paths from the sandboxed app still resolve correctly.
add_whitelist_mount() {
  local host_path="$1"
  [[ -e "$host_path" ]] || return 0

  WHITELIST_ARGS+=("--whitelist=$host_path")

  if [[ "$host_path" == "$REAL_HOME"* ]]; then
    local rel_path="${host_path#"$REAL_HOME"/}"
    local fake_path="$HOME_DIR/$rel_path"

    # Only symlink if the target is a sub-path of the fake home (not home itself)
    if [[ "$fake_path" != "$HOME_DIR" ]]; then
      mkdir -p -- "$(dirname -- "$fake_path")"
      ln -sfn -- "$host_path" "$fake_path"
    fi
  fi
}

# --- Identity Management ---

# Returns the first N hex chars of the identity's md5 hash.
# Centralizes hashing so we never compute the same hash twice.
# Uses cache to avoid repeated md5sum calls for the same identity.
_identity_hash() {
  local name="$1" len="${2:-$IDENTITY_HASH_LENGTH}"
  local cache_key="${name}:${len}"

  if [[ -n "${HASH_CACHE[$cache_key]:-}" ]]; then
    printf '%s' "${HASH_CACHE[$cache_key]}"
  else
    local hash
    hash="$(printf '%s' "$name" | md5sum | cut -c1-"$len")"
    HASH_CACHE[$cache_key]="$hash"
    printf '%s' "$hash"
  fi
}

list_identities() {
  local identity_root="$REAL_HOME/.sandbox_identities"
  if [[ ! -d "$identity_root" ]]; then
    log "No identities found. Directory does not exist: $identity_root"
    return 0
  fi

  local found=false
  for dir in "$identity_root"/*/; do
    [[ -d "$dir" ]] || continue
    local name size
    name="$(basename -- "$dir")"
    # du is expensive for large state dirs; only compute when --verbose is set
    if [[ "$VERBOSE_ENABLED" == true ]] && [[ -d "$dir/home" ]]; then
      size="$(du -sh -- "$dir/home" 2>/dev/null | cut -f1)"
    else
      size="N/A"
    fi
    log "  $name  (state: $size, path: $dir)"
    found=true
  done

  [[ "$found" == true ]] || log "No identities found in $identity_root"
}

delete_identity() {
  local name="$1"
  audit_log "Identity deletion requested: $name"
  local sanitized="${name//[!a-zA-Z0-9_-]/}"

  if [[ "$sanitized" != "$name" ]]; then
    warn "Identity name sanitized: '$name' -> '$sanitized'"
  fi
  [[ -n "$sanitized" ]] || error "Invalid identity name for deletion."

  local identity_dir="$REAL_HOME/.sandbox_identities/$sanitized"
  [[ -d "$identity_dir" ]] || error "Identity '$sanitized' does not exist at $identity_dir"

  # --force skips the confirmation prompt (useful in scripts and CI)
  if [[ "$FORCE" != true ]]; then
    local confirm
    read -r -p "Permanently delete identity '$sanitized' and all its state? [y/N] " confirm
    if [[ "$confirm" != [yY] ]]; then
      log "Deletion cancelled."
      return 0
    fi
  fi

  log "Deleting identity '$sanitized' and all associated state..."
  log "  Path: $identity_dir"
  rm -rf -- "$identity_dir"
  log "Identity '$sanitized' deleted successfully."
  audit_log "Identity deleted successfully: $sanitized"
}

export_identity() {
  local name="$1"
  local sanitized="${name//[!a-zA-Z0-9_-]/}"
  audit_log "Identity export requested: $sanitized"

  if [[ "$sanitized" != "$name" ]]; then
    warn "Identity name sanitized: '$name' -> '$sanitized'"
  fi
  [[ -n "$sanitized" ]] || error "Invalid identity name for export."

  local identity_dir="$REAL_HOME/.sandbox_identities/$sanitized"
  [[ -d "$identity_dir" ]] || error "Identity '$sanitized' does not exist at $identity_dir"

  local output_file="${EXPORT_TARGET:-${sanitized}-identity.tar.gz}"

  log "Exporting identity '$sanitized' to $output_file..."
  start_progress "Creating identity archive"

  # Create tar archive with identity state
  tar -czf "$output_file" -C "$REAL_HOME/.sandbox_identities" "$sanitized" 2>/dev/null
  local exit_code=$?

  stop_progress

  if ((exit_code != 0)); then
    error "Failed to export identity '$sanitized'." "$EXIT_GENERAL"
  fi

  log "Identity '$sanitized' exported successfully to $output_file"
  audit_log "Identity exported successfully: $sanitized -> $output_file"
}

import_identity() {
  local archive_file="$1"
  local new_name="${2:-}"
  audit_log "Identity import requested: $archive_file -> $new_name"

  [[ -f "$archive_file" ]] || error "Archive file does not exist: $archive_file" "$EXIT_USAGE"

  # Extract the original identity name from the archive
  local original_name
  original_name="$(tar -tzf "$archive_file" 2>/dev/null | head -1 | cut -d'/' -f1)"
  [[ -n "$original_name" ]] || error "Failed to read archive or archive is invalid." "$EXIT_USAGE"

  # Use provided name or original name
  local target_name="${new_name:-$original_name}"
  target_name="${target_name//[!a-zA-Z0-9_-]/}"
  [[ -n "$target_name" ]] || error "Invalid target identity name."

  local target_dir="$REAL_HOME/.sandbox_identities/$target_name"
  if [[ -d "$target_dir" ]]; then
    error "Target identity '$target_name' already exists." "$EXIT_USAGE" "Use --delete to remove the existing identity first, or choose a different name."
  fi

  log "Importing identity from $archive_file as '$target_name'..."
  start_progress "Extracting identity archive"

  # Create target directory and extract archive
  mkdir -p -- "$(dirname -- "$target_dir")"

  # Extract to temporary location first, then rename if needed
  local temp_dir="$REAL_HOME/.sandbox_identities/.import_temp"
  rm -rf -- "$temp_dir" 2>/dev/null || true
  mkdir -p -- "$temp_dir"

  tar -xzf "$archive_file" -C "$temp_dir" 2>/dev/null
  local exit_code=$?

  if ((exit_code != 0)); then
    rm -rf -- "$temp_dir"
    stop_progress
    error "Failed to extract archive file." "$EXIT_GENERAL"
  fi

  # Rename if target name differs from original
  if [[ "$target_name" != "$original_name" ]]; then
    mv -- "$temp_dir/$original_name" "$temp_dir/$target_name"
  fi

  # Move to final location
  mv -- "$temp_dir/$target_name" "$target_dir"
  rm -rf -- "$temp_dir"

  stop_progress

  log "Identity imported successfully as '$target_name'"
  audit_log "Identity imported successfully: $archive_file -> $target_name"
}

clone_identity() {
  local source_name="$1"
  local target_name="$2"
  audit_log "Identity clone requested: $source_name -> $target_name"

  local source_sanitized="${source_name//[!a-zA-Z0-9_-]/}"
  local target_sanitized="${target_name//[!a-zA-Z0-9_-]/}"

  [[ -n "$source_sanitized" ]] || error "Invalid source identity name."
  [[ -n "$target_sanitized" ]] || error "Invalid target identity name."

  local source_dir="$REAL_HOME/.sandbox_identities/$source_sanitized"
  local target_dir="$REAL_HOME/.sandbox_identities/$target_sanitized"

  [[ -d "$source_dir" ]] || error "Source identity '$source_sanitized' does not exist."
  [[ ! -d "$target_dir" ]] || error "Target identity '$target_sanitized' already exists."

  log "Cloning identity '$source_sanitized' to '$target_sanitized'..."
  start_progress "Cloning identity"

  # Copy identity directory
  cp -r -- "$source_dir" "$target_dir"
  local exit_code=$?

  stop_progress

  if ((exit_code != 0)); then
    error "Failed to clone identity." "$EXIT_GENERAL"
  fi

  # Remove any stale PID file from the clone
  rm -f -- "$target_dir/.sandbox.pid"

  log "Identity cloned successfully from '$source_sanitized' to '$target_sanitized'"
  audit_log "Identity cloned successfully: $source_sanitized -> $target_sanitized"
}

show_status() {
  local identity_root="$REAL_HOME/.sandbox_identities"
  if [[ ! -d "$identity_root" ]]; then
    log "No identities found."
    return 0
  fi

  local found=false
  for dir in "$identity_root"/*/; do
    [[ -d "$dir" ]] || continue
    local name ns_name pid_file pid status="stopped"
    name="$(basename -- "$dir")"
    # Namespace name is derived from the identity hash (must match generate_hardware_ids)
    ns_name="ns-$(_identity_hash "$name")"

    if ip netns list 2>/dev/null | grep -q "^${ns_name}[[:space:]]"; then
      pid_file="$dir/.sandbox.pid"
      if [[ -f "$pid_file" ]]; then
        pid="$(<"$pid_file")"
        if is_sandbox_pid "$pid"; then
          status="running (PID: $pid)"

          # Get resource usage if running
          if has_command ps; then
            local cpu mem
            cpu="$(ps -p "$pid" -o %cpu --no-headers 2>/dev/null | xargs || echo "N/A")"
            mem="$(ps -p "$pid" -o %mem --no-headers 2>/dev/null | xargs || echo "N/A")"
            status+="  CPU: ${cpu}%  MEM: ${mem}%"
          fi

          # Get network activity if verbose
          if [[ "$VERBOSE_ENABLED" == true ]] && has_command ip; then
            local veth_host
            veth_host="vh-$(_identity_hash "$name" 6)"
            local rx_tx
            rx_tx="$(ip -s link show "$veth_host" 2>/dev/null | awk '/RX:/ {rx=$2} /TX:/ {tx=$2} END {print "RX: "rx" KB, TX: "tx" KB"}')" || rx_tx="N/A"
            status+="  $rx_tx"
          fi
        else
          # Namespace exists but PID is dead or belongs to a different process
          status="namespace active (stale PID)"
        fi
      else
        status="namespace active"
      fi
    fi

    log "  $name  [$status]  ns=$ns_name"
    found=true
  done

  [[ "$found" == true ]] || log "No identities found in $identity_root"
}

stop_identity() {
  local name="$1"
  audit_log "Identity stop requested: $name"
  name="${name//[!a-zA-Z0-9_-]/}"
  [[ -n "$name" ]] || error "Invalid identity name."

  local identity_dir="$REAL_HOME/.sandbox_identities/$name"
  local pid_file="$identity_dir/.sandbox.pid"
  [[ -f "$pid_file" ]] || error "No running sandbox found for identity '$name'."

  local pid
  pid="$(<"$pid_file")"

  # Verify the PID is actually our sandbox before killing. Without this check,
  # a recycled PID (same number, different process) could be killed by mistake.
  if ! is_sandbox_pid "$pid"; then
    warn "PID $pid is dead or not a sandbox process. Cleaning stale PID file."
    rm -f -- "$pid_file"
    return 0
  fi

  log "Stopping sandbox for identity '$name' (PID: $pid)..."

  # Kill children first (tun2socks, socat, dns-proxy) so they don't outlive the parent
  pkill --parent "$pid" 2>/dev/null || true
  kill -TERM "$pid" 2>/dev/null || true
  sleep 1
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -f -- "$pid_file"

  # Namespace may still exist if the sandbox didn't clean up on exit
  local ns_name
  ns_name="ns-$(_identity_hash "$name")"
  if ip netns list 2>/dev/null | grep -q "^${ns_name}[[:space:]]"; then
    local pids
    mapfile -t pids < <(sudo ip netns pids "$ns_name" 2>/dev/null || true)
    if [[ ${#pids[@]} -gt 0 ]]; then
      sudo kill -TERM "${pids[@]}" 2>/dev/null || true
      sleep "$SIGTERM_WAIT"
      sudo kill -KILL "${pids[@]}" 2>/dev/null || true
    fi
    sudo ip netns delete "$ns_name" 2>/dev/null || true
  fi

  local veth_host
  veth_host="vh-$(_identity_hash "$name")"
  sudo ip link delete "$veth_host" 2>/dev/null || true

  log "Identity '$name' stopped."
  audit_log "Identity stopped successfully: $name"
}

show_version() {
  printf '%s version %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
  exit "$EXIT_OK"
}

show_config() {
  log "=== Current Configuration ==="
  if [[ -n "$CONFIG_FILE" ]]; then
    log "Config file: $CONFIG_FILE"
    if [[ -r "$CONFIG_FILE" ]]; then
      log "Config file contents:"
      while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        log "  $line"
      done < "$CONFIG_FILE"
    else
      warn "Config file exists but is not readable"
    fi
  else
    log "Config file: Not found (checked ~/.sandboxrc and \$XDG_CONFIG_HOME/sandbox/config)"
  fi
  log ""
  log "Current effective settings:"
  log "  Identity: ${IDENTITY:-<not set>}"
  log "  DNS Server: $DNS_SERVER"
  log "  SOCKS Port: $SOCKS_PORT"
  log "  Timeout: $TIMEOUT"
  log "  Verbose: $VERBOSE_ENABLED"
  log "  GUI Enabled: true"
  log "  No Sandbox: $NO_SANDBOX"
  log "  Trace: $TRACE_ENABLED"
  log "  Dry Run: $DRY_RUN"
  exit "$EXIT_OK"
}

cleanup_all_stale() {
  log "=== Cleaning up stale resources ==="
  local identity_root="$REAL_HOME/.sandbox_identities"

  # Clean up stale temp files
  log "Cleaning stale temp files..."
  local config_dir
  if [[ -n "${XDG_CONFIG_HOME:-}" ]]; then
    config_dir="$XDG_CONFIG_HOME/sandbox"
  else
    config_dir="$HOME/.config/sandbox"
  fi
  cleanup_stale_temps "$config_dir"

  # Clean up stale network namespaces and veth interfaces
  log "Cleaning stale network namespaces..."
  local ns_list
  ns_list="$(ip netns list 2>/dev/null || true)"
  if [[ -n "$ns_list" ]]; then
    while IFS= read -r ns; do
      [[ "$ns" =~ ^ns- ]] || continue
      log "  Cleaning namespace: $ns"
      local pids
      mapfile -t pids < <(sudo ip netns pids "$ns" 2>/dev/null || true)
      if [[ ${#pids[@]} -gt 0 ]]; then
        sudo kill -TERM "${pids[@]}" 2>/dev/null || true
        sleep 0.5
        sudo kill -KILL "${pids[@]}" 2>/dev/null || true
      fi
      sudo ip netns delete "$ns" 2>/dev/null || true
    done <<< "$ns_list"
  fi

  # Clean up stale veth interfaces
  log "Cleaning stale veth interfaces..."
  local veth_list
  veth_list="$(ip link show 2>/dev/null | grep -oE 'vh-[a-f0-9]{6}' || true)"
  if [[ -n "$veth_list" ]]; then
    while IFS= read -r veth; do
      [[ "$veth" =~ ^vh- ]] || continue
      log "  Cleaning veth interface: $veth"
      sudo ip link delete "$veth" 2>/dev/null || true
    done <<< "$veth_list"
  fi

  # Clean up stale PID files
  log "Cleaning stale PID files..."
  if [[ -d "$identity_root" ]]; then
    for pid_file in "$identity_root"/*/.sandbox.pid; do
      [[ -f "$pid_file" ]] || continue
      local pid
      pid="$(<"$pid_file")"
      if ! is_sandbox_pid "$pid"; then
        log "  Removing stale PID file: $pid_file"
        rm -f -- "$pid_file"
      fi
    done
  fi

  log "=== Cleanup complete ==="
  exit "$EXIT_OK"
}

show_help() {
  cat <<EOF
=================================================================
    Identity-Based Secure Workspace Manager  (v${SCRIPT_VERSION})
=================================================================
Usage: $SCRIPT_NAME [options] -- <command> [arguments...]

Options:
  -i, --identity <name>    Unique identity name (Creates persistent hardware spoof & home)
  -w, --whitelist <paths>  Comma-separated list of host files/dirs to expose
  -p, --port <number>      Host SOCKS5 proxy port (Default: $DEFAULT_SOCKS_PORT)
  -f, --profile <name>     Explicitly use/override pre-existing Firejail profile
  -d, --dns <ip>           Upstream DNS resolver IP (Default: $DEFAULT_DNS_SERVER)
  -t, --timeout <seconds>  Kill sandbox after N seconds (0 = no timeout, Default: 0)
  -n, --no-sandbox         Disable Firejail filesystem/app sandboxing (Network namespace only)
  --verbose                Enable detailed step-by-step logging (also shows dir sizes in --list)
  --log-level <level>      Set logging level: debug, info, warn, error (default: info)
  --trace                  Enable shell tracing (set -x) for debugging
  --progress               Show progress indicators for long operations
  --audit                  Enable audit logging for security-relevant operations
  --dry-run                Show proposed topology and profile without altering system
  --force                  Skip confirmation prompts (--delete only)
  --list                   List all existing identities and their state
  --status                 Show running sandbox instances
  --stop <name>            Stop a running sandbox instance
  --delete <name>          Delete an identity and all its persistent state
  --export <name>          Export an identity to a tarball archive
  --import <archive>       Import an identity from a tarball archive
  --clone <src> <dst>      Clone an existing identity to a new name
  --show-config            Show current configuration (file + command line)
  --cleanup-only           Clean up stale resources without launching anything
  -v, --version            Show version information
  -h, --help               Show help menu

Examples:
  # Launch Trae as 'Account 1' (Persistent login, spoofed hardware):
  $SCRIPT_NAME -i trae-acc1 -w ~/.agents -- /usr/share/trae/trae --no-sandbox

  # Run a CLI agent with isolated persistent state:
  $SCRIPT_NAME -i qoder_astral -w ~/.agents -- qodercli

  # List all identities:
  $SCRIPT_NAME --list

  # Show running sandbox instances:
  $SCRIPT_NAME --status

  # Stop a running sandbox:
  $SCRIPT_NAME --stop trae-acc1

  # Delete an identity (with confirmation):
  $SCRIPT_NAME --delete trae-acc1

  # Force delete without confirmation:
  $SCRIPT_NAME --delete trae-acc1 --force

  # Show current configuration:
  $SCRIPT_NAME --show-config

  # Enable shell completion (bash):
  source sandbox-completion.bash  # or add to ~/.bashrc

  # Enable shell completion (zsh):
  source sandbox-completion.zsh    # or add to ~/.zshrc

  # Enable shell completion (fish):
  source sandbox-completion.fish   # or add to ~/.config/fish/completions/sandbox.fish
=================================================================
EOF
  exit "$EXIT_OK"
}

# --- Pre-flight: refuse root ---
# Running as root defeats the purpose of sandboxing and creates privilege escalation risk
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  error "Please run this script as a normal user, not root."
fi

: "${USER:?USER environment variable is not set}"
: "${HOME:?HOME environment variable is not set}"

readonly REAL_USER="$USER"
readonly REAL_HOME="$HOME"

# --- Core Functions ---

check_platform() {
  verbose "Asserting platform..."
  [[ "$(uname -s)" == "Linux" ]] ||
    error "This script requires Linux-specific kernel features (network namespaces)." "$EXIT_PERMISSION"
  # /proc/sys/net existence confirms the kernel has networking support compiled in
  [[ -d /proc/sys/net ]] ||
    error "Network namespace support not available in kernel." "$EXIT_PERMISSION"
}

check_sudo() {
  verbose "Performing sudo pre-flight check..."
  command -v sudo >/dev/null 2>&1 || error "sudo command is missing." "$EXIT_PERMISSION" "Install sudo using your package manager."

  # Fail early if the user can't sudo, rather than mid-setup when ip netns fails
  local sudo_check
  sudo_check="$(sudo -n -l 2>&1 || true)"
  if [[ "$sudo_check" == *"not allowed"* || "$sudo_check" == *"not in the sudoers"* ]]; then
    error "Sudo pre-flight check failed: User '$REAL_USER' lacks sudo privileges." "$EXIT_PERMISSION" "Configure sudo privileges in /etc/sudoers or ask your system administrator."
  fi
}

# Wrapper for sudo operations with timeout handling
sudo_with_timeout() {
  local timeout="${1:-30}" shift
  local sudo_cmd=(timeout -s TERM "$timeout" sudo "$@")

  verbose "Executing sudo command with ${timeout}s timeout: ${sudo_cmd[*]}"
  "${sudo_cmd[@]}"
  local exit_code=$?

  if ((exit_code == 124)); then
    error "Sudo command timed out after ${timeout}s: ${*}" "$EXIT_GENERAL" "Try increasing the timeout or check if the command is hanging."
  elif ((exit_code != 0)); then
    error "Sudo command failed with exit code $exit_code: ${*}" "$EXIT_GENERAL"
  fi

  return 0
}

parse_args() {
  IDENTITY_INPUT="default-identity"
  WHITELIST_INPUT=""
  SOCKS_PORT="$DEFAULT_SOCKS_PORT"
  USER_PROFILE=""
  ACTION="run"
  DELETE_TARGET=""
  STOP_TARGET=""

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
    -i | --identity)
      [[ -n "${2:-}" ]] || error "Option $1 requires an argument."
      IDENTITY_INPUT="$2"
      shift 2
      ;;
    -w | --whitelist)
      [[ -n "${2:-}" ]] || error "Option $1 requires an argument."
      WHITELIST_INPUT="$2"
      shift 2
      ;;
    -p | --port)
      [[ -n "${2:-}" ]] || error "Option $1 requires an argument."
      SOCKS_PORT="$2"
      shift 2
      ;;
    -f | --profile)
      [[ -n "${2:-}" ]] || error "Option $1 requires an argument."
      USER_PROFILE="$2"
      shift 2
      ;;
    -d | --dns)
      [[ -n "${2:-}" ]] || error "Option $1 requires an argument."
      DNS_SERVER="$2"
      shift 2
      ;;
    -t | --timeout)
      [[ -n "${2:-}" ]] || error "Option $1 requires an argument."
      TIMEOUT="$2"
      shift 2
      ;;
    -n | --no-sandbox)
      NO_SANDBOX=true
      shift
      ;;
    --verbose)
      VERBOSE_ENABLED=true
      CURRENT_LOG_LEVEL=$LOG_LEVEL_DEBUG
      shift
      ;;
    --log-level)
      [[ -n "${2:-}" ]] || error "Option $1 requires an argument."
      case "$2" in
        debug) CURRENT_LOG_LEVEL=$LOG_LEVEL_DEBUG ;;
        info) CURRENT_LOG_LEVEL=$LOG_LEVEL_INFO ;;
        warn) CURRENT_LOG_LEVEL=$LOG_LEVEL_WARN ;;
        error) CURRENT_LOG_LEVEL=$LOG_LEVEL_ERROR ;;
        *) error "Invalid log level: $2. Must be debug, info, warn, or error." "$EXIT_USAGE" ;;
      esac
      shift 2
      ;;
    --trace)
      TRACE_ENABLED=true
      shift
      ;;
    --progress)
      PROGRESS_ENABLED=true
      shift
      ;;
    --audit)
      AUDIT_ENABLED=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --force)
      FORCE=true
      shift
      ;;
    --list)
      ACTION="list"
      shift
      ;;
    --status)
      ACTION="status"
      shift
      ;;
    --stop)
      [[ -n "${2:-}" ]] || error "Option $1 requires an identity name."
      ACTION="stop"
      STOP_TARGET="$2"
      shift 2
      ;;
    --delete)
      [[ -n "${2:-}" ]] || error "Option $1 requires an argument."
      ACTION="delete"
      DELETE_TARGET="$2"
      shift 2
      ;;
    --export)
      [[ -n "${2:-}" ]] || error "Option $1 requires an argument."
      ACTION="export"
      EXPORT_TARGET="$2"
      shift 2
      ;;
    --import)
      [[ -n "${2:-}" ]] || error "Option $1 requires an argument."
      ACTION="import"
      IMPORT_TARGET="$2"
      shift 2
      ;;
    --clone)
      [[ -n "${2:-}" ]] || error "Option $1 requires source identity name."
      [[ -n "${3:-}" ]] || error "Option $1 requires target identity name."
      ACTION="clone"
      CLONE_SOURCE="$2"
      CLONE_TARGET="$3"
      shift 3
      ;;
    --show-config)
      ACTION="show_config"
      shift
      ;;
    --cleanup-only)
      ACTION="cleanup_only"
      shift
      ;;
    -v | --version) show_version ;;
    -h | --help) show_help ;;
    --)
      shift
      break
      ;;
    *) error "Unknown parameter: $1" ;;
    esac
  done

  if [[ "$TRACE_ENABLED" == true ]]; then set -x; fi
  COMMAND_ARGS=("$@")
}

validate_inputs() {
  verbose "Validating input parameters..."

  # Strip invalid chars to prevent path traversal and shell injection via identity name
  IDENTITY="${IDENTITY_INPUT//[!a-zA-Z0-9_-]/}"
  [[ -n "$IDENTITY" ]] || error "Identity name is empty or contains only invalid characters." "$EXIT_USAGE"
  ((${#IDENTITY} <= MAX_IDENTITY_LEN)) ||
    error "Identity name too long (${#IDENTITY}/$MAX_IDENTITY_LEN chars)." "$EXIT_USAGE"

  [[ "$SOCKS_PORT" =~ ^[0-9]+$ ]] || error "Invalid SOCKS proxy port: '$SOCKS_PORT'. Must be numeric." "$EXIT_USAGE"
  ((SOCKS_PORT >= 1 && SOCKS_PORT <= 65535)) ||
    error "Invalid SOCKS proxy port: '$SOCKS_PORT'. Must be 1-65535." "$EXIT_USAGE"

  # Validate each octet individually to reject things like 999.0.0.1
  if [[ "$DNS_SERVER" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    local octet
    for octet in "${BASH_REMATCH[@]:1}"; do
      ((octet <= 255)) || error "Invalid DNS IP address (octet > 255): $DNS_SERVER" "$EXIT_USAGE"
    done
  else
    error "Invalid DNS IP address format: $DNS_SERVER" "$EXIT_USAGE"
  fi

  [[ "$TIMEOUT" =~ ^[0-9]+$ ]] ||
    error "Invalid timeout value: '$TIMEOUT'. Must be a non-negative integer." "$EXIT_USAGE"

  # Validate whitelist paths if provided
  if [[ -n "$WHITELIST_INPUT" ]]; then
    local IFS=','
    local inject_pattern='[;&|\\$()]'
    for path in $WHITELIST_INPUT; do
      # Check for path traversal attempts
      if [[ "$path" =~ \.\. ]]; then
        error "Invalid whitelist path: '$path' contains parent directory references (..)" "$EXIT_USAGE"
      fi
      # Check for shell injection attempts
      if [[ "$path" =~ $inject_pattern ]]; then
        error "Invalid whitelist path: '$path' contains shell metacharacters" "$EXIT_USAGE"
      fi
    done
  fi

  # Validate user profile if provided
  if [[ -n "$USER_PROFILE" ]]; then
    # Check for path traversal attempts
    if [[ "$USER_PROFILE" =~ \.\. ]]; then
      error "Invalid profile path: contains parent directory references (..)" "$EXIT_USAGE"
    fi
    # Check for shell injection attempts
    local inject_pattern='[;&|\\$()]'
    if [[ "$USER_PROFILE" =~ $inject_pattern ]]; then
      error "Invalid profile path: contains shell metacharacters" "$EXIT_USAGE"
    fi
  fi
}

check_deps() {
  verbose "Checking system dependencies..."
  local missing=()
  local cmd
  for cmd in firejail socat tun2socks ip python3 md5sum realpath flock ss; do
    has_command "$cmd" || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    suggest_install_command "${missing[@]}"
    error "Missing required dependencies: ${missing[*]}" "$EXIT_MISSING_DEPS" "Run the suggested install command above, or install missing packages manually."
  fi
}

generate_hardware_ids() {
  verbose "Generating hardware spoofing parameters..."

  # Hash the identity once; all deterministic values (MAC, namespace name, IP
  # address) are derived from this single hash. Caching avoids calling md5sum
  # 3+ times for the same identity across different functions.
  local hash
  hash="$(printf '%s' "$IDENTITY" | md5sum)"
  hash="${hash%% *}"
  _CACHED_HASH="$hash"

  local short_hash="${hash:0:$IDENTITY_HASH_LENGTH}"
  # Locally-administered unicast MAC: bit 1 of octet 0 set (02:xx), bit 0 clear
  local mac_addr="02:${hash:2:2}:${hash:4:2}:${hash:6:2}:${hash:8:2}:${hash:10:2}"
  # Map first byte to a 1-254 range so it works as a valid IPv4 octet
  local octet=$((1 + 16#${hash:0:2} % 254))

  MAC_ADDR="$mac_addr"
  NS_NAME="ns-$short_hash"
  VETH_HOST="vh-$short_hash"
  VETH_NS="vn-$short_hash"
  PROXY_IP="$PROXY_NETWORK_BASE.$octet.1"
  NS_IP="$PROXY_NETWORK_BASE.$octet.2"
  SOCKS_PROXY="socks5://$PROXY_IP:$SOCKS_PORT"
}

# Resolve the firejail profile to use. Takes the command name as an argument so
# we don't depend on COMMAND_ARGS being in scope at call time.
resolve_profile() {
  verbose "Resolving Firejail profile..."
  local cmd_name="$1"
  local cmd_path cmd_base

  cmd_path="$(command -v "$cmd_name" 2>/dev/null || realpath -- "$cmd_name" 2>/dev/null || printf '%s' "$cmd_name")"
  cmd_base="$(basename -- "$cmd_path" 2>/dev/null || printf '%s' "$cmd_name")"
  CMD_PATH="$cmd_path"
  NATIVE_PROFILE=""

  if [[ -n "$USER_PROFILE" ]]; then
    if [[ "$USER_PROFILE" == \~/* ]]; then
      NATIVE_PROFILE="$REAL_HOME/${USER_PROFILE#~/}"
    elif [[ "$USER_PROFILE" == "/"* || "$USER_PROFILE" == "./"* || "$USER_PROFILE" == "../"* ]]; then
      NATIVE_PROFILE="$(realpath -m -- "$USER_PROFILE" 2>/dev/null || printf '%s' "$USER_PROFILE")"
    elif [[ "$USER_PROFILE" != *".profile" ]]; then
      NATIVE_PROFILE="${USER_PROFILE}.profile"
    else
      NATIVE_PROFILE="$USER_PROFILE"
    fi
  elif [[ -n "$cmd_base" ]]; then
    # Check user-local profiles first, then system-wide, then known aliases
    if [[ -f "$REAL_HOME/.config/firejail/${cmd_base}.profile" ]]; then
      NATIVE_PROFILE="${cmd_base}.profile"
    elif [[ -f "/etc/firejail/${cmd_base}.profile" ]]; then
      NATIVE_PROFILE="${cmd_base}.profile"
    elif [[ "$cmd_base" == "vscodium" || "$cmd_base" == "trae" ]] &&
      [[ -f "/etc/firejail/codium.profile" ]]; then
      NATIVE_PROFILE="codium.profile"
    fi
  fi
}

build_profile_content() {
  verbose "Generating Firejail profile content..."
  local etc_list include_line=""

  # When an upstream profile exists, mount a broader /etc set for compatibility
  # (fonts, audio, locale). Without one, keep it minimal for security.
  if [[ -n "$NATIVE_PROFILE" ]]; then
    etc_list="resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies,fonts,ld.so.cache,ld.so.conf,ld.so.conf.d,localtime,nsswitch.conf,passwd,group,asound.conf,pulse"
    include_line="include $NATIVE_PROFILE"
  else
    etc_list="resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies"
  fi

  PROFILE_CONTENT="$(
    cat <<EOF
# Dynamic Security Profile for Identity: $IDENTITY
${include_line}

# Identity Spoofing
hostname $IDENTITY
machine-id

# Block Hardware Telemetry (Defeats Electron PC Fingerprinting)
blacklist /sys/class/dmi
blacklist /sys/devices/virtual/dmi
blacklist /sys/class/firmware

nogroups
caps.drop all
seccomp
nonewprivs
noroot

# Route DNS through the local python translator
dns 127.0.0.1

private-dev
private-tmp
private-etc $etc_list

read-only /sbin
read-only /usr/sbin
read-only /bin
read-only /usr/bin
EOF
  )"

  # GUI mode needs X11 shared memory; headless mode locks down IPC and GPU
  PROFILE_CONTENT+=$'\nwhitelist /tmp/.X11-unix'
}

show_dry_run() {
  log "=== DRY RUN MODE: No system-altering commands will be executed ==="
  log "Proposed Namespace Topology:"
  log "  Namespace Name:      $NS_NAME"
  log "  Veth Host Interface: $VETH_HOST (IP: $PROXY_IP/24)"
  log "  Veth NS Interface:   $VETH_NS (IP: $NS_IP/24, Spoofed MAC: $MAC_ADDR)"
  log "  Tunnel Interface:    tun0 (Route: default)"
  log "  Upstream Proxy:      $SOCKS_PROXY"
  log "  Upstream DNS:        $DNS_SERVER"
  log "  State Home Directory: $HOME_DIR"
  log "  Machine ID:          Spoofed (Random)"
  if ((TIMEOUT > 0)); then log "  Timeout:             ${TIMEOUT}s"; fi
  log "Proposed Firejail Profile:"
  printf '%s\n' "$SEPARATOR"
  printf '%s\n' "$PROFILE_CONTENT"
  printf '%s\n' "$SEPARATOR"
  log "Proposed Whitelist Mounts:"
  log "  Identity root: $IDENTITY_ROOT"
  log "  Working dir:   $TARGET_DIR"
  if [[ "$CMD_PATH" == "$REAL_HOME"* ]]; then log "  Command path:  $CMD_PATH"; fi
  if [[ -n "$WHITELIST_INPUT" ]]; then
    local item
    while IFS= read -r item; do
      log "  User whitelist: $item"
    done < <(printf '%s\n' "$WHITELIST_INPUT" | tr ',' '\n')
  fi
  exit "$EXIT_OK"
}

setup_directories() {
  verbose "Creating state and configuration directories..."
  mkdir -p -- "$HOME_DIR" "$CONFIG_DIR"
  cleanup_stale_temps "$CONFIG_DIR"
}

write_config_files() {
  verbose "Creating secure session configuration files..."
  # mktemp with identity-scoped template keeps files inside the identity dir
  DNS_PROXY_PY="$(mktemp "$CONFIG_DIR/dns_proxy_XXXXXX.py")"
  PROFILE_PATH="$(mktemp "$CONFIG_DIR/sandbox_XXXXXX.profile")"
  chmod 600 -- "$DNS_PROXY_PY" "$PROFILE_PATH"

  printf '%s\n' "$PROFILE_CONTENT" >"$PROFILE_PATH"

  verbose "Writing DNS UDP-to-TCP translator script..."
  # This Python script bridges firejail's UDP-only dns directive with the
  # TCP-only path through tun2socks. Uses ThreadingUDPServer so concurrent
  # DNS queries from the sandboxed app don't block each other.
  cat <<'PYEOF' >"$DNS_PROXY_PY"
import socket
import sys
import os
import socketserver
import signal

DNS_SERVER = os.environ.get("SANDBOX_DNS_SERVER", "1.1.1.1")

def log_err(msg):
    print(f"[dns-proxy] {msg}", file=sys.stderr, flush=True)


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        if not data:
            return
        length = len(data)
        tcp_data = bytes([length >> 8, length & 0xFF]) + data
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.settimeout(4.0)
        try:
            tcp_sock.connect((DNS_SERVER, 53))
            tcp_sock.sendall(tcp_data)
            resp_len_buf = tcp_sock.recv(2)
            if len(resp_len_buf) < 2:
                log_err("Incomplete TCP length header from upstream")
                return
            resp_len = (resp_len_buf[0] << 8) + resp_len_buf[1]
            resp_data = b""
            while len(resp_data) < resp_len:
                chunk = tcp_sock.recv(resp_len - len(resp_data))
                if not chunk:
                    break
                resp_data += chunk
            if len(resp_data) == resp_len:
                sock.sendto(resp_data, self.client_address)
            else:
                log_err(f"Truncated DNS response: got {len(resp_data)}/{resp_len} bytes")
        except Exception as e:
            log_err(f"Upstream query failed: {e}")
        finally:
            tcp_sock.close()


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    server = ThreadedUDPServer(("127.0.0.1", 53), DNSHandler)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
PYEOF
}

setup_network() {
  log "Initializing hardware-spoofed network for identity [$IDENTITY]..."
  start_progress "Setting up network"

  # Pre-delete any leftover namespace/veth from a previous crash.
  # Without this, 'ip netns add' fails with "File exists" on stale state.
  sudo ip netns delete "$NS_NAME" 2>/dev/null || true
  sudo ip link delete "$VETH_HOST" 2>/dev/null || true

  verbose "Adding network namespace: $NS_NAME"
  sudo ip netns add "$NS_NAME"
  NS_CREATED=true

  verbose "Adding veth pair: $VETH_HOST <-> $VETH_NS"
  sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
  VETH_CREATED=true

  verbose "Moving $VETH_NS to namespace $NS_NAME"
  sudo ip link set "$VETH_NS" netns "$NS_NAME"

  # Spoofed MAC must be set BEFORE bringing the interface up
  verbose "Setting spoofed MAC address $MAC_ADDR on $VETH_NS"
  sudo ip netns exec "$NS_NAME" ip link set dev "$VETH_NS" address "$MAC_ADDR"

  verbose "Configuring host veth address $PROXY_IP/24 and bringing link UP"
  sudo ip addr add "$PROXY_IP/24" dev "$VETH_HOST"
  sudo ip link set "$VETH_HOST" up

  verbose "Configuring namespace veth address $NS_IP/24 and bringing links UP"
  sudo ip netns exec "$NS_NAME" ip addr add "$NS_IP/24" dev "$VETH_NS"
  sudo ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
  sudo ip netns exec "$NS_NAME" ip link set lo up

  # tun0 carries all traffic through tun2socks; default route ensures everything
  # goes through the tunnel rather than leaking via the veth directly
  verbose "Adding tun0 interface inside namespace"
  sudo ip netns exec "$NS_NAME" ip tuntap add dev tun0 mode tun
  sudo ip netns exec "$NS_NAME" ip link set tun0 up
  sudo ip netns exec "$NS_NAME" ip route add default dev tun0

  stop_progress
}

start_proxies() {
  # socat bridges the namespace's tun2socks to the host's SOCKS5 proxy.
  # It binds to the host-side veth IP so only the namespace can reach it.
  start_progress "Starting proxy redirectors"
  verbose "Starting socat proxy redirector on port $SOCKS_PORT..."
  socat TCP-LISTEN:"$SOCKS_PORT",bind="$PROXY_IP",fork,reuseaddr TCP:127.0.0.1:"$SOCKS_PORT" >/dev/null 2>&1 &
  SOCAT_PID=$!
  kill -0 "$SOCAT_PID" 2>/dev/null || error "socat failed to start on port $SOCKS_PORT. Is the port in use?"

  verbose "Starting tun2socks inside network namespace..."
  sudo ip netns exec "$NS_NAME" tun2socks -device tun0 -proxy "$SOCKS_PROXY" >/dev/null 2>&1 &
  TUN_PID=$!
  kill -0 "$TUN_PID" 2>/dev/null || error "tun2socks failed to start."
  stop_progress
}

wait_for_network() {
  verbose "Synchronizing network interface and proxy connectivity..."
  local attempt=0 tun_up=false proxy_up=false

  while ((attempt < MAX_SYNC_ATTEMPTS)); do
    if [[ "$tun_up" == false ]]; then
      if sudo ip netns exec "$NS_NAME" ip link show tun0 2>/dev/null | grep -qE "state UP|UP,LOWER_UP"; then
        tun_up=true
        verbose "Network interface tun0 is UP in namespace."
      fi
    fi
    if [[ "$proxy_up" == false ]]; then
      if { echo >"/dev/tcp/$PROXY_IP/$SOCKS_PORT"; } 2>/dev/null; then
        proxy_up=true
        verbose "Proxy port $SOCKS_PORT is reachable on host side."
      fi
    fi
    [[ "$tun_up" == false || "$proxy_up" == false ]] || break
    sleep "$SYNC_POLL_INTERVAL"
    ((++attempt))
  done

  # Report which specific check failed so the user can diagnose the issue
  if [[ "$tun_up" == false && "$proxy_up" == false ]]; then
    error "Network startup failed: tun0 is down AND proxy port $SOCKS_PORT is unreachable." "$EXIT_NETWORK"
  elif [[ "$tun_up" == false ]]; then
    error "Network startup failed: tun0 interface did not come up in namespace $NS_NAME." "$EXIT_NETWORK"
  elif [[ "$proxy_up" == false ]]; then
    error "Network startup failed: proxy port $SOCKS_PORT is not reachable at $PROXY_IP." "$EXIT_NETWORK"
  fi
}

start_dns_proxy() {
  verbose "Starting DNS proxy python script..."
  sudo ip netns exec "$NS_NAME" env "SANDBOX_DNS_SERVER=$DNS_SERVER" python3 -- "$DNS_PROXY_PY" >/dev/null 2>&1 &
  DNS_PID=$!
  kill -0 "$DNS_PID" 2>/dev/null || error "DNS proxy failed to start."
}

build_whitelist() {
  verbose "Configuring whitelisting..."
  WHITELIST_ARGS=()

  WHITELIST_ARGS+=("--whitelist=$IDENTITY_ROOT")
  add_whitelist_mount "$TARGET_DIR"

  if [[ "$CMD_PATH" == "$REAL_HOME"* ]]; then
    add_whitelist_mount "$CMD_PATH"
  fi

  if [[ -n "$WHITELIST_INPUT" ]]; then
    local dir abs_dir
    while IFS= read -r dir; do
      # Centralize tilde expansion here so add_whitelist_mount only sees absolute paths
      if [[ "$dir" == \~/* ]]; then
        abs_dir="$REAL_HOME/${dir#~/}"
      elif [[ "$dir" == "~" ]]; then
        abs_dir="$REAL_HOME"
      else
        abs_dir="$(realpath -m -- "$dir" 2>/dev/null || printf '%s' "$dir")"
      fi
      add_whitelist_mount "$abs_dir"
    done < <(printf '%s\n' "$WHITELIST_INPUT" | tr ',' '\n')
  fi
}

execute_sandbox() {
  local term_value="${TERM:-xterm-256color}"
  # 'dumb' terminals break color output and line editing in most apps
  [[ "$term_value" != "dumb" ]] || term_value="xterm-256color"

  # Automatically append --no-sandbox for Electron-based apps when running inside Firejail
  if [[ "$NO_SANDBOX" == false ]]; then
    local cmd_base
    cmd_base="$(basename -- "$CMD_PATH" 2>/dev/null || true)"
    case "$cmd_base" in
      trae|code|vscodium|codium|cursor|obsidian)
        local arg has_no_sandbox=false
        for arg in "${COMMAND_ARGS[@]}"; do
          if [[ "$arg" == "--no-sandbox" ]]; then
            has_no_sandbox=true
            break
          fi
        done
        if [[ "$has_no_sandbox" == false ]]; then
          log "Detecting Electron-based application [$cmd_base]. Auto-appending --no-sandbox to bypass internal zygote sandbox inside Firejail."
          COMMAND_ARGS+=("--no-sandbox")
        fi
        ;;
    esac
  fi

  # If no-sandbox is enabled, run directly in the network namespace with user env preserved
  if [[ "$NO_SANDBOX" == true ]]; then
    log "$SEPARATOR"
    log "Identity:        $IDENTITY (Network Namespace Only)"
    log "Spoofed MAC:     $MAC_ADDR"
    log "Namespace:       $NS_NAME"
    if ((TIMEOUT > 0)); then log "Timeout:         ${TIMEOUT}s"; fi
    log "$SEPARATOR"

    verbose "Running command directly inside namespace $NS_NAME..."

    local net_env_args=(
      "HOME=$REAL_HOME"
      "USER=$REAL_USER"
      "LOGNAME=$REAL_USER"
      "PATH=$PATH"
      "TERM=$term_value"
      "COLORTERM=${COLORTERM:-truecolor}"
      "LANG=${LANG:-en_US.UTF-8}"
      "SHELL=/bin/bash"
    )
    [[ -n "${XDG_CONFIG_HOME:-}" ]] && net_env_args+=("XDG_CONFIG_HOME=$XDG_CONFIG_HOME")
    [[ -n "${XDG_DATA_HOME:-}" ]] && net_env_args+=("XDG_DATA_HOME=$XDG_DATA_HOME")
    [[ -n "${XDG_STATE_HOME:-}" ]] && net_env_args+=("XDG_STATE_HOME=$XDG_STATE_HOME")
    [[ -n "${XDG_CACHE_HOME:-}" ]] && net_env_args+=("XDG_CACHE_HOME=$XDG_CACHE_HOME")
    [[ -n "${DISPLAY:-}" ]] && net_env_args+=("DISPLAY=$DISPLAY")
    [[ -n "${WAYLAND_DISPLAY:-}" ]] && net_env_args+=("WAYLAND_DISPLAY=$WAYLAND_DISPLAY")
    [[ -n "${XAUTHORITY:-}" ]] && net_env_args+=("XAUTHORITY=$XAUTHORITY")
    [[ -n "${XDG_RUNTIME_DIR:-}" ]] && net_env_args+=("XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR")
    [[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] && net_env_args+=("DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS")

    local timeout_args=()
    if ((TIMEOUT > 0)); then
      timeout_args=(timeout --signal=TERM --kill-after="$TUN2SOCKS_KILL_WAIT" "$TIMEOUT")
    fi

    sudo ip netns exec "$NS_NAME" sudo -u "$REAL_USER" env -i \
      "${net_env_args[@]}" \
      "${timeout_args[@]}" \
      "${COMMAND_ARGS[@]}" &
    local sandbox_pid=$!

    # Persist PID so --stop and --status can find us from another terminal
    printf '%s\n' "$sandbox_pid" >"$IDENTITY_ROOT/.sandbox.pid"
    local exit_code=0
    wait "$sandbox_pid" || exit_code=$?
    rm -f -- "$IDENTITY_ROOT/.sandbox.pid"
    return "$exit_code"
  fi

  local env_args=(
    "HOME=$HOME_DIR"
    "XDG_CONFIG_HOME=$HOME_DIR/.config"
    "XDG_DATA_HOME=$HOME_DIR/.local/share"
    "XDG_STATE_HOME=$HOME_DIR/.local/state"
    "XDG_CACHE_HOME=$HOME_DIR/.cache"
    "TERM=$term_value"
    "COLORTERM=${COLORTERM:-truecolor}"
    "LANG=${LANG:-en_US.UTF-8}"
    "USER=user"
    "LOGNAME=user"
    "SHELL=/bin/bash"
    "PATH=$REAL_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
  )

  # Forward terminal capabilities so the sandboxed app renders correctly
  [[ -n "${TERM_PROGRAM:-}" ]] && env_args+=("TERM_PROGRAM=$TERM_PROGRAM")
  [[ -n "${VTE_VERSION:-}" ]] && env_args+=("VTE_VERSION=$VTE_VERSION")

  [[ -n "${DISPLAY:-}" ]] && env_args+=("DISPLAY=$DISPLAY")
  [[ -n "${WAYLAND_DISPLAY:-}" ]] && env_args+=("WAYLAND_DISPLAY=$WAYLAND_DISPLAY")
  if [[ -n "${XAUTHORITY:-}" ]]; then
    env_args+=("XAUTHORITY=$XAUTHORITY")
    WHITELIST_ARGS+=("--whitelist=$XAUTHORITY")
  fi
  [[ -n "${XDG_RUNTIME_DIR:-}" ]] && env_args+=("XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR")

  # timeout wraps firejail so the entire sandbox is killed after N seconds,
  # including all child processes. --kill-after ensures SIGKILL if SIGTERM is ignored.
  local timeout_args=()
  if ((TIMEOUT > 0)); then
    timeout_args=(timeout --signal=TERM --kill-after="$TUN2SOCKS_KILL_WAIT" "$TIMEOUT")
  fi

  log "$SEPARATOR"
  log "Identity:        $IDENTITY"
  log "Spoofed MAC:     $MAC_ADDR"
  log "Machine ID:      Spoofed (Random)"
  log "Namespace:       $NS_NAME"
  log "State Directory: $HOME_DIR"
  if ((TIMEOUT > 0)); then log "Timeout:         ${TIMEOUT}s"; fi
  log "$SEPARATOR"

  verbose "Running firejail within namespace $NS_NAME..."

  # The EXIT trap handles cleanup when this process exits (normal or signal).
  # Ctrl+C sends SIGINT to the whole process group including firejail, so it
  # exits too, and our trap tears down the namespace and proxies.
  sudo ip netns exec "$NS_NAME" sudo -u "$REAL_USER" env -i \
    "${env_args[@]}" \
    "${timeout_args[@]}" \
    firejail \
    --deterministic-shutdown \
    --deterministic-exit-code \
    --profile="$PROFILE_PATH" \
    "${WHITELIST_ARGS[@]}" \
    --private-cwd="$TARGET_DIR" \
    -- "${COMMAND_ARGS[@]}" &
  local sandbox_pid=$!

  # Persist PID so --stop and --status can find us from another terminal
  printf '%s\n' "$sandbox_pid" >"$IDENTITY_ROOT/.sandbox.pid"
  local exit_code=0
  wait "$sandbox_pid" || exit_code=$?
  rm -f -- "$IDENTITY_ROOT/.sandbox.pid"
  return "$exit_code"
}

# --- Main ---

main() {
  # Platform and sudo checks run first because everything else depends on them.
  # No trap yet: there's no state to clean up if these fail.
  check_platform
  check_sudo

  # Load config file before parse_args so command line can override config
  load_config_file

  parse_args "$@"

  # Initialize audit logging if enabled
  init_audit_log
  audit_log "Script started: $SCRIPT_NAME version $SCRIPT_VERSION"

  # Management actions exit early and don't create namespaces or proxies,
  # so they don't need the cleanup trap.
  case "$ACTION" in
  list)
    list_identities
    exit "$EXIT_OK"
    ;;
  status)
    show_status
    exit "$EXIT_OK"
    ;;
  stop)
    stop_identity "$STOP_TARGET"
    exit "$EXIT_OK"
    ;;
  delete)
    delete_identity "$DELETE_TARGET"
    exit "$EXIT_OK"
    ;;
  export)
    export_identity "$EXPORT_TARGET"
    exit "$EXIT_OK"
    ;;
  import)
    import_identity "$IMPORT_TARGET"
    exit "$EXIT_OK"
    ;;
  clone)
    clone_identity "$CLONE_SOURCE" "$CLONE_TARGET"
    exit "$EXIT_OK"
    ;;
  show_config)
    show_config
    exit "$EXIT_OK"
    ;;
  cleanup_only)
    cleanup_all_stale
    exit "$EXIT_OK"
    ;;
  esac

  # COMMAND_ARGS is populated in parse_args so it contains only the command
  # arguments after option parsing and shifts.
  [[ ${#COMMAND_ARGS[@]} -gt 0 ]] || error "No command specified to run. Use -- for the command, e.g.: $SCRIPT_NAME -i myid -- firefox" "$EXIT_USAGE"

  # Exit trap for normal cleanup - runs when script exits normally
  trap cleanup EXIT

  validate_inputs
  check_deps
  generate_hardware_ids

  TARGET_DIR="$(pwd)"
  IDENTITY_ROOT="$REAL_HOME/.sandbox_identities/$IDENTITY"
  HOME_DIR="$IDENTITY_ROOT/home"
  CONFIG_DIR="$IDENTITY_ROOT/.sandbox_configs"

  mkdir -p -- "$IDENTITY_ROOT"
  exec {LOCK_FD}>"$IDENTITY_ROOT/.lock"
  if ! flock -n "$LOCK_FD"; then
    # Before giving up, check if the lock holder is actually alive. A crashed
    # previous run may have left the lock file without releasing it.
    recover_stale_instance "$IDENTITY_ROOT" "$IDENTITY"
    flock -n "$LOCK_FD" || error "Another sandbox instance for identity '$IDENTITY' is already running." "$EXIT_LOCK_CONFLICT" "Use --stop $IDENTITY to stop the running instance, or --cleanup-only to clean up stale resources."
  fi

  # Check for port conflicts before setting up the network. Escaping dots in
  # the IP prevents grep from matching e.g. 10.250.12.1 against 10X250X12X1.
  # The trailing space after the port number anchors against partial matches
  # (e.g., port 1080 matching 10808).
  local escaped_ip="${PROXY_IP//./\.}"
  if ss -tln 2>/dev/null | grep -qE "(${escaped_ip}|0\.0\.0\.0|\[::\]|\*):${SOCKS_PORT} "; then
    error "Port $SOCKS_PORT is already in use." "$EXIT_PORT_CONFLICT" "Try a different port with -p, or stop the process using port $SOCKS_PORT."
  fi

  # Resolve the firejail profile with the command name passed explicitly.
  # This avoids depending on COMMAND_ARGS being in scope at call time.
  resolve_profile "${COMMAND_ARGS[0]}"
  build_profile_content

  if [[ "$DRY_RUN" == true ]]; then
    show_dry_run
  fi

  setup_directories
  write_config_files
  if [[ "${SANDBOX_TEST_SKIP_NET:-}" != "true" ]]; then
    setup_network
    start_proxies
    wait_for_network
    start_dns_proxy
  fi
  build_whitelist
  execute_sandbox
}

main "$@"
