#!/usr/bin/env bash
# ==============================================================================
# UNIFIED IDENTITY-BASED SECURE WORKSPACE MANAGER (ARCH SAFE)
# ==============================================================================
# Engineered for AI Agents & IDEs (Cursor, Trae, QoderCLI).
# Provides complete network isolation, persistent hardware spoofing (MAC/UUID),
# and dedicated identity state folders to prevent account cross-contamination.
# ==============================================================================

set -Eeuo pipefail
shopt -s inherit_errexit 2> /dev/null || true

# --- Bash Version Assertion ---
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4))); then
  printf '[FATAL] Bash 4.4+ required (have %s)\n' "$BASH_VERSION" >&2
  exit 1
fi

readonly SCRIPT_VERSION="1.0.0"
# shellcheck disable=SC2155
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"

# Global State for Cleanup and Tracking
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

# Global Flags / Configs
VERBOSE_ENABLED=false
TRACE_ENABLED=false
DRY_RUN=false
DNS_SERVER="1.1.1.1"
TIMEOUT=0

# --- Structured Logging ---
log()     { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
verbose() { [[ "$VERBOSE_ENABLED" == true ]] && log "DEBUG: $*" || true; }
warn()    { printf '[%s] WARN: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
error()   {
            printf '[%s] ERROR: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
                                                                               exit 1
}

# --- Error Trap with Line Context ---
on_error() {
  local line="$1" exit_code="$2"
  if ((exit_code == 0)); then return 0; fi
  printf '[%s] FATAL: script failed at line %d (exit %d)\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$line" "$exit_code" >&2
}
trap 'on_error "$LINENO" "$?"' ERR

kill_if_set() {
  local pid="${1:-}" use_sudo="${2:-false}"
  if [[ -n "$pid" ]]; then
    if [[ "$use_sudo" == true ]]; then
      sudo kill -- "$pid" 2> /dev/null || true
    else
      kill -- "$pid" 2> /dev/null || true
    fi
  fi
}

cleanup() {
  local had_state=false
  if [[ "$NS_CREATED" == true ]] || [[ "$VETH_CREATED" == true ]] \
     || [[ -n "${TUN_PID:-}" ]] || [[ -n "${PROFILE_PATH:-}" ]]; then
    had_state=true
    if [[ -n "${IDENTITY:-}" ]]; then
      log "Saving state and cleaning up identity [$IDENTITY]..."
    else
      log "Saving state and cleaning up sandbox resources..."
    fi
  fi

  kill_if_set "${TUN_PID:-}" true
  kill_if_set "${SOCAT_PID:-}"
  kill_if_set "${DNS_PID:-}"

  if [[ "$NS_CREATED" == true ]] && [[ -n "${NS_NAME:-}" ]]; then
    sudo ip netns delete -- "$NS_NAME" 2> /dev/null || true
  fi
  if [[ "$VETH_CREATED" == true ]] && [[ -n "${VETH_HOST:-}" ]]; then
    sudo ip link delete -- "$VETH_HOST" 2> /dev/null || true
  fi

  [[ -n "${PROFILE_PATH:-}" ]] && rm -f -- "$PROFILE_PATH" || true
  [[ -n "${DNS_PROXY_PY:-}" ]] && rm -f -- "$DNS_PROXY_PY" || true

  if [[ -n "${LOCK_FD:-}" ]]; then
    flock -u "$LOCK_FD" 2> /dev/null || true
  fi

  if [[ "$had_state" == true ]]; then
    log "Cleanup complete."
  fi
}

suggest_install_command() {
  local missing_deps=("$@")
  local pkgs=()
  for dep in "${missing_deps[@]}"; do
    case "$dep" in
      ip) pkgs+=("iproute2") ;;
      *)  pkgs+=("$dep") ;;
    esac
  done

  if command -v apt-get > /dev/null 2>&1; then
    log "To install: sudo apt-get update && sudo apt-get install -y ${pkgs[*]}"
  elif command -v dnf > /dev/null 2>&1; then
    log "To install: sudo dnf install -y ${pkgs[*]}"
  elif command -v pacman > /dev/null 2>&1; then
    log "To install: sudo pacman -S --noconfirm ${pkgs[*]}"
  elif command -v zypper > /dev/null 2>&1; then
    log "To install: sudo zypper install -y ${pkgs[*]}"
  elif command -v apk > /dev/null 2>&1; then
    log "To install: sudo apk add ${pkgs[*]}"
  else
    log "Please install: ${pkgs[*]}"
  fi
}

add_whitelist_mount() {
  local host_path="$1"
  [[ -e "$host_path" ]] || return 0

  WHITELIST_ARGS+=("--whitelist=$host_path")

  if [[ "$host_path" == "$REAL_HOME"* ]]; then
    local rel_path="${host_path#"$REAL_HOME"/}"
    local fake_path="$HOME_DIR/$rel_path"

    if [[ "$fake_path" != "$HOME_DIR" ]]; then
      mkdir -p -- "$(dirname -- "$fake_path")"
      ln -sfn -- "$host_path" "$fake_path"
    fi
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
    local name
    name="$(basename -- "$dir")"
    local home_dir="$dir/home"
    local size="N/A"
    if [[ -d "$home_dir" ]]; then
      size="$(du -sh -- "$home_dir" 2> /dev/null | awk '{print $1}')"
    fi
    log "  $name  (state: $size, path: $dir)"
    found=true
  done

  [[ "$found" == true ]] || log "No identities found in $identity_root"
}

delete_identity() {
  local name="$1"
  name="${name//[!a-zA-Z0-9_-]/}"
  [[ -n "$name" ]] || error "Invalid identity name for deletion."

  local identity_dir="$REAL_HOME/.sandbox_identities/$name"
  [[ -d "$identity_dir" ]] || error "Identity '$name' does not exist at $identity_dir"

  log "Deleting identity '$name' and all associated state..."
  log "  Path: $identity_dir"
  rm -rf -- "$identity_dir"
  log "Identity '$name' deleted successfully."
}

show_version() {
  printf '%s version %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
  exit 0
}

show_help() {
  cat << EOF
=================================================================
    Identity-Based Secure Workspace Manager  (v${SCRIPT_VERSION})
=================================================================
Usage: $SCRIPT_NAME [options] -- <command> [arguments...]

Options:
  -i, --identity <name>    Unique identity name (Creates persistent hardware spoof & home)
  -w, --whitelist <paths>  Comma-separated list of host files/dirs to expose
  -p, --port <number>      Host SOCKS5 proxy port (Default: 10808)
  -f, --profile <name>     Explicitly use/override pre-existing Firejail profile
  -d, --dns <ip>           Upstream DNS resolver IP (Default: 1.1.1.1)
  -t, --timeout <seconds>  Kill sandbox after N seconds (0 = no timeout, Default: 0)
  --gui                    Enable GUI support (X11 & Wayland forwarding)
  --verbose                Enable detailed step-by-step logging
  --trace                  Enable shell tracing (set -x) for debugging
  --dry-run                Show proposed topology and profile without altering system
  --list                   List all existing identities and their state
  --delete <name>          Delete an identity and all its persistent state
  -v, --version            Show version information
  -h, --help               Show help menu

Examples:
  # Launch Trae as 'Account 1' (Persistent login, spoofed hardware):
  $SCRIPT_NAME -i trae-acc1 --gui -w ~/.agents -- /usr/share/trae/trae --no-sandbox

  # Run a CLI agent with isolated persistent state:
  $SCRIPT_NAME -i qoder_astral -w ~/.agents -- qodercli

  # List all identities:
  $SCRIPT_NAME --list

  # Delete an identity:
  $SCRIPT_NAME --delete trae-acc1
=================================================================
EOF
  exit 0
}

# --- Pre-flight: refuse root ---
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  error "Please run this script as a normal user, not root."
fi

: "${USER:?USER environment variable is not set}"
: "${HOME:?HOME environment variable is not set}"

readonly REAL_USER="$USER"
readonly REAL_HOME="$HOME"

main() {
  # --- Platform Assertion ---
  verbose "Asserting platform..."
  [[ "$(uname -s)" == "Linux" ]] \
                                 || error "This script requires Linux-specific kernel features (network namespaces)."

  # --- Sudo Pre-flight Check ---
  verbose "Performing sudo pre-flight check..."
  command -v sudo > /dev/null 2>&1 || error "sudo command is missing."

  local sudo_check
  sudo_check="$(sudo -n -l 2>&1 || true)"
  if [[ "$sudo_check" == *"not allowed"* || "$sudo_check" == *"not in the sudoers"* ]]; then
    error "Sudo pre-flight check failed: User '$REAL_USER' lacks sudo privileges."
  fi

  # Register trap early
  trap cleanup EXIT INT TERM

  # --- 1. PARSE ARGUMENTS ---
  local IDENTITY_INPUT="default-identity"
  local WHITELIST_INPUT=""
  local SOCKS_PORT="10808"
  local USER_PROFILE=""
  local GUI_ENABLED=false
  local ACTION="run"
  local DELETE_TARGET=""

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
      --gui)
                    GUI_ENABLED=true
                                      shift
                                            ;;
      --verbose)
                    VERBOSE_ENABLED=true
                                          shift
                                                ;;
      --trace)
                    TRACE_ENABLED=true
                                        shift
                                              ;;
      --dry-run)
                    DRY_RUN=true
                                  shift
                                        ;;
      --list)
                    ACTION="list"
                                   shift
                                         ;;
      --delete)
        [[ -n "${2:-}" ]] || error "Option $1 requires an argument."
        ACTION="delete"
                         DELETE_TARGET="$2"
                                             shift 2
                                                     ;;
      -v | --version) show_version ;;
      -h | --help)  show_help ;;
      --)
                    shift
                           break
                                 ;;
      *)            error "Unknown parameter: $1" ;;
    esac
  done

  # Enable trace if requested
  if [[ "$TRACE_ENABLED" == true ]]; then set -x; fi

  # Handle subcommands that don't need the rest of the pipeline
  if [[ "$ACTION" == "list" ]]; then
    list_identities
    exit 0
  fi
  if [[ "$ACTION" == "delete" ]]; then
    delete_identity "$DELETE_TARGET"
    exit 0
  fi

  local COMMAND_ARGS=("$@")

  [[ ${#COMMAND_ARGS[@]} -gt 0 ]] || error "No command specified to run."

  # --- 2. INPUT VALIDATION ---
  verbose "Validating input parameters..."
  IDENTITY="${IDENTITY_INPUT//[!a-zA-Z0-9_-]/}"
  [[ -n "$IDENTITY" ]] || error "Identity name is empty or contains only invalid characters."

  [[ "$SOCKS_PORT" =~ ^[0-9]+$ ]] || error "Invalid SOCKS proxy port: '$SOCKS_PORT'. Must be numeric."
  ((SOCKS_PORT >= 1 && SOCKS_PORT <= 65535))   || error "Invalid SOCKS proxy port: '$SOCKS_PORT'. Must be 1-65535."

  if [[ "$DNS_SERVER" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    local octet
    for octet in "${BASH_REMATCH[@]:1}"; do
      ((octet <= 255))   || error "Invalid DNS IP address (octet > 255): $DNS_SERVER"
    done
  else
    error "Invalid DNS IP address format: $DNS_SERVER"
  fi

  [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || error "Invalid timeout value: '$TIMEOUT'. Must be a non-negative integer."

  # --- 3. PREREQUISITES CHECK ---
  verbose "Checking system dependencies..."
  local missing=()
  local cmd
  for cmd in firejail socat tun2socks ip python3 md5sum realpath flock; do
    command -v "$cmd" > /dev/null 2>&1 || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    suggest_install_command "${missing[@]}"
    error "Missing required dependencies: ${missing[*]}"
  fi

  # --- 4. GENERATE DETERMINISTIC HARDWARE SPOOFING ---
  verbose "Generating hardware spoofing parameters..."
  local HASH
  HASH="$(printf '%s' "$IDENTITY" | md5sum | awk '{print $1}')"
  local SESSION_HASH="${HASH:0:6}"

  local MAC_ADDR="02:${HASH:2:2}:${HASH:4:2}:${HASH:6:2}:${HASH:8:2}:${HASH:10:2}"

  NS_NAME="ns-$SESSION_HASH"
  VETH_HOST="vh-$SESSION_HASH"
  local VETH_NS="vn-$SESSION_HASH"
  local OCTET=$((1 + 16#${HASH:0:2} % 254))
  local PROXY_IP="10.250.$OCTET.1"
  local NS_IP="10.250.$OCTET.2"
  local SOCKS_PROXY="socks5://$PROXY_IP:$SOCKS_PORT"

  local TARGET_DIR
  TARGET_DIR="$(pwd)"

  # --- 5. CONFIGURE PERSISTENT IDENTITY DIRECTORIES ---
  local IDENTITY_ROOT="$REAL_HOME/.sandbox_identities/$IDENTITY"
  local HOME_DIR="$IDENTITY_ROOT/home"
  local CONFIG_DIR="$IDENTITY_ROOT/.sandbox_configs"

  # --- Concurrent run guard (flock) ---
  mkdir -p -- "$IDENTITY_ROOT"
  exec {LOCK_FD}> "$IDENTITY_ROOT/.lock"
  flock -n "$LOCK_FD" || error "Another sandbox instance for identity '$IDENTITY' is already running."

  # --- Port conflict detection ---
  local escaped_ip
  escaped_ip="${PROXY_IP//./\\.}"
  if ss -tlnp 2> /dev/null | grep -q -E "(0\\.0\\.0\\.0|\\[::\\]|\\*|${escaped_ip}):${SOCKS_PORT} "; then
    error "Port $SOCKS_PORT is already in use. Choose a different port with -p."
  fi

  # --- 6. NATIVE PROFILE RESOLUTION ---
  verbose "Resolving Firejail profile..."
  local CMD_NAME="${COMMAND_ARGS[0]}"
  local CMD_PATH
  CMD_PATH="$(command -v "$CMD_NAME" 2> /dev/null || realpath -- "$CMD_NAME" 2> /dev/null || printf '%s' "$CMD_NAME")"
  local CMD_BASE
  CMD_BASE="$(basename -- "$CMD_PATH" 2> /dev/null || printf '%s' "$CMD_NAME")"
  local NATIVE_PROFILE=""

  if [[ -n "$USER_PROFILE" ]]; then
    if [[ "$USER_PROFILE" == \~/* ]]; then
      NATIVE_PROFILE="$REAL_HOME/${USER_PROFILE#~/}"
    elif [[ "$USER_PROFILE" == "/"* || "$USER_PROFILE" == "./"* || "$USER_PROFILE" == "../"* ]]; then
      NATIVE_PROFILE="$(realpath -m -- "$USER_PROFILE" 2> /dev/null || printf '%s' "$USER_PROFILE")"
    else
      if [[ "$USER_PROFILE" != *".profile" ]]; then
        NATIVE_PROFILE="${USER_PROFILE}.profile"
      else
        NATIVE_PROFILE="$USER_PROFILE"
      fi
    fi
  else
    if [[ -n "$CMD_BASE" ]]; then
      if [[ -f "$REAL_HOME/.config/firejail/${CMD_BASE}.profile" ]]; then
        NATIVE_PROFILE="${CMD_BASE}.profile"
      elif [[ -f "/etc/firejail/${CMD_BASE}.profile" ]]; then
        NATIVE_PROFILE="${CMD_BASE}.profile"
      elif [[ "$CMD_BASE" == "vscodium" ]] && [[ -f "/etc/firejail/codium.profile" ]]; then
        NATIVE_PROFILE="codium.profile"
      elif [[ "$CMD_BASE" == "trae" ]] && [[ -f "/etc/firejail/codium.profile" ]]; then
        NATIVE_PROFILE="codium.profile"
      fi
    fi
  fi

  # --- 7. HARDWARE SPOOFING PROFILE GENERATION ---
  verbose "Generating Firejail profile content..."
  local ETC_LIST
  if [[ -n "$NATIVE_PROFILE" ]]; then
    ETC_LIST="resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies,fonts,ld.so.cache,ld.so.conf,ld.so.conf.d,localtime,nsswitch.conf,passwd,group,asound.conf,pulse"
  else
    ETC_LIST="resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies"
  fi

  local INCLUDE_LINE=""
  if [[ -n "$NATIVE_PROFILE" ]]; then INCLUDE_LINE="include $NATIVE_PROFILE"; fi

  local PROFILE_CONTENT
  PROFILE_CONTENT="$(
                     cat << EOF
# Dynamic Security Profile for Identity: $IDENTITY
${INCLUDE_LINE}

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
private-etc $ETC_LIST

read-only /sbin
read-only /usr/sbin
read-only /bin
read-only /usr/bin
EOF
  )"

  if [[ "$GUI_ENABLED" == true ]]; then
    PROFILE_CONTENT+=$'\nwhitelist /tmp/.X11-unix'
  else
    PROFILE_CONTENT+=$'\nipc-namespace\nnodbus\nnosound\nno3d'
  fi

  # --- 8. DRY-RUN MODE ---
  if [[ "$DRY_RUN" == true ]]; then
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
    printf '%.0s-' {1..56}
                            printf '\n'
    printf '%s\n' "$PROFILE_CONTENT"
    printf '%.0s-' {1..56}
                            printf '\n'
    log "Proposed Whitelist Mounts:"
    log "  Identity root: $IDENTITY_ROOT"
    log "  Working dir:   $TARGET_DIR"
    if [[ "$CMD_PATH" == "$REAL_HOME"* ]]; then log "  Command path:  $CMD_PATH"; fi
    if [[ -n "$WHITELIST_INPUT" ]]; then
      local IFS=','
      local wl_items
      read -ra wl_items <<< "$WHITELIST_INPUT"
      local item
      for item in "${wl_items[@]}"; do
        log "  User whitelist: $item"
      done
    fi
    exit 0
  fi

  # --- 9. DIRECTORY & CONFIGURATION CREATION ---
  verbose "Creating state and configuration directories..."
  mkdir -p -- "$HOME_DIR" "$CONFIG_DIR"

  verbose "Creating secure session configuration files..."
  DNS_PROXY_PY="$(mktemp "$CONFIG_DIR/dns_proxy_XXXXXX.py")"
  PROFILE_PATH="$(mktemp "$CONFIG_DIR/sandbox_XXXXXX.profile")"

  printf '%s\n' "$PROFILE_CONTENT" > "$PROFILE_PATH"

  verbose "Writing DNS UDP-to-TCP translator script..."
  cat << PYEOF > "$DNS_PROXY_PY"
import socket, sys, os

DNS_SERVER = "$DNS_SERVER"

def log_err(msg):
    print(f"[dns-proxy] {msg}", file=sys.stderr, flush=True)

def forward_dns():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_sock.bind(('127.0.0.1', 53))
    except Exception as e:
        log_err(f"Failed to bind UDP port 53: {e}")
        sys.exit(1)
    udp_sock.settimeout(1.0)
    while True:
        try:
            data, addr = udp_sock.recvfrom(512)
            if not data:
                continue
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
                    continue
                resp_len = (resp_len_buf[0] << 8) + resp_len_buf[1]
                resp_data = b''
                while len(resp_data) < resp_len:
                    chunk = tcp_sock.recv(resp_len - len(resp_data))
                    if not chunk:
                        break
                    resp_data += chunk
                if len(resp_data) == resp_len:
                    udp_sock.sendto(resp_data, addr)
                else:
                    log_err(f"Truncated DNS response: got {len(resp_data)}/{resp_len} bytes")
            except Exception as e:
                log_err(f"Upstream query failed: {e}")
            finally:
                tcp_sock.close()
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_err(f"Unexpected error: {e}")

if __name__ == '__main__':
    forward_dns()
PYEOF

  # --- 10. NETWORK NAMESPACE SETUP ---
  log "Initializing hardware-spoofed network for identity [$IDENTITY]..."

  # Pre-flight: clean up stale namespace/veth from a previous crashed run
  sudo ip netns delete -- "$NS_NAME" 2> /dev/null || true
  sudo ip link delete -- "$VETH_HOST" 2> /dev/null || true

  verbose "Adding network namespace: $NS_NAME"
  sudo ip netns add -- "$NS_NAME"
  NS_CREATED=true

  verbose "Adding veth pair: $VETH_HOST <-> $VETH_NS"
  sudo ip link add -- "$VETH_HOST" type veth peer name "$VETH_NS"
  VETH_CREATED=true

  verbose "Moving $VETH_NS to namespace $NS_NAME"
  sudo ip link set -- "$VETH_NS" netns "$NS_NAME"

  verbose "Setting spoofed MAC address $MAC_ADDR on $VETH_NS"
  sudo ip netns exec "$NS_NAME" ip link set dev "$VETH_NS" address "$MAC_ADDR"

  verbose "Configuring host veth address $PROXY_IP/24 and bringing link UP"
  sudo ip addr add -- "$PROXY_IP/24" dev "$VETH_HOST"
  sudo ip link set -- "$VETH_HOST" up

  verbose "Configuring namespace veth address $NS_IP/24 and bringing links UP"
  sudo ip netns exec "$NS_NAME" ip addr add -- "$NS_IP/24" dev "$VETH_NS"
  sudo ip netns exec "$NS_NAME" ip link set -- "$VETH_NS" up
  sudo ip netns exec "$NS_NAME" ip link set -- lo up

  verbose "Adding tun0 interface inside namespace"
  sudo ip netns exec "$NS_NAME" ip tuntap add dev tun0 mode tun
  sudo ip netns exec "$NS_NAME" ip link set -- tun0 up
  sudo ip netns exec "$NS_NAME" ip route add default dev tun0

  verbose "Starting socat proxy redirector on port $SOCKS_PORT..."
  socat TCP-LISTEN:"$SOCKS_PORT",bind="$PROXY_IP",fork,reuseaddr TCP:127.0.0.1:"$SOCKS_PORT" > /dev/null 2>&1 &
  SOCAT_PID=$!

  verbose "Starting tun2socks inside network namespace..."
  sudo ip netns exec "$NS_NAME" tun2socks -device tun0 -proxy "$SOCKS_PROXY" > /dev/null 2>&1 &
  TUN_PID=$!

  verbose "Synchronizing network interface and proxy connectivity..."
  local max_attempts=50
  local attempt=0
  local tun_up=false
  local proxy_up=false
  while ((attempt < max_attempts)); do
    if [[ "$tun_up" == false ]]; then
      if sudo ip netns exec "$NS_NAME" ip link show tun0 2> /dev/null | grep -q -E "state UP|UP,LOWER_UP"; then
        tun_up=true
        verbose "Network interface tun0 is UP in namespace."
      fi
    fi
    if [[ "$proxy_up" == false ]]; then
      if (echo > /dev/tcp/"$PROXY_IP"/"$SOCKS_PORT") 2> /dev/null; then
        proxy_up=true
        verbose "Proxy port $SOCKS_PORT is reachable on host side."
      fi
    fi
    if [[ "$tun_up" == true ]] && [[ "$proxy_up" == true ]]; then break; fi
    sleep 0.1
    ((attempt++)) || true
  done
  if [[ "$tun_up" == true ]] && [[ "$proxy_up" == true ]]; then :; else
    error "Failed to synchronize network interface (tun0) or proxy port ($SOCKS_PORT)."
  fi

  verbose "Starting DNS proxy python script..."
  sudo ip netns exec "$NS_NAME" python3 -- "$DNS_PROXY_PY" > /dev/null 2>&1 &
  DNS_PID=$!

  # --- 11. SMART WHITELISTING & SYMLINKING ---
  verbose "Configuring whitelisting..."
  local WHITELIST_ARGS=()

  WHITELIST_ARGS+=("--whitelist=$IDENTITY_ROOT")

  add_whitelist_mount "$TARGET_DIR"

  if [[ "$CMD_PATH" == "$REAL_HOME"* ]]; then add_whitelist_mount "$CMD_PATH"; fi

  if [[ -n "$WHITELIST_INPUT" ]]; then
    local saved_ifs="$IFS"
    IFS=','
    read -ra wl_entries <<< "$WHITELIST_INPUT"
    IFS="$saved_ifs"
    local dir abs_dir
    for dir in "${wl_entries[@]}"; do
      if [[ "$dir" == \~/* ]]; then
        abs_dir="$REAL_HOME/${dir#~/}"
      elif [[ "$dir" == "~" ]]; then
        abs_dir="$REAL_HOME"
      else
        abs_dir="$(realpath -m -- "$dir" 2> /dev/null || printf '%s' "$dir")"
      fi
      add_whitelist_mount "$abs_dir"
    done
  fi

  # --- 12. EXECUTE WITH IDENTITY ---
  log "--------------------------------------------------------"
  log "Identity:        $IDENTITY"
  log "Spoofed MAC:     $MAC_ADDR"
  log "Machine ID:      Spoofed (Random)"
  log "Namespace:       $NS_NAME"
  log "State Directory: $HOME_DIR"
  if ((TIMEOUT > 0)); then log "Timeout:         ${TIMEOUT}s"; fi
  log "--------------------------------------------------------"

  local TERM_VALUE="${TERM:-xterm-256color}"
  if [[ "$TERM_VALUE" == "dumb" ]]; then TERM_VALUE="xterm-256color"; fi

  local ENV_ARGS=(
    "HOME=$HOME_DIR"
    "XDG_CONFIG_HOME=$HOME_DIR/.config"
    "XDG_DATA_HOME=$HOME_DIR/.local/share"
    "XDG_STATE_HOME=$HOME_DIR/.local/state"
    "XDG_CACHE_HOME=$HOME_DIR/.cache"
    "TERM=$TERM_VALUE"
    "COLORTERM=${COLORTERM:-truecolor}"
    "LANG=${LANG:-en_US.UTF-8}"
    "USER=user"
    "LOGNAME=user"
    "SHELL=/bin/bash"
    "PATH=$REAL_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
  )

  if [[ -n "${TERM_PROGRAM:-}" ]]; then ENV_ARGS+=("TERM_PROGRAM=$TERM_PROGRAM"); fi
  if [[ -n "${VTE_VERSION:-}" ]]; then ENV_ARGS+=("VTE_VERSION=$VTE_VERSION"); fi

  if [[ "$GUI_ENABLED" == true ]]; then
    if [[ -n "${DISPLAY:-}" ]]; then ENV_ARGS+=("DISPLAY=$DISPLAY"); fi
    if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then ENV_ARGS+=("WAYLAND_DISPLAY=$WAYLAND_DISPLAY"); fi
    if [[ -n "${XAUTHORITY:-}" ]]; then
      ENV_ARGS+=("XAUTHORITY=$XAUTHORITY")
      WHITELIST_ARGS+=("--whitelist=$XAUTHORITY")
    fi
    if [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then ENV_ARGS+=("XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"); fi
  fi

  local TIMEOUT_ARGS=()
  if ((TIMEOUT > 0)); then TIMEOUT_ARGS=(timeout --signal=TERM --kill-after=5 "$TIMEOUT"); fi

  verbose "Running firejail within namespace $NS_NAME..."
  sudo ip netns exec "$NS_NAME" sudo -u "$REAL_USER" env -i \
    "${ENV_ARGS[@]}" \
    "${TIMEOUT_ARGS[@]}" \
    firejail \
    --profile="$PROFILE_PATH" \
    "${WHITELIST_ARGS[@]}" \
    --private-cwd="$TARGET_DIR" \
    -- "${COMMAND_ARGS[@]}"
}

main "$@"
