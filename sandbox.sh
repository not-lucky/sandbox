#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_NAME

# ==============================================================================
# UNIFIED IDENTITY-BASED SECURE WORKSPACE MANAGER (ARCH SAFE)
# ==============================================================================
# Engineered for AI Agents & IDEs (Cursor, Trae, QoderCLI).
# Provides complete network isolation, persistent hardware spoofing (MAC/UUID),
# and dedicated identity state folders to prevent account cross-contamination.
# ==============================================================================

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

# Global Flags / Configs
VERBOSE_ENABLED=false
TRACE_ENABLED=false
DRY_RUN=false
DNS_SERVER="1.1.1.1"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
verbose() {
    if [ "$VERBOSE_ENABLED" = true ]; then
        log "DEBUG: $*"
    fi
}
error() {
    log "ERROR: $*" >&2
    exit 1
}

cleanup() {
    if [ "$NS_CREATED" = true ] || [ "$VETH_CREATED" = true ] || [ -n "${TUN_PID:-}" ] || [ -n "${PROFILE_PATH:-}" ]; then
        if [ -n "${IDENTITY:-}" ]; then
            log "Saving state and cleaning up identity [$IDENTITY]..."
        else
            log "Saving state and cleaning up sandbox resources..."
        fi
    fi
    [ -n "${TUN_PID:-}" ] && sudo kill "$TUN_PID" 2> /dev/null || true
    [ -n "${SOCAT_PID:-}" ] && kill "$SOCAT_PID" 2> /dev/null || true
    [ -n "${DNS_PID:-}" ] && kill "$DNS_PID" 2> /dev/null || true
    [ "$NS_CREATED" = true ] && [ -n "${NS_NAME:-}" ] && sudo ip netns delete "$NS_NAME" 2> /dev/null || true
    [ "$VETH_CREATED" = true ] && [ -n "${VETH_HOST:-}" ] && sudo ip link delete "$VETH_HOST" 2> /dev/null || true
    [ -n "${PROFILE_PATH:-}" ] && rm -f "$PROFILE_PATH" || true
    [ -n "${DNS_PROXY_PY:-}" ] && rm -f "$DNS_PROXY_PY" || true
    if [ "$NS_CREATED" = true ] || [ "$VETH_CREATED" = true ] || [ -n "${TUN_PID:-}" ] || [ -n "${PROFILE_PATH:-}" ]; then
        log "Cleanup complete."
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

    if command -v apt-get >/dev/null 2>&1; then
        log "To install missing dependencies, run: sudo apt-get update && sudo apt-get install -y ${pkgs[*]}"
    elif command -v dnf >/dev/null 2>&1; then
        log "To install missing dependencies, run: sudo dnf install -y ${pkgs[*]}"
    elif command -v pacman >/dev/null 2>&1; then
        log "To install missing dependencies, run: sudo pacman -S --noconfirm ${pkgs[*]}"
    elif command -v zypper >/dev/null 2>&1; then
        log "To install missing dependencies, run: sudo zypper install -y ${pkgs[*]}"
    elif command -v apk >/dev/null 2>&1; then
        log "To install missing dependencies, run: sudo apk add ${pkgs[*]}"
    else
        log "Please install the following packages using your system package manager: ${pkgs[*]}"
    fi
}

show_help() {
    cat << EOF
=================================================================
    Identity-Based Secure Workspace Manager
=================================================================
Usage: $SCRIPT_NAME [options] -- <command> [arguments...]

Options:
  -i, --identity <name>    Unique identity name (Creates persistent hardware spoof & home)
  -w, --whitelist <paths>  Comma-separated list of host files/dirs to expose
  -p, --port <number>      Host SOCKS5 proxy port (Default: 10808)
  -f, --profile <name>     Explicitly use/override pre-existing Firejail profile
  -d, --dns <ip>           Upstream DNS resolver IP (Default: 1.1.1.1)
  --gui                    Enable GUI support (X11 & Wayland forwarding)
  --verbose                Enable detailed step-by-step logging
  --trace                  Enable shell tracing (set -x) for debugging
  --dry-run                Show proposed topology and profile without altering system
  -h, --help               Show help menu

Examples:
  # Launch Trae as 'Account 1' (Persistent login, spoofed hardware):
  $SCRIPT_NAME -i trae-acc1 --gui -w ~/.agents -- /usr/share/trae/trae --no-sandbox

  # Run a CLI agent with isolated persistent state:
  $SCRIPT_NAME -i qoder_astral -w ~/.agents -- qodercli
=================================================================
EOF
    exit 0
}

# Real user information
if [ "${EUID:-}" -eq 0 ]; then
    error "Please run this script as a normal user, not root."
fi

readonly REAL_USER="${USER:-}"
readonly REAL_HOME="${HOME:-}"

main() {
    # --- Platform Assertion ---
    verbose "Asserting platform..."
    if [[ "$(uname -s)" != "Linux" ]]; then
        error "This script requires Linux-specific kernel features (network namespaces)."
    fi

    # --- Sudo Pre-flight Check ---
    verbose "Performing sudo pre-flight check..."
    if ! command -v sudo >/dev/null 2>&1; then
        error "sudo command is missing."
    fi
    local sudo_check
    sudo_check=$(sudo -n -l 2>&1 || true)
    if [[ "$sudo_check" == *"not allowed"* || "$sudo_check" == *"not in the sudoers"* ]]; then
        error "Sudo pre-flight check failed: User '$REAL_USER' does not have sudo privileges."
    fi

    # Register trap early
    trap cleanup EXIT ERR INT TERM

    # --- 1. PARSE ARGUMENTS ---
    local IDENTITY_INPUT="default-identity"
    local WHITELIST_INPUT=""
    local SOCKS_PORT="10808"
    local USER_PROFILE=""
    local GUI_ENABLED=false

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            -i | --identity)
                IDENTITY_INPUT="$2"
                shift 2
                ;;
            -w | --whitelist)
                WHITELIST_INPUT="$2"
                shift 2
                ;;
            -p | --port)
                SOCKS_PORT="$2"
                shift 2
                ;;
            -f | --profile)
                USER_PROFILE="$2"
                shift 2
                ;;
            -d | --dns)
                DNS_SERVER="$2"
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
            -h | --help)
                show_help
                ;;
            --)
                shift
                break
                ;;
            *)
                error "Unknown parameter: $1"
                ;;
        esac
    done

    # Enable trace if requested
    if [ "$TRACE_ENABLED" = true ]; then
        set -x
    fi

    local COMMAND_ARGS=("$@")

    if [ ${#COMMAND_ARGS[@]} -eq 0 ]; then
        error "No command specified to run."
    fi

    # --- 2. INPUT VALIDATION ---
    verbose "Validating input parameters..."
    IDENTITY=$(echo "$IDENTITY_INPUT" | tr -cd 'a-zA-Z0-9_-')
    if [ -z "$IDENTITY" ]; then
        error "Identity name is empty or contains only invalid characters after sanitization."
    fi

    if [[ ! "$SOCKS_PORT" =~ ^[0-9]+$ ]] || [ "$SOCKS_PORT" -lt 1 ] || [ "$SOCKS_PORT" -gt 65535 ]; then
        error "Invalid SOCKS proxy port: '$SOCKS_PORT'. Must be an integer between 1 and 65535."
    fi

    if [[ "$DNS_SERVER" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for octet in "${BASH_REMATCH[@]:1}"; do
            if (( octet > 255 )); then
                error "Invalid DNS IP address (octet out of range): $DNS_SERVER"
            fi
        done
    else
        error "Invalid DNS IP address format: $DNS_SERVER"
    fi

    # --- 3. PREREQUISITES CHECK ---
    verbose "Checking system dependencies..."
    local missing=()
    for cmd in firejail socat tun2socks ip python3; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        suggest_install_command "${missing[@]}"
        error "Missing required dependencies: ${missing[*]}"
    fi

    # --- 4. GENERATE DETERMINISTIC HARDWARE SPOOFING ---
    verbose "Generating hardware spoofing parameters..."
    local HASH
    HASH=$(echo -n "$IDENTITY" | md5sum | awk '{print $1}')
    local SESSION_HASH=${HASH:0:6}

    # Generate a valid, persistent MAC Address
    local MAC_ADDR="02:${HASH:2:2}:${HASH:4:2}:${HASH:6:2}:${HASH:8:2}:${HASH:10:2}"

    # Network Params
    NS_NAME="ns-$SESSION_HASH"
    VETH_HOST="vh-$SESSION_HASH"
    local VETH_NS="vn-$SESSION_HASH"
    # Using 16# to ensure base16
    local OCTET=$((1 + 16#${HASH:0:2} % 254))
    local PROXY_IP="10.250.$OCTET.1"
    local NS_IP="10.250.$OCTET.2"
    local SOCKS_PROXY="socks5://$PROXY_IP:$SOCKS_PORT"

    local TARGET_DIR
    TARGET_DIR=$(pwd)

    # --- 5. CONFIGURE PERSISTENT IDENTITY DIRECTORIES ---
    local IDENTITY_ROOT="$REAL_HOME/.sandbox_identities/$IDENTITY"
    local HOME_DIR="$IDENTITY_ROOT/home"
    local CONFIG_DIR="$IDENTITY_ROOT/.sandbox_configs"

    # --- 6. NATIVE PROFILE RESOLUTION ---
    verbose "Resolving Firejail profile..."
    local CMD_NAME="${COMMAND_ARGS[0]}"
    local CMD_PATH
    CMD_PATH=$(command -v "$CMD_NAME" 2> /dev/null || realpath "$CMD_NAME" 2> /dev/null || echo "$CMD_NAME")
    local CMD_BASE
    CMD_BASE=$(basename "$CMD_PATH" 2> /dev/null || echo "$CMD_NAME")
    local NATIVE_PROFILE=""

    if [ -n "$USER_PROFILE" ]; then
        if [[ "$USER_PROFILE" == \~/* ]]; then
            NATIVE_PROFILE="$REAL_HOME/${USER_PROFILE#~/}"
        elif [[ "$USER_PROFILE" == "/"* || "$USER_PROFILE" == "./"* || "$USER_PROFILE" == "../"* ]]; then
            NATIVE_PROFILE=$(realpath -m "$USER_PROFILE" 2> /dev/null || echo "$USER_PROFILE")
        else
            if [[ "$USER_PROFILE" != *".profile" ]]; then
                NATIVE_PROFILE="${USER_PROFILE}.profile"
            else NATIVE_PROFILE="$USER_PROFILE"; fi
        fi
    else
        if [ -n "$CMD_BASE" ]; then
            if [ -f "$REAL_HOME/.config/firejail/${CMD_BASE}.profile" ]; then
                NATIVE_PROFILE="${CMD_BASE}.profile"
            elif [ -f "/etc/firejail/${CMD_BASE}.profile" ]; then
                NATIVE_PROFILE="${CMD_BASE}.profile"
            elif [ "$CMD_BASE" = "vscodium" ] && [ -f "/etc/firejail/codium.profile" ]; then
                NATIVE_PROFILE="codium.profile"
            elif [ "$CMD_BASE" = "trae" ] && [ -f "/etc/firejail/codium.profile" ]; then
                NATIVE_PROFILE="codium.profile"
            fi
        fi
    fi

    # --- 7. HARDWARE SPOOFING PROFILE GENERATION ---
    verbose "Generating Firejail profile content..."
    local ETC_LIST=""
    if [ -n "$NATIVE_PROFILE" ]; then
        ETC_LIST="resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies,fonts,ld.so.cache,ld.so.conf,ld.so.conf.d,localtime,nsswitch.conf,passwd,group,asound.conf,pulse"
    else
        ETC_LIST="resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies"
    fi

    local PROFILE_CONTENT
    PROFILE_CONTENT=$(cat << EOF
# Dynamic Security Profile for Identity: $IDENTITY
$( [ -n "$NATIVE_PROFILE" ] && echo "include $NATIVE_PROFILE" || true )

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
)

    if [ "$GUI_ENABLED" = true ]; then
        PROFILE_CONTENT+=$'\n'$(cat << EOF
whitelist /tmp/.X11-unix
EOF
)
    else
        PROFILE_CONTENT+=$'\n'$(cat << EOF
ipc-namespace
nodbus
nosound
no3d
EOF
)
    fi

    # --- 8. DRY-RUN MODE ---
    if [ "$DRY_RUN" = true ]; then
        log "=== DRY RUN MODE: No system-altering commands will be executed ==="
        log "Proposed Namespace Topology:"
        log "  Namespace Name:      $NS_NAME"
        log "  Veth Host Interface: $VETH_HOST (IP: $PROXY_IP/24)"
        log "  Veth NS Interface:   $VETH_NS (IP: $NS_IP/24, Spoofed MAC: $MAC_ADDR)"
        log "  Tunnel Interface:    tun0 (Route: default)"
        log "  Upstream Proxy:      $SOCKS_PROXY"
        log "  Upstream DNS:        $DNS_SERVER"
        log "  State Home Directory: $HOME_DIR"
        log "Proposed Firejail Profile:"
        echo "--------------------------------------------------------"
        echo "$PROFILE_CONTENT"
        echo "--------------------------------------------------------"
        exit 0
    fi

    # --- 9. DIRECTORY & CONFIGURATION CREATION ---
    verbose "Creating state and configuration directories..."
    mkdir -p "$HOME_DIR"
    mkdir -p "$CONFIG_DIR"

    # Generate secure temporary files under the configuration directory
    verbose "Creating secure session configuration files..."
    DNS_PROXY_PY=$(mktemp "$CONFIG_DIR/dns_proxy_XXXXXX.py")
    PROFILE_PATH=$(mktemp "$CONFIG_DIR/sandbox_XXXXXX.profile")

    # Write the profile file
    echo "$PROFILE_CONTENT" > "$PROFILE_PATH"

    # Write the DNS proxy python script
    verbose "Writing DNS UDP-to-TCP translator script..."
    cat << EOF > "$DNS_PROXY_PY"
import socket, sys
def forward_dns():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: udp_sock.bind(('127.0.0.1', 53))
    except Exception: sys.exit(1)
    udp_sock.settimeout(1.0)
    while True:
        try:
            data, addr = udp_sock.recvfrom(512)
            if not data: continue
            length = len(data)
            tcp_data = bytes([length >> 8, length & 0xFF]) + data
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.settimeout(4.0)
            try:
                tcp_sock.connect(('$DNS_SERVER', 53))
                tcp_sock.sendall(tcp_data)
                resp_len_buf = tcp_sock.recv(2)
                if len(resp_len_buf) < 2: continue
                resp_len = (resp_len_buf[0] << 8) + resp_len_buf[1]
                resp_data = b''
                while len(resp_data) < resp_len:
                    chunk = tcp_sock.recv(resp_len - len(resp_data))
                    if not chunk: break
                    resp_data += chunk
                if len(resp_data) == resp_len:
                    udp_sock.sendto(resp_data, addr)
            except Exception: pass
            finally: tcp_sock.close()
        except socket.timeout: continue
        except KeyboardInterrupt: break
        except Exception: pass
if __name__ == '__main__': forward_dns()
EOF

    # --- 10. NETWORK NAMESPACE SETUP ---
    log "Initializing hardware-spoofed network for identity [$IDENTITY]..."
    verbose "Adding network namespace: $NS_NAME"
    sudo ip netns add "$NS_NAME"
    NS_CREATED=true
    verbose "Adding veth pair: $VETH_HOST <-> $VETH_NS"
    sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
    VETH_CREATED=true
    verbose "Moving $VETH_NS to namespace $NS_NAME"
    sudo ip link set "$VETH_NS" netns "$NS_NAME"

    # Apply the persistent spoofed MAC address to the sandbox interface
    verbose "Setting spoofed MAC address $MAC_ADDR on $VETH_NS"
    sudo ip netns exec "$NS_NAME" ip link set dev "$VETH_NS" address "$MAC_ADDR"

    verbose "Configuring host veth address $PROXY_IP/24 and bringing link UP"
    sudo ip addr add "$PROXY_IP/24" dev "$VETH_HOST"
    sudo ip link set "$VETH_HOST" up

    verbose "Configuring namespace veth address $NS_IP/24 and bringing links UP"
    sudo ip netns exec "$NS_NAME" ip addr add "$NS_IP/24" dev "$VETH_NS"
    sudo ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
    sudo ip netns exec "$NS_NAME" ip link set lo up

    verbose "Adding tun0 interface inside namespace"
    sudo ip netns exec "$NS_NAME" ip tuntap add dev tun0 mode tun
    sudo ip netns exec "$NS_NAME" ip link set tun0 up
    sudo ip netns exec "$NS_NAME" ip route add default dev tun0

    verbose "Starting socat proxy redirector on port $SOCKS_PORT..."
    socat TCP-LISTEN:"$SOCKS_PORT",bind="$PROXY_IP",fork,reuseaddr TCP:127.0.0.1:"$SOCKS_PORT" > /dev/null 2>&1 &
    SOCAT_PID=$!

    verbose "Starting tun2socks inside network namespace..."
    sudo ip netns exec "$NS_NAME" tun2socks -device tun0 -proxy "$SOCKS_PROXY" > /dev/null 2>&1 &
    TUN_PID=$!

    # Active synchronization check
    verbose "Synchronizing network interface and proxy connectivity..."
    local max_attempts=50 # 5 seconds max (50 * 0.1s)
    local attempt=0
    local tun_up=false
    local proxy_up=false
    while [ "$attempt" -lt "$max_attempts" ]; do
        if ! $tun_up; then
            if sudo ip netns exec "$NS_NAME" ip link show tun0 2>/dev/null | grep -q -E "state UP|UP,LOWER_UP"; then
                tun_up=true
                verbose "Network interface tun0 is UP in namespace."
            fi
        fi
        if ! $proxy_up; then
            if python3 -c "import socket; s = socket.socket(); s.settimeout(0.1); s.connect(('$PROXY_IP', $SOCKS_PORT)); s.close()" 2>/dev/null; then
                proxy_up=true
                verbose "Proxy port $SOCKS_PORT is reachable on host side."
            fi
        fi
        if $tun_up && $proxy_up; then
            break
        fi
        sleep 0.1
        attempt=$((attempt + 1))
    done
    if ! $tun_up || ! $proxy_up; then
        error "Failed to synchronize network interface (tun0) or proxy port ($SOCKS_PORT)."
    fi

    # Start DNS proxy python server
    verbose "Starting DNS proxy python script..."
    sudo ip netns exec "$NS_NAME" python3 "$DNS_PROXY_PY" > /dev/null 2>&1 &
    DNS_PID=$!

    # --- 11. SMART WHITELISTING & SYMLINKING ---
    verbose "Configuring whitelisting..."
    local WHITELIST_ARGS=()

    # 1. We MUST whitelist the identity root so the sandbox can read/write the persistent configs
    WHITELIST_ARGS+=("--whitelist=$IDENTITY_ROOT")

    add_whitelist_mount() {
        local host_path="$1"
        if [ ! -e "$host_path" ]; then return; fi

        # Whitelist the absolute path so Firejail bind-mounts it into the sandbox
        WHITELIST_ARGS+=("--whitelist=$host_path")

        # If the path is inside the real home directory, create a symlink in the fake home.
        # This ensures that if the IDE looks for $HOME/project, it finds the real whitelisted files.
        if [[ "$host_path" == "$REAL_HOME"* ]]; then
            local rel_path="${host_path#"$REAL_HOME"/}"
            local fake_path="$HOME_DIR/$rel_path"

            if [ "$fake_path" != "$HOME_DIR" ]; then
                mkdir -p "$(dirname "$fake_path")"
                ln -sfn "$host_path" "$fake_path"
            fi
        fi
    }

    # 2. Mount the current working directory so the IDE can open the project
    add_whitelist_mount "$TARGET_DIR"

    # 3. Mount the execution binary if it resides in the home folder (like ~/.local/bin/qodercli)
    if [[ "$CMD_PATH" == "$REAL_HOME"* ]]; then
        add_whitelist_mount "$CMD_PATH"
    fi

    # 4. Mount User-Defined Whitelists (like ~/.agents)
    if [ -n "$WHITELIST_INPUT" ]; then
        IFS=',' read -ra ADDR <<< "$WHITELIST_INPUT"
        for dir in "${ADDR[@]}"; do
            if [[ "$dir" == \~/* ]]; then
                local ABS_DIR="$REAL_HOME/${dir#~/}"
            elif [ "$dir" == "~" ]; then
                local ABS_DIR="$REAL_HOME"
            else
                local ABS_DIR
                ABS_DIR=$(realpath -m "$dir" 2> /dev/null || echo "$dir")
            fi
            add_whitelist_mount "$ABS_DIR"
        done
    fi

    # --- 12. EXECUTE WITH IDENTITY ---
    log "--------------------------------------------------------"
    log "Identity:        $IDENTITY"
    log "Spoofed MAC:     $MAC_ADDR"
    log "State Directory: $HOME_DIR"
    log "--------------------------------------------------------"

    # We trick the application into saving all its configs, logins, and telemetry
    # into our isolated identity folder by aggressively setting the HOME and XDG variables.
    local ENV_ARGS=(
        "HOME=$HOME_DIR"
        "XDG_CONFIG_HOME=$HOME_DIR/.config"
        "XDG_DATA_HOME=$HOME_DIR/.local/share"
        "XDG_STATE_HOME=$HOME_DIR/.local/state"
        "XDG_CACHE_HOME=$HOME_DIR/.cache"
        "TERM=xterm-256color"
        "LANG=en_US.UTF-8"
        "USER=user"
        "LOGNAME=user"
        "SHELL=/bin/bash"
        "PATH=$REAL_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
    )

    if [ "$GUI_ENABLED" = true ]; then
        [ -n "${DISPLAY:-}" ] && ENV_ARGS+=("DISPLAY=$DISPLAY")
        [ -n "${WAYLAND_DISPLAY:-}" ] && ENV_ARGS+=("WAYLAND_DISPLAY=$WAYLAND_DISPLAY")
        [ -n "${XAUTHORITY:-}" ] && ENV_ARGS+=("XAUTHORITY=$XAUTHORITY")
        [ -n "${XDG_RUNTIME_DIR:-}" ] && ENV_ARGS+=("XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR")
    fi

    verbose "Running firejail within namespace $NS_NAME..."
    sudo ip netns exec "$NS_NAME" sudo -u "$REAL_USER" env -i \
        "${ENV_ARGS[@]}" \
        firejail \
        --profile="$PROFILE_PATH" \
        "${WHITELIST_ARGS[@]}" \
        --private-cwd="$TARGET_DIR" \
        "${COMMAND_ARGS[@]}"
}

main "$@"
