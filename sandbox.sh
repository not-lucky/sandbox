#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_NAME

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
error() {
    log "ERROR: $*" >&2
    exit 1
}

# ==============================================================================
# UNIFIED IDENTITY-BASED SECURE WORKSPACE MANAGER (ARCH SAFE)
# ==============================================================================
# Engineered for AI Agents & IDEs (Cursor, Trae, QoderCLI).
# Provides complete network isolation, persistent hardware spoofing (MAC/UUID),
# and dedicated identity state folders to prevent account cross-contamination.
# ==============================================================================

if [ "${EUID:-}" -eq 0 ]; then
    error "Please run this script as a normal user, not root."
fi

readonly REAL_USER="${USER:-}"
readonly REAL_HOME="${HOME:-}"

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
  --gui                    Enable GUI support (X11 & Wayland forwarding)
  -h, --help               Show this help menu

Examples:
  # Launch Trae as 'Account 1' (Persistent login, spoofed hardware):
  $SCRIPT_NAME -i trae-acc1 --gui -w ~/.agents -- /usr/share/trae/trae --no-sandbox

  # Run a CLI agent with isolated persistent state:
  $SCRIPT_NAME -i qoder_astral -w ~/.agents -- qodercli
=================================================================
EOF
    exit 0
}

main() {
    # --- 1. PARSE ARGUMENTS ---
    local IDENTITY="default-identity"
    local WHITELIST_INPUT=""
    local SOCKS_PORT="10808"
    local USER_PROFILE=""
    local GUI_ENABLED=false

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            -i | --identity)
                IDENTITY="$2"
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
            --gui)
                GUI_ENABLED=true
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

    local COMMAND_ARGS=("$@")

    if [ ${#COMMAND_ARGS[@]} -eq 0 ]; then
        error "No command specified to run."
    fi

    IDENTITY=$(echo "$IDENTITY" | tr -cd 'a-zA-Z0-9_-')

    # --- 2. GENERATE DETERMINISTIC HARDWARE SPOOFING ---
    local HASH
    HASH=$(echo -n "$IDENTITY" | md5sum | awk '{print $1}')
    local SESSION_HASH=${HASH:0:6}

    # Generate a valid, persistent MAC Address
    local MAC_ADDR="02:${HASH:2:2}:${HASH:4:2}:${HASH:6:2}:${HASH:8:2}:${HASH:10:2}"

    # Network Params
    local NS_NAME="ns-$SESSION_HASH"
    local VETH_HOST="vh-$SESSION_HASH"
    local VETH_NS="vn-$SESSION_HASH"
    # Using 16# to ensure base16
    local OCTET=$((1 + 16#${HASH:0:2} % 254))
    local PROXY_IP="10.250.$OCTET.1"
    local NS_IP="10.250.$OCTET.2"
    local SOCKS_PROXY="socks5://$PROXY_IP:$SOCKS_PORT"

    local TARGET_DIR
    TARGET_DIR=$(pwd)

    # --- 3. CONFIGURE PERSISTENT IDENTITY DIRECTORIES ---
    local IDENTITY_ROOT="$REAL_HOME/.sandbox_identities/$IDENTITY"
    local HOME_DIR="$IDENTITY_ROOT/home"

    mkdir -p "$HOME_DIR"

    # --- 4. PREREQUISITES & CLEANUP ---
    for cmd in firejail socat tun2socks ip python3; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            error "System dependency '$cmd' is missing."
        fi
    done

    # Global PID variables for cleanup
    TUN_PID=""
    SOCAT_PID=""
    DNS_PID=""
    PROFILE_PATH=""
    DNS_PROXY_PY=""

    cleanup() {
        log "Saving state and cleaning up identity [$IDENTITY]..."
        [ -n "${TUN_PID:-}" ] && sudo kill "$TUN_PID" 2> /dev/null || true
        [ -n "${SOCAT_PID:-}" ] && kill "$SOCAT_PID" 2> /dev/null || true
        [ -n "${DNS_PID:-}" ] && kill "$DNS_PID" 2> /dev/null || true
        sudo ip netns delete "$NS_NAME" 2> /dev/null || true
        sudo ip link delete "$VETH_HOST" 2> /dev/null || true
        [ -n "${PROFILE_PATH:-}" ] && rm -f "$PROFILE_PATH" || true
        [ -n "${DNS_PROXY_PY:-}" ] && rm -f "$DNS_PROXY_PY" || true
        log "Cleanup complete."
    }
    trap cleanup EXIT ERR INT TERM

    # --- 5. NETWORK NAMESPACE SETTINGS ---
    log "Initializing hardware-spoofed network for identity [$IDENTITY]..."
    sudo ip netns add "$NS_NAME"
    sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
    sudo ip link set "$VETH_NS" netns "$NS_NAME"

    # Apply the persistent spoofed MAC address to the sandbox interface
    sudo ip netns exec "$NS_NAME" ip link set dev "$VETH_NS" address "$MAC_ADDR"

    sudo ip addr add "$PROXY_IP/24" dev "$VETH_HOST"
    sudo ip link set "$VETH_HOST" up

    sudo ip netns exec "$NS_NAME" ip addr add "$NS_IP/24" dev "$VETH_NS"
    sudo ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
    sudo ip netns exec "$NS_NAME" ip link set lo up

    sudo ip netns exec "$NS_NAME" ip tuntap add dev tun0 mode tun
    sudo ip netns exec "$NS_NAME" ip link set tun0 up
    sudo ip netns exec "$NS_NAME" ip route add default dev tun0

    socat TCP-LISTEN:"$SOCKS_PORT",bind="$PROXY_IP",fork,reuseaddr TCP:127.0.0.1:"$SOCKS_PORT" > /dev/null 2>&1 &
    SOCAT_PID=$!

    sudo ip netns exec "$NS_NAME" tun2socks -device tun0 -proxy "$SOCKS_PROXY" > /dev/null 2>&1 &
    TUN_PID=$!
    sleep 1.2

    # --- 5.5 INLINE DNS UDP-TO-TCP RESOLUTION DAEMON ---
    DNS_PROXY_PY="/tmp/fj_dns_proxy_$SESSION_HASH.py"
    cat << 'EOF' > "$DNS_PROXY_PY"
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
                tcp_sock.connect(('1.1.1.1', 53))
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
    sudo ip netns exec "$NS_NAME" python3 "$DNS_PROXY_PY" > /dev/null 2>&1 &
    DNS_PID=$!

    # --- 6. SMART WHITELISTING & SYMLINKING ---
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
    local CMD_NAME="${COMMAND_ARGS[0]}"
    local CMD_PATH
    CMD_PATH=$(command -v "$CMD_NAME" 2> /dev/null || realpath "$CMD_NAME" 2> /dev/null || echo "$CMD_NAME")
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

    # --- 6.5 NATIVE PROFILE RESOLUTION ---
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
    PROFILE_PATH="/tmp/fj_sandbox_$SESSION_HASH.profile"
    echo "# Dynamic Security Profile for Identity: $IDENTITY" > "$PROFILE_PATH"

    local ETC_LIST=""
    if [ -n "$NATIVE_PROFILE" ]; then
        echo "include $NATIVE_PROFILE" >> "$PROFILE_PATH"
        ETC_LIST="resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies,fonts,ld.so.cache,ld.so.conf,ld.so.conf.d,localtime,nsswitch.conf,passwd,group,asound.conf,pulse"
    else
        ETC_LIST="resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies"
    fi

    cat << EOF >> "$PROFILE_PATH"
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

    if [ "$GUI_ENABLED" = true ]; then
        echo "whitelist /tmp/.X11-unix" >> "$PROFILE_PATH"
    else
        cat << EOF >> "$PROFILE_PATH"
ipc-namespace
nodbus
nosound
no3d
EOF
    fi

    # --- 8. EXECUTE WITH IDENTITY ---
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

    sudo ip netns exec "$NS_NAME" sudo -u "$REAL_USER" env -i \
        "${ENV_ARGS[@]}" \
        firejail \
        --profile="$PROFILE_PATH" \
        "${WHITELIST_ARGS[@]}" \
        --private-cwd="$TARGET_DIR" \
        "${COMMAND_ARGS[@]}"
}

main "$@"
