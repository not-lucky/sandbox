# CloakID

**CloakID** (formerly known as Sandbox) is a unified, identity-based secure workspace manager engineered natively in Go. It is designed to provide complete network isolation, persistent hardware spoofing, and dedicated state folders to prevent account cross-contamination. 

This makes it an ideal tool for running AI Agents (like Cursor, Trae, QoderCLI) and browsers seamlessly across multiple distinct "identities" without the risk of browser fingerprinting, cache spillage, or network leakages linking the identities together.

## Key Features

*   **Identity-Based Sandboxing:** Every named identity gets its own persistent, completely isolated `~/.cloakid_identities/<identity>/home` state directory. Caches, logins, extensions, and histories survive restarts but never interact with your host home directory.
*   **Hardware Spoofing & Fingerprint Evasion:** Each identity deterministically hashes into a unique, persistent MAC Address and Machine UUID. 
*   **Network Namespace Isolation:** The application cannot see your host network, VPNs, or local LAN devices. All networking is strictly contained within a dedicated Linux Network Namespace (`ns-<hash>`).
*   **Forced Proxification (`tun2socks`):** Inside the namespace, a TUN interface routes 100% of the TCP and UDP traffic strictly to a designated SOCKS5 proxy on your host. There is no route to the raw internet, preventing IP leaks entirely.
*   **Native DNS Proxying:** Intercepts UDP DNS queries (`127.0.0.1:53`) from the sandboxed application and losslessly bridges them over TCP to your upstream DNS provider through the SOCKS5 proxy, preventing UDP DNS leaks.
*   **Application Sandboxing (`firejail`):** When enabled, leverages Firejail to completely lock down the filesystem, blocking access to `/sys/class/dmi` and `/sys/devices/virtual/dmi` to defeat hardware-level telemetry and PC fingerprinting (especially prevalent in Electron-based IDEs).
*   **Electron Aware:** Automatically detects Electron apps (`trae`, `cursor`, `vscodium`, `code`, `obsidian`) and adjusts the internal sandbox zygote boundaries to run safely inside the Firejail environment.

## Prerequisites

CloakID relies on several Linux-specific tools to build the isolation layers. Ensure you have the following installed on your host system:

*   `iproute2` (for `ip netns` and interface management)
*   `firejail` (for filesystem isolation)
*   `socat` (for bridging the host SOCKS proxy)
*   `tun2socks` (for routing namespace traffic into the proxy)
*   `sudo` access for the executing user (CloakID invokes `sudo ip netns ...` dynamically).

## Installation

You can compile and install CloakID directly using the included Makefile:

```bash
git clone <repository_url> cloakid
cd cloakid
make build
sudo make install
```

This places the `cloakid` binary into `/usr/local/bin`.

## Configuration

CloakID uses a YAML configuration file. It looks for the file in the following order:
1. `$XDG_CONFIG_HOME/cloakid/config.yaml`
2. `~/.cloakidrc`

**Example Configuration (`~/.cloakidrc`):**
```yaml
default_identity: "my-work-profile"
default_dns: "1.1.1.1"
default_socks_port: 10808
default_timeout: 0
verbose: false
no_sandbox: false
```

You can view your active configuration by running:
```bash
cloakid config
```

## Usage

CloakID operates using a subcommand structure (via Cobra).

### Running Applications

The primary command is `cloakid run`. It requires an identity name and the command you wish to execute.

```bash
cloakid run [options] -- <command> [args...]
```

**Examples:**

*   **Launch a CLI tool under a specific identity:**
    ```bash
    cloakid run -i project_alpha -- curl ipinfo.io
    ```
*   **Launch an IDE with specific host folders whitelisted:**
    ```bash
    cloakid run -i trae-account-2 -w ~/my_projects/frontend -- /usr/bin/trae
    ```
*   **Specify a custom SOCKS5 proxy port (default is 10808):**
    ```bash
    cloakid run -i browsing -p 9050 -- firefox
    ```
*   **Run without Firejail (Network Namespace isolation ONLY):**
    ```bash
    cloakid run -i trusted-tools --no-sandbox -- git push origin master
    ```

**Available Flags for `run`:**
*   `-i, --identity <name>`: The unique identity name.
*   `-w, --whitelist <paths>`: Comma-separated list of host files/directories to expose to the sandbox. Note: The current working directory is whitelisted automatically.
*   `-p, --port <number>`: SOCKS5 proxy port running on the host.
*   `-f, --profile <name>`: Override the default Firejail profile.
*   `-d, --dns <ip>`: Upstream DNS resolver IP.
*   `-t, --timeout <seconds>`: Automatically kill the sandbox after N seconds.
*   `-n, --no-sandbox`: Disable Firejail filesystem isolation (faster, but less secure; only network is isolated).
*   `--dry-run`: Simulation mode that prints the proposed configurations (namespace topology, firejail profile, whitelists) without executing any alterations.

### Managing Identities

CloakID keeps all state for an identity in `~/.cloakid_identities/<identity>`. You can manage these directly using the CLI:

*   **List all existing identities:**
    ```bash
    cloakid list
    ```
    *Note: When run with the global `--verbose` flag, it calculates and displays the size of each identity's state.*
*   **Check running sandbox instances:**
    ```bash
    cloakid status
    ```
    *Note: Displays running CPU/Memory metrics and namespace mappings. With the global `--verbose` flag, it also lists interface RX/TX traffic details.*
*   **Stop a running instance forcefully:**
    ```bash
    cloakid stop <identity>
    ```
*   **Delete an identity (Wipes all state/caches/history):**
    ```bash
    cloakid delete <identity> [--force]
    ```
    *Note: Prompts for confirmation before wiping data unless `--force` or `-f` is supplied.*
*   **Export an identity to a tarball archive (Great for backups):**
    ```bash
    cloakid export <identity>
    ```
*   **Import an identity from a tarball:**
    ```bash
    cloakid import <archive.tar.gz> [new_name]
    ```
    *Note: You can optionally provide a second argument to rename the identity on import.*
*   **Clone an existing identity's state to a new name:**
    ```bash
    cloakid clone <source_identity> <target_identity>
    ```

### Managing Command Aliases / Shortcuts

You can save long, complex `cloakid` commands as short aliases so you don't have to type out the whole command every time:

*   **Add an alias:**
    ```bash
    cloakid alias add <alias_name> <command_args...>
    ```
    *Example:*
    ```bash
    cloakid alias add mullvad run -i my-identity -w ~/.agents,~/.skills -f mullvad-browser -- /opt/mullvad-browser/mullvadbrowser --no-sandbox
    ```
*   **Run a saved alias:**
    Simply call the alias name directly:
    ```bash
    cloakid <alias_name>
    ```
    *Example:*
    ```bash
    cloakid mullvad
    ```
*   **List all saved aliases:**
    ```bash
    cloakid alias list
    ```
*   **Remove an alias:**
    ```bash
    cloakid alias remove <alias_name>
    ```

### Maintenance

If an application crashes violently or the host machine loses power, you may be left with stale network namespaces or `veth` interfaces. You can easily wipe all lingering network state:

```bash
cloakid cleanup
```

## Architecture Details

When you run `cloakid run -i "AccountA" -- firefox`:

1.  **Deterministic Hashing:** CloakID hashes "AccountA" to derive `ns-a2b4c6`.
2.  **Namespace Creation:** It runs `ip netns add ns-a2b4c6`.
3.  **Veth Pairs:** It creates a veth pair, moving one end into the namespace and assigning it a deterministic MAC address derived from the hash.
4.  **Routing:** It spawns `socat` on the host side of the veth, mapping it to your local SOCKS5 proxy. Inside the namespace, it spawns `tun2socks`, routing `tun0` out the veth and into `socat`.
5.  **DNS Proxy:** A lightweight native Go DNS server spins up, intercepting UDP 53 and wrapping it into TCP 53 to survive the SOCKS5 proxy boundary.
6.  **Firejail Sandbox:** Firejail is launched inside the namespace, mounting the fake home directory `~/.cloakid_identities/AccountA/home` and executing `firefox`.

This ensures that Firefox running as "AccountA" has zero visibility into Firefox running as "AccountB", even down to the kernel MAC address level.
