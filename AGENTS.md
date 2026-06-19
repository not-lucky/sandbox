# Repository Guidelines

> CloakID — identity-based secure workspace manager. Linux-only.

## Project Overview

CloakID runs any process inside a fully isolated environment composed of three layers: a Linux **network namespace** (`ns-<hash>`), a **veth pair + TUN + tun2socks** chain that forces every TCP/UDP packet through a host-side **SOCKS5 proxy**, and an optional **Firejail** filesystem sandbox. Each named identity (e.g. `accountA`) gets:

- A persistent fake home at `~/.cloakid_identities/<identity>/home` (caches, logins, history survive restarts but never touch the host home).
- A deterministic **spoofed MAC address** and namespace name, both derived from `md5(identity)[:6]`.
- A native **UDP→TCP DNS proxy** on `127.0.0.1:53` inside the namespace so DNS doesn't leak via UDP.

The primary use case is running AI agents (Cursor, Trae, QoderCLI) and browsers across distinct identities with zero cross-contamination (no fingerprint leaks, no cache spillage, no raw-IP egress).

## Architecture & Data Flow

Single binary, single entry point. All orchestration is driven from one place: `sandbox.Manager.Run`.

```
cloakid run -i <identity> -- <cmd> [args...]
        │
        ▼
cli/run.go  ──► sandbox.Manager{ Identity, SocksPort, DNS, ... }
                       │
                       ├─ identity.EnsureDirs(<identity>)
                       │       ~/.cloakid_identities/<identity>/{home,.cloakid_configs,.cloakid.pid}
                       │
                       ├─ netns.GenerateHardwareConfig(identity, port)
                       │       HardwareConfig{ NSName="ns-a2b4c6", VethHost="vh-a2b4c6", ... }
                       │
                       ├─ netns.SetupNetwork(hwCfg)
                       │       sudo ip netns add / veth pair / ip addr / ip tuntap tun0 / default route
                       │
                       ├─ proxy.StartHostSocat    UNIX-LISTEN → host SOCKS5
                       ├─ proxy.StartNSSocat      TCP-LISTEN  → UNIX-CONNECT  (must follow host socat)
                       │
                       ├─ parallel: (each gated by spawnAndProbe ~150ms)
                       │     proxy.StartTun2Socks  tun0 → socks5://host:port
                       │     proxy.StartDNSProxy   re-execs `cloakid dns-proxy` inside netns
                       │     proxy.StartPortForwarding per mapping + AutoForwarder goroutine
                       │
                       └─ sandbox.Execute(opts)
                              sudo ip netns exec <ns> sudo -u <user> env -i ...
                              ├─ firejail --deterministic-shutdown --profile=<generated>
                              │   (or raw `env -i <cmd>` if NoSandbox)
                              ├─ electron workaround: appends `--no-sandbox` to known Electron apps
                              │   + relaxed seccomp profile (allows bwrap/clone/unshare)
                              └─ writes .cloakid.pid, waits for exit
                              on exit: removes .cloakid.pid, defers → netns.TeardownNetwork
```

Cleanup path: `stop` / SIGINT / `cleanup` → `netns.TeardownNetwork` (SIGTERM → 500ms → SIGKILL → `ip netns delete` + `ip link delete`).

## Key Directories

| Path | Purpose |
|---|---|
| `cmd/cloakid/main.go` | Entry point — only calls `cli.Execute()`. |
| `internal/cli/` | All Cobra commands: `run`, `list`, `status`, `stop`, `delete`, `clone`, `export`, `import`, `cleanup`, `alias {add,remove,list}`, `dns-proxy` (hidden), `config`. |
| `internal/config/` | YAML config struct + load/save. Path lookup: `$XDG_CONFIG_HOME/cloakid/config.yaml` → `~/.cloakidrc`. |
| `internal/identity/` | Identity naming, MD5 hashing (deterministic MAC/NS names), filesystem paths, PID tracking via `/proc/<pid>/cmdline`. |
| `internal/logging/` | Levelled `Info/Warn/Error/Debug/Fatal` with TTY-aware color; audit log writer with kept-open file handle. |
| `internal/netns/` | `ip netns` / `ip link` invocation, veth + TUN topology, hardware-config derivation. |
| `internal/proxy/` | `socat` bridge helpers, `tun2socks` invocation, UDP→TCP DNS proxy, port forwarding, AutoForwarder goroutine. |
| `internal/sandbox/` | Manager orchestration, Firejail profile generator, command builder, Electron workarounds. |
| `internal/sandbox/manager.go` | The single most important file — read first. |
| `rank_dns.py`, `sing-box_config.py`, `dns_resolvers.txt`, `proxy_links.txt`, `config_gpt.json` | **Operator/dev-only artefacts.** Not referenced by the Go binary. `rank_dns.py` ranks resolvers; `sing-box_config.py` generates sing-box configs from `proxy_links.txt`; the `.txt`/`.json` files contain proxy URLs and are gitignored. |

## Development Commands

```bash
# Build
make build                  # → ./cloakid (entry: cmd/cloakid/main.go)
go build -o cloakid cmd/cloakid/main.go

# Install
sudo make install           # copies to /usr/local/bin/cloakid

# Clean
make clean                  # removes ./cloakid

# Test
go test ./...               # stdlib testing only; no testify, no mocks

# Format / vet
gofmt -l $(git ls-files '*.go')
go vet ./...

# Cross-compile / check
GOOS=linux go build ./...   # project is Linux-only; don't pretend otherwise
```

There is no `make test`, no linter config, no CI workflow under `.github/`, and no Dockerfile.

## Code Conventions & Common Patterns

- **Module path:** `cloakid` (not GitHub-style). Direct deps: `github.com/spf13/cobra v1.10.2`, `gopkg.in/yaml.v3 v3.0.1`. `pflag` and `mousetrap` are indirect.
- **Go version:** `go 1.26.3`.
- **Error handling:** wrap with `fmt.Errorf("...: %w", err)`; print stderr captured from `exec.Cmd` into the error. `cli/root.go` prints errors then `os.Exit(1)`. CLI `RunE` returns errors; `Run` ignores them.
- **External commands:** every privileged operation goes through `os/exec`. There are **no interfaces** abstracting these — they call real binaries (`ip`, `sudo`, `firejail`, `socat`, `tun2socks`, `tar`, `cp`, `ps`, `ss`, `pkill`, `kill`). Tests that touch these are integration-flavored or limited to pure helpers.
- **Deterministic naming:** `identity.Hash(name) = md5(name)[:6]` drives `ns-`, `vh-`, `vn-` prefixes, the `02:` locally-administered MAC, and the `10.250.<octet>.1/2` IPs. Changing this hash breaks every existing identity — never change it lightly.
- **State passing:** the `Manager` struct (`internal/sandbox/manager.go:26`) is a plain value type populated from CLI flags + config. No DI container, no globals across packages except `logging.AuditEnabled` / `logging.CurrentLevel` (intentionally — set once in `initConfig`).
- **Concurrency:** `startProxies` fans out tun2socks + DNS-proxy + port-forwarders in goroutines, first error wins; cleanup is via `processCtx` cancel propagating into `CommandContext`. `AutoForwarder` runs a 500ms-tick reconciler goroutine that maps namespace listening ports → host forwarders. `setupSignalHandler` traps SIGINT/SIGTERM and tears down.
- **Process spawning helper:** `proxy.spawnAndProbe` (`internal/proxy/socat.go`) starts the cmd, waits up to `launchProbe = 150ms`; if the process exits in that window, the captured stderr is reported. Used by `StartDNSProxy`; the same pattern is also inlined in `StartHostSocat` and `StartNSSocat`.
- **PID locking:** per-identity `flock` on `~/.cloakid_identities/<identity>/.lock` (`acquireLock`); stale lock → re-tear the netns and retry. PID file `.cloakid.pid` is used only by `stop` and `status` (and verified by `IsSandboxPID` reading `/proc/<pid>/cmdline` for `firejail`/`cloakid`/`sandbox` substrings).
- **Config layering:** CLI flag > `config.yaml` > built-in default. `run` uses `cmd.Flags().Changed("name")` to detect explicit user override vs config fallback. Don't refactor this away without preserving the precedence.
- **Alias expansion:** happens **before** Cobra parses args (`internal/cli/root.go:36-58`) by rewriting `os.Args`. Aliases are stored as raw `[]string` of args in `Config.Aliases`. `DisableFlagParsing: true` on `alias add` to preserve shell quoting.
- **Electron workaround:** `applyElectronWorkarounds` appends `--no-sandbox` for `trae`, `code`, `vscodium`, `codium`, `cursor`, `obsidian` (only when Firejail is in play). Additionally, `BuildProfileContent` generates a **relaxed seccomp profile** for these apps: uses `seccomp.drop` with an explicit dangerous-syscall blocklist instead of blanket `seccomp`, and omits `nonewprivs`/`noroot`. This allows Electron apps that use `bwrap` (bubblewrap) internally to create namespaces for their extension host and terminal processes, avoiding conflicts with Firejail security blocks. Keep the `electronApps` map in `executor.go` in sync if new Electron-based agents are added.
- **Firefox workaround:** `applyFirefoxWorkarounds` sets `MOZ_DISABLE_CONTENT_SANDBOX=1`, `MOZ_DISABLE_GMP_SANDBOX=1`, `MOZ_DISABLE_RDD_SANDBOX=1`, and `MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1` environment variables for `firefox`, `firefox-esr`, `mullvadbrowser`, `librewolf`, `waterfox` (only when Firejail is in play). This disables Firefox's internal sandbox to prevent `chroot: EPERM` conflicts with Firejail. `BuildProfileContent` also generates a **relaxed seccomp profile** for Firefox apps (same as Electron) since Firefox uses namespaces internally. Keep the `firefoxApps` map in `executor.go` in sync if new Firefox-based browsers are added.
- **DNS fail-over:** `DNSProxy.activeResolver` is updated under `sync.RWMutex`; tests poke it directly via the same lock. Don't drop the lock — there's no other sync.

## Important Files

| File | Why it matters |
|---|---|
| `cmd/cloakid/main.go` | Trivial — just calls `cli.Execute()`. |
| `internal/cli/root.go` | Alias-rewriting pre-pass; `--verbose` and `--audit` flag wiring; `dns-proxy` hidden command for in-namespace DNS server. |
| `internal/sandbox/manager.go` | End-to-end orchestrator. The `Run` method is the single source of truth for sandbox lifecycle. |
| `internal/sandbox/executor.go` | `ExecuteOptions` shape, `applyElectronWorkarounds`, `applyFirefoxWorkarounds`, `buildEnvArgs`, `buildCommandArgs`, `Execute`. **Run `gofmt -w` on this — it was flagged by audit.** |
| `internal/sandbox/firejail.go` | `BuildProfileContent(identity, nativeProfile, cmdName)` generates the runtime profile (hostname, machine-id, `/sys/class/dmi` blocklist, private-etc, read-only bins, X11 whitelist). For Electron and Firefox apps, emits a relaxed seccomp profile allowing bwrap syscalls (Electron) or namespace operations (Firefox). |
| `internal/netns/hardware.go` | `HardwareConfig` derivation. Test in `hardware_test.go` pins the exact hash output (`md5("test")` → `098f6b`). |
| `internal/proxy/dns.go` | UDP→TCP DNS proxy + fallback resolver list. `StartDNSProxy` re-execs the cloakid binary so port 53 binds inside the netns only. |
| `internal/proxy/forward.go` | `PortMapping` parser, `CheckPortConflict` (uses `ss`), `StartPortForwarding`, `AutoForwarder` (500ms polling goroutine). |
| `internal/proxy/socat.go` | `spawnAndProbe` shared helper (start + 150ms probe); `StartHostSocat`, `StartNSSocat` bridge helpers. |
| `internal/identity/identity.go` | `Sanitize` regex `[^a-zA-Z0-9_-]`; `IsSandboxPID` reads `/proc/<pid>/cmdline`. |
| `internal/logging/logger.go` | `LogLevel` constants; audit file kept open; `isTerminal` cached at package init. |
| `internal/config/config.go` | `Config` YAML tags — field renames will silently drop user values. |
| `AUDIT_REPORT.md` | Historical audit from 2026-06-16. Do not regenerate from scratch; treat findings as still relevant unless superseded. |
| `Makefile` | Three targets only: `build`, `install`, `clean`. No test/lint target. |

## Runtime / Tooling Preferences

- **OS:** Linux only. Every code path calls `ip`, `firejail`, `socat`, `tun2socks`, `sudo`, `tar`, `cp`, `ps`, `ss`, `pkill`. No build tags gate this — it's implicit.
- **Required host binaries:** `iproute2` (`ip`), `firejail`, `socat`, `tun2socks`. The executing user must have passwordless `sudo` for `ip netns ...`, `ip link ...`, `sudo -u <user>`, `firejail`, `socat`, and the re-execed cloakid binary.
- **No Go package manager.** Plain `go build`. No `go.mod` replace directives, no `vendor/` directory.
- **Python helpers (`rank_dns.py`, `sing-box_config.py`)** are operator tooling, not part of any CI. Don't try to invoke them from Go.
- **Audit secret files** (`config.json`, `config_gpt.json`, `proxy_links.txt`, `dns_resolvers.txt`) are gitignored. Don't add tests that read them.

## Testing & QA

- **Framework:** stdlib `testing` only. No testify, no gomock, no fuzz tests, no benchmarks.
- **Test inventory** (12 tests across 5 packages):
  - `internal/config/config_test.go` — `TestLoadConfig`, `TestLoadConfigDefaults` (uses `t.TempDir` + `XDG_CONFIG_HOME`).
  - `internal/identity/identity_test.go` — `TestSanitize` (table-driven), `TestHash` (pins `md5("test") → 098f6b`).
  - `internal/netns/hardware_test.go` — `TestGenerateHardwareConfig` (pins every field for `("test", 10808)`).
  - `internal/proxy/dns_test.go` — `TestHandleDNSQuery`, `TestHandleDNSQueryFallback` (real UDP/TCP loopback; **no skip**).
  - `internal/proxy/forward_test.go` — `TestParsePortMappings` (table-driven).
  - `internal/sandbox/executor_test.go` — `TestApplyElectronWorkarounds` (table-driven), `TestBuildEnvArgs`.
  - `internal/sandbox/firejail_test.go` — `TestBuildProfileContent` (substring asserts on generated profile), `TestBuildProfileContentStrictSeccomp` (verifies non-Electron apps get blanket seccomp/nonewprivs/noroot), `TestBuildProfileContentElectronRelaxed` (verifies all Electron apps get `seccomp.drop` without nonewprivs/noroot).
  - `internal/sandbox/manager_test.go` — `TestBuildWhitelist` (smoke test, asserts no panic).
- **Run:** `go test ./...`. The DNS tests open real UDP/TCP loopback sockets; they pass on any Linux/macOS dev box.
- **What is NOT covered:** anything calling `sudo`, `ip`, `firejail`, `socat`, `tar`, `cp` — those are integration scenarios, exercised manually. `Manager.Run` itself has no end-to-end test. Adding such a test requires root + a real `sudo` configuration and is intentionally out of scope.
- **Coverage expectations:** none enforced. Tests target pure helpers (hashing, parsing, profile generation, env-var assembly) and behaviour that can break silently. When you change one of those, update the corresponding test in the same PR.
- **What to verify before yielding a non-trivial change:**
  1. `gofmt -l $(git ls-files '*.go')` reports nothing.
  2. `go vet ./...` is clean.
  3. `go test ./...` passes.
  4. If you touched `internal/sandbox/executor.go`, run `gofmt -w` on it (audit flagged it).
  5. If you changed deterministic-hash logic, update `internal/netns/hardware_test.go` and `internal/identity/identity_test.go` to match.