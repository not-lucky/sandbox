# CloakID Codebase Audit Report

**Date:** 2026-06-16  
**Scope:** Current repository at `/home/lucky/stuff/cloakid`  
**Purpose:** Identify bugs, security risks, optimizations, and maintainability gaps that can be acted upon.  
**Important:** This audit did **not** modify source code. It ran tests, static checks, scans, and source inspection only.

## Executive Summary

CloakID is a small Go CLI with a clear product goal: launch applications inside identity-scoped network namespaces, Firejail profiles, SOCKS proxying, and DNS forwarding. The project builds and the existing tests pass, but the audit found several high-risk issues that should be addressed before broader use or release.

Highest-priority risks:

1. **Secrets are present in the working tree** in ignored proxy config/link files. Treat these credentials as exposed and rotate them.
2. **Destructive identity path bug:** some identity names sanitize to an empty string, which can make commands target the entire identities root.
3. **Unsafe archive import:** `tar -xzf` extraction is not entry-validated and can be abused for path traversal or unexpected writes.
4. **Partial network setup can leave stale namespaces/veths** because `SetupNetwork` has no rollback path.
5. **Signal handling calls `os.Exit`**, bypassing deferred cleanup such as lock release, PID cleanup, and helper process cancellation.
6. **Management commands bypass the identity lock**, allowing `stop`/`delete`/`clone`/`import`/`export` to race with `run`.
7. **Helper processes are not tracked or waited**, so failed startup/cleanup can leave `socat`, `tun2socks`, or DNS proxy processes behind.
8. **CLI/test infrastructure is weak:** `internal/cli` has 0% coverage, total coverage is 19.6%, and there is no CI/lint workflow.

## Severity Rubric

- **Critical:** Immediate data loss, credential exposure, or privilege/escalation risk.
- **High:** Likely correctness/security bug with destructive, stale-state, or isolation impact.
- **Medium:** Important hardening, validation, maintainability, or operational issue.
- **Low:** Cleanup, formatting, docs, dependency freshness, or minor operational polish.

## Findings Summary

| # | Severity | Area | Location | Action |
|---:|---|---|---|---|
| 1 | Critical | Secrets | `config.json`, `config_gpt.json`, `proxy_links.txt` | Rotate/revoke credentials; remove from local workspace/backups; add secret scanning. |
| 2 | Critical | Identity validation | `internal/identity/identity.go`, `internal/cli/delete.go` | Reject empty sanitized identity names and guard destructive commands. |
| 3 | High | Archive import | `internal/cli/import.go` | Replace unsafe `tar` extraction with validated extraction. |
| 4 | High | Config handling | `internal/cli/root.go`, `internal/cli/run.go` | Propagate config load errors and validate required defaults. |
| 5 | High | Network setup | `internal/netns/namespace.go`, `internal/sandbox/manager.go` | Add rollback cleanup and teardown error reporting. |
| 6 | High | Signal handling | `internal/sandbox/manager.go` | Replace `os.Exit` with controlled cancellation and normal defer cleanup. |
| 7 | High | Concurrency/state | `internal/sandbox/manager.go`, `internal/cli/stop.go`, `internal/cli/delete.go` | Use shared identity locks for mutating operations. |
| 8 | High | Process lifecycle | `internal/sandbox/manager.go`, `internal/proxy/*.go` | Track, wait, and stop helper processes explicitly. |
| 9 | High | Testing | `internal/cli/*`, `Makefile` | Add CLI tests, command-runner abstraction, and CI/test targets. |
| 10 | Medium | GUI isolation | `internal/sandbox/executor.go` | Do not pass `XAUTHORITY`/`XDG_RUNTIME_DIR` by default. |
| 11 | Medium | Permissions | `internal/identity/identity.go`, `internal/sandbox/executor.go`, `internal/cli/export.go` | Use `0700`/`0600` permissions for identity state and archives. |
| 12 | Medium | DNS proxy | `internal/proxy/dns.go` | Handle upstreams with ports and IPv6 correctly; add deadlines/rate limits. |
| 13 | Medium | Cleanup safety | `internal/cli/cleanup.go`, `internal/netns/namespace.go` | Make cleanup scoped, error-aware, and process-safe. |
| 14 | Medium | Delete behavior | `internal/cli/delete.go` | Check existence, stop/teardown first, and do not report success for missing identities. |
| 15 | Medium | Whitelist handling | `internal/sandbox/manager.go` | Use boundary-aware path checks and return symlink/mkdir errors. |
| 16 | Medium | Firejail profile injection | `internal/sandbox/profile.go`, `internal/sandbox/firejail.go` | Validate profile values and reject control characters/newlines. |
| 17 | Medium | Electron sandboxing | `internal/sandbox/executor.go` | Do not auto-append `--no-sandbox`; require explicit opt-in. |
| 18 | Low | Formatting | `internal/sandbox/executor.go`, `internal/sandbox/executor_test.go`, `internal/sandbox/manager_test.go` | Run `gofmt`; add `make fmt-check`. |
| 19 | Low | Dependencies | `go.mod`, `go.sum` | Update available indirect dependencies and add `govulncheck`. |
| 20 | Low | Build artifact | `cloakid` binary | Remove generated binary or ensure it is ignored/cleaned. |

## Detailed Findings

### 1. Critical: Hardcoded proxy credentials and links exist in ignored files

**Locations:** `config.json`, `config_gpt.json`, `proxy_links.txt`

The repository contains ignored local files with proxy credentials and subscription links. A scan found multiple VMess UUIDs, Shadowsocks passwords, and proxy links. These files are ignored by `.gitignore`, so a clean `git status --short` can hide their presence.

**Risk:** If these files were ever committed, shared, uploaded, or included in backups, the credentials are exposed. Even locally, plaintext proxy credentials are risky for a privacy/isolation tool.

**Recommended actions:**

- Rotate/revoke all proxy credentials and UUIDs found in these files.
- Remove the plaintext files from the working tree and backups.
- Store proxy credentials in an encrypted local secret store or secret manager.
- Add pre-commit secret scanning, e.g. `gitleaks`, `trufflehog`, or GitHub secret scanning.
- Ensure generated sing-box configs are `0600` and never logged or printed.

**Verification:**

```bash
git check-ignore -v config.json config_gpt.json proxy_links.txt dns_resolvers.txt
gitleaks detect --source .
trufflehog filesystem .
```

### 2. Critical: Empty sanitized identity names can target the identities root

**Locations:** `internal/identity/identity.go`, `internal/cli/delete.go`

`Sanitize()` removes invalid characters and can return an empty string. `GetIdentityPath()` then joins the identities root with an empty component. For example, an identity name containing only invalid characters can resolve to `~/.cloakid_identities/`.

**Risk:** Destructive commands such as `delete` can remove the entire identities root, deleting all identity state.

**Recommended actions:**

- Add `ValidateIdentityName()` or make `Sanitize()` return `(string, error)`.
- Reject empty sanitized names at all CLI boundaries.
- Add regression tests for inputs such as `!!!`, `/`, `..`, whitespace-only names, and collisions.
- Add an existence check before `delete`, `export`, `clone`, `import`, and `stop`.

**Verification:**

```bash
go test ./internal/identity -run TestSanitize -count=1
# Add tests for empty result and destructive path guard.
```

### 3. High: Unsafe archive import can lead to path traversal or unexpected writes

**Location:** `internal/cli/import.go`

The import command uses:

```go
tar -tzf <archive>
tar -xzf <archive> -C <tempDir>
```

No per-entry validation is performed. Malicious archives can use absolute paths, `..`, symlinks, hardlinks, or special files to write outside the intended import directory.

**Risk:** Arbitrary file write if the CLI is run with elevated privileges or imports untrusted archives. Even without privilege escalation, it can corrupt identity state.

**Recommended actions:**

- Replace shell `tar` extraction with Go `archive/tar` plus gzip handling.
- Reject absolute paths, `..` components, symlinks, hardlinks, device nodes, FIFOs, sockets, and paths outside one top-level identity directory.
- Use `os.MkdirTemp(identity.GetIdentitiesRoot(), ".import-*")` with `0700`.
- Sanitize extracted permissions: directories `0700`, files `0600`.
- Atomically rename only after full validation.

**Verification:**

- Add tests with archives containing `../escape`, absolute paths, symlink entries, hardlink entries, and nested valid identity directories.

### 4. High: Config load errors are swallowed and `run` can continue with invalid defaults

**Locations:** `internal/cli/root.go`, `internal/cli/run.go`

`initConfig()` prints config errors but leaves `cfg == nil`. `run` then only uses defaults when `cfg != nil`, so a corrupt/unreadable config can lead to invalid defaults such as `SocksPort == 0` or empty DNS.

**Risk:** Network/proxy setup may proceed with invalid configuration, producing confusing failures or unsafe partial state.

**Recommended actions:**

- Store config load errors in package state and return them from commands that depend on config.
- Validate required runtime defaults before network setup:
  - `SocksPort` must be `1..65535`.
  - DNS must be non-empty and parseable.
  - Identity must be non-empty and valid.
- Add tests for corrupt config and missing config fallback.

**Verification:**

```bash
go test ./internal/cli -run TestRunValidation -count=1
```

### 5. High: Network setup can leave partial namespaces/veths after failure

**Locations:** `internal/netns/namespace.go`, `internal/sandbox/manager.go`

`SetupNetwork()` deletes existing resources, creates the namespace/veth pair, then performs several privileged `ip` commands. If any step fails after `ip netns add`, it returns immediately without cleanup. `Manager.Run()` only defers teardown after `SetupNetwork()` succeeds.

**Risk:** Failed runs can leave partial namespaces, veth interfaces, or routes.

**Recommended actions:**

- Add rollback cleanup inside `SetupNetwork()` on every error path.
- Make `TeardownNetwork()` return `error` or a structured cleanup result.
- Treat initial cleanup errors as warnings only if idempotency is desired, but log/report them.
- Add fake command-runner tests for command ordering and rollback.

### 6. High: Signal handler calls `os.Exit`, bypassing deferred cleanup

**Location:** `internal/sandbox/manager.go`, `setupSignalHandler`

On SIGINT/SIGTERM, the handler calls `cancelProcess()`, `netns.TeardownNetwork(hwCfg)`, then `os.Exit(1)`. `os.Exit` terminates the process without running deferred functions.

**Risk:** Lock file, PID file, context cancellation, and helper process cleanup can be skipped, leaving stale state.

**Recommended actions:**

- Replace manual signal goroutine with `signal.NotifyContext`.
- Cancel the run context and return an error from `Manager.Run`.
- Let Cobra/main print the error and exit after normal defers run.
- Add tests using an injectable signal channel where possible.

### 7. High: Mutating commands bypass identity locks and can race with `run`

**Locations:** `internal/sandbox/manager.go`, `internal/cli/stop.go`, `internal/cli/delete.go`, `internal/cli/clone.go`, `internal/cli/import.go`, `internal/cli/export.go`

Only `run` acquires the identity lock. `stop`, `delete`, `clone`, `import`, and `export` do not.

**Risk:** A concurrent `delete` can remove state while a sandbox is running. `stop` can delete a namespace while setup is in progress. `clone`/`export` can copy inconsistent state.

**Recommended actions:**

- Add a shared identity operation lock helper.
- Acquire the lock for all mutating commands.
- Refuse or stop/teardown before destructive operations.
- Consider a lock timeout with a clear error message.

### 8. High: Helper processes are started but not retained, waited, or explicitly stopped

**Locations:** `internal/sandbox/manager.go`, `internal/proxy/socat.go`, `internal/proxy/tun2socks.go`, `internal/proxy/dns.go`

`startProxies()` discards the `*exec.Cmd` values from `StartSocat()` and `StartTun2Socks()` and starts the DNS proxy without retaining/waiting it. If a later helper fails, earlier helpers may remain running.

**Risk:** Stale `socat`, `tun2socks`, or DNS proxy processes can remain after failed runs or interrupted sessions.

**Recommended actions:**

- Store all helper commands in a process group.
- Wait for helper processes in goroutines and collect errors.
- Stop previously started helpers if a later helper fails.
- Capture stderr for diagnostics.
- Use process groups so context cancellation kills child processes.

### 9. High: CLI package has no tests and relies on global mutable state

**Locations:** `internal/cli/*`, `cmd/cloakid/main.go`, `Makefile`

The public command surface is the highest-change-risk area, but `internal/cli` has 0% test coverage. Globals such as `cfg`, `Verbose`, `runIdentity`, `runSocksPort`, and alias command state make behavior order-dependent.

**Risk:** Bugs in command parsing, config loading, alias expansion, delete/export/import behavior, and default validation can slip through.

**Recommended actions:**

- Introduce an `App` or `CLI` struct that owns config, logger, and command construction.
- Pass resolved config into command handlers instead of reading package globals.
- Add command tests using Cobra command instances and `cmd.SetArgs(...)`.
- Refactor alias expansion into a pure function.
- Add Makefile targets: `test`, `test-race`, `vet`, `fmt-check`, `coverage`.
- Add CI workflow running those targets.

### 10. Medium: GUI/session environment weakens sandbox isolation

**Location:** `internal/sandbox/executor.go`, `buildEnvArgs`

The sandbox passes host GUI/session environment such as `DISPLAY`, `WAYLAND_DISPLAY`, `XAUTHORITY`, and `XDG_RUNTIME_DIR`. If `XAUTHORITY` is present, it also whitelists the X authority file.

**Risk:** A sandboxed GUI app may access the host graphical session, X11/Wayland auth material, and user-session IPC. This weakens the isolation boundary.

**Recommended actions:**

- Do not pass `XAUTHORITY` by default.
- If GUI support is required, generate a scoped temporary Xauthority cookie and revoke it after the session.
- Avoid passing `XDG_RUNTIME_DIR` unless explicitly required; provide an isolated runtime directory instead.
- Document that GUI sandboxing is weaker than non-GUI sandboxing.
- Add a warning when `--no-sandbox` is used.

### 11. Medium: Identity state, PID files, imports, clones, and exports use permissive permissions

**Locations:** `internal/identity/identity.go`, `internal/sandbox/executor.go`, `internal/cli/import.go`, `internal/cli/export.go`, `internal/cli/clone.go`

Identity directories are created with `0755`, PID files with `0644`, import temp dirs with `0755`, and export tarballs inherit the process umask.

**Risk:** Local users may be able to enumerate or read identity state, proxy config, PID files, or exported archives if the home directory is traversable.

**Recommended actions:**

- Create identity root/home/config directories with `0700`.
- Write PID, lock, profile, and audit files with `0600`.
- Force export tarball permissions to `0600`.
- Sanitize imported/cloned directory permissions to `0700`/`0600`.
- Set process `umask(077)` for commands that create sensitive state.

### 12. Medium: DNS proxy mishandles upstreams with ports or IPv6 literals

**Location:** `internal/proxy/dns.go`, `NewDNSProxy`

`NewDNSProxy(upstream)` blindly appends `:53`, producing invalid addresses for inputs such as `8.8.8.8:5353` or IPv6 literals.

**Risk:** Direct `dns-proxy` use and config paths that permit non-plain IPv4 DNS values can fail.

**Recommended actions:**

- Parse upstream DNS with `net.SplitHostPort`.
- If no port is present, use `net.JoinHostPort(host, "53")`.
- Validate the resulting address before starting the proxy.
- Add tests for IPv4, IPv4:port, IPv6, `[IPv6]:port`, and invalid inputs.

### 13. Medium: Cleanup is broad, destructive, and ignores errors

**Locations:** `internal/cli/cleanup.go`, `internal/netns/namespace.go`

`cleanup` deletes every namespace whose `ip netns list` output starts with `ns-` and every link whose output contains `: vh-`. Errors from list/delete commands are ignored.

**Risk:** It can delete unrelated resources matching generic prefixes, fail silently, or leave processes behind.

**Recommended actions:**

- Scope cleanup to CloakID-created resources derived from identity state.
- Kill namespace PIDs before deleting namespaces.
- Check and report all command errors.
- Add dry-run and confirmation for destructive cleanup.
- Consider less generic resource prefixes, e.g. `cloakid-<hash>-...`.

### 14. Medium: Delete can succeed for non-existent identities and can delete active state

**Location:** `internal/cli/delete.go`

`os.RemoveAll()` returns nil for a missing path, so deleting a non-existent identity reports success. Delete also does not stop/teardown running state first.

**Risk:** Misleading success messages and possible data loss/stale namespace state.

**Recommended actions:**

- Check that the identity directory exists before prompting/removing.
- Stop/teardown the identity first, preferably using the shared lock.
- Return an error if teardown fails.
- Add tests for missing identities and active identities.

### 15. Medium: Whitelist path handling can escape fake home and ignores errors

**Location:** `internal/sandbox/manager.go`, `buildWhitelist`

The whitelist logic uses `strings.HasPrefix(hostPath, realHome)` and then `filepath.Rel`. This can misclassify paths such as `/home/user2/app` when `realHome` is `/home/user`, creating symlinks outside `fakeHome`. Errors from `os.MkdirAll` and `os.Symlink` are ignored.

**Risk:** Unintended host paths may be exposed, and mount preparation failures can be silent.

**Recommended actions:**

- Use `filepath.Rel`, then reject `..` components or paths outside the intended root.
- Check and return/report errors from `MkdirAll` and `Symlink`.
- Trim whitespace around comma-separated whitelist entries.
- Reject control characters in paths.

### 16. Medium: Electron apps are automatically run with Chromium sandbox disabled

**Location:** `internal/sandbox/executor.go`, `applyElectronWorkarounds`

For apps such as `code`, `cursor`, `trae`, and `vscodium`, the code appends `--no-sandbox` unless already present.

**Risk:** The application-level Electron/Chromium sandbox is disabled by default, increasing reliance on Firejail and network namespace isolation.

**Recommended actions:**

- Do not auto-append `--no-sandbox`.
- Require explicit user opt-in, e.g. `--allow-electron-no-sandbox`, with a warning.
- Prefer fixing Firejail profiles so Electron apps can run with their native sandbox.
- Add tests that fail if `--no-sandbox` is appended implicitly.

### 17. Medium: Firejail profile generation accepts user-controlled profile strings directly

**Locations:** `internal/sandbox/profile.go`, `internal/sandbox/firejail.go`

`BuildProfileContent()` emits `include %s` using `nativeProfile` directly. `ResolveProfile` can return user-provided profile strings from `-f/--profile`.

**Risk:** A malformed profile argument with newlines/control characters can inject additional Firejail directives.

**Recommended actions:**

- Validate profile names/paths before rendering.
- Reject newline and control characters.
- Consider a typed `ProfileRef` with constructors for built-in, local, and absolute profile references.
- Add tests for malicious profile inputs.

### 18. Low: Formatting drift exists

**Locations:** `internal/sandbox/executor.go`, `internal/sandbox/executor_test.go`, `internal/sandbox/manager_test.go`

`gofmt -l $(git ls-files '*.go')` reports these files.

**Recommended actions:**

- Run `gofmt -w` on the listed files.
- Add `make fmt-check` to CI.

### 19. Low: Dependency freshness should be checked with `govulncheck`

**Locations:** `go.mod`, `go.sum`

`go list -m -u -json all` found available updates for indirect modules. `govulncheck` is not installed in this environment.

**Recommended actions:**

- Install/run `golang.org/x/vuln/cmd/govulncheck`.
- Update available indirect dependencies after reviewing changelogs.
- Add dependency scanning to CI.

### 20. Low: Built binary exists in the working tree

**Location:** `cloakid`

A built ELF binary exists in the repository root. It is ignored, but it can confuse audits and consume space.

**Recommended actions:**

- Run `make clean` or remove the binary.
- Ensure `.gitignore` intentionally ignores it.

## Recommended Action Plan

### Immediate: before further use or release

1. **Rotate and remove exposed proxy credentials.**
   - Rotate credentials/UUIDs in proxy configs/links.
   - Remove plaintext local config/link files from workspace/backups.
   - Add secret scanning to pre-commit/CI.

2. **Fix identity validation and delete guard.**
   - Reject empty sanitized identity names.
   - Add tests for invalid names and destructive path cases.
   - Add existence checks to destructive commands.

3. **Replace unsafe archive import.**
   - Implement validated `archive/tar` extraction.
   - Add path traversal and symlink/hardlink tests.

4. **Fix config error propagation and runtime validation.**
   - Make commands fail on config load errors when config is required.
   - Validate DNS, port, and identity before network setup.

### Short term: reliability and isolation hardening

5. **Add network setup rollback.**
   - Clean up partial namespaces/veths on setup failure.
   - Return/report teardown errors.

6. **Replace signal `os.Exit` path.**
   - Use `signal.NotifyContext`.
   - Let normal defers run before exit.

7. **Add shared identity locks.**
   - Use locks for `stop`, `delete`, `clone`, `import`, and `export`.
   - Refuse destructive operations while running.

8. **Track helper process lifecycle.**
   - Store, wait, and stop `socat`, `tun2socks`, and DNS proxy processes.
   - Capture stderr for diagnostics.

9. **Harden GUI/session environment.**
   - Do not pass `XAUTHORITY`/`XDG_RUNTIME_DIR` by default.
   - Document GUI isolation limitations.

10. **Tighten permissions.**
   - Use `0700` for identity state directories.
   - Use `0600` for PID/lock/profile/export files.

### Medium term: maintainability and CI

11. **Refactor CLI globals into an `App` struct.**
   - Makes commands testable and less order-dependent.

12. **Add command-runner abstraction.**
   - Allows testing privileged commands without root privileges.

13. **Add CI and Makefile targets.**
   - `make test`
   - `make test-race`
   - `make vet`
   - `make fmt-check`
   - `make coverage`
   - `make clean`

14. **Raise test coverage for critical paths.**
   - CLI commands.
   - Network setup/teardown command construction.
   - Sandbox planning/dry-run.
   - Archive import/export.
   - Identity validation.
   - Logging/audit behavior.

## Commands Run During Audit

```bash
go test ./...
go vet ./...
go test -race ./...
go build ./...
go test -count=1 ./... -coverprofile=/tmp/cloakid.cover
go tool cover -func=/tmp/cloakid.cover
gofmt -l $(git ls-files '*.go')
go list -m -u -json all
python3 -m py_compile rank_dns.py sing-box_config.py
git status --short --branch
git status --short --ignored
git check-ignore -v config.json config_gpt.json proxy_links.txt dns_resolvers.txt
```

## Validation Results

- `go test ./...` passed.
- `go vet ./...` produced no findings.
- `go test -race ./...` passed.
- `go build ./...` passed.
- `python3 -m py_compile rank_dns.py sing-box_config.py` passed.
- `gofmt -l $(git ls-files '*.go')` reported:
  - `internal/sandbox/executor.go`
  - `internal/sandbox/executor_test.go`
  - `internal/sandbox/manager_test.go`
- Total statement coverage: **19.6%**.
- `internal/cli` coverage: **0.0%**.
- `internal/logging` coverage: **0.0%**.
- `internal/netns` coverage: **11.9%**.
- `internal/sandbox` coverage: **18.1%**.
- Secret scan found sensitive proxy credentials/links in ignored local files. Values are intentionally not included in this report.

## Limitations

- I did not run actual sandbox sessions because they require root, `sudo`, Linux network namespace operations, Firejail, `socat`, and `tun2socks`, and can be destructive.
- I did not validate runtime Firejail profile effectiveness against real Electron/CLI apps.
- `govulncheck`, `staticcheck`, and `golangci-lint` were not available in this environment.
- The secret scan was based on local working-tree files and pattern matching; it is not a substitute for a full secret-management review.

## Suggested First Pull Request

Create a small, safe PR with:

1. Identity validation and destructive command guards.
2. Config/default validation before `run`.
3. `gofmt` fixes.
4. Tests for invalid identities, config failures, and DNS upstream parsing.
5. No secret files committed.

Then follow with a second PR for archive import hardening and network rollback, because those touch higher-risk system behavior.
