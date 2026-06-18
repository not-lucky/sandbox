#compdef sandbox.sh
# Zsh completion script for sandbox.sh

_sandbox() {
  local -a identities profiles commands archives

  # Get existing identities
  local identity_root="$HOME/.sandbox_identities"
  if [[ -d "$identity_root" ]]; then
    identities=("$identity_root"/*/(:t))
  fi

  # Get available profiles
  profiles=()
  [[ -d "$HOME/.config/firejail" ]] && profiles+=("$HOME/.config/firejail"/*.profile(:t))
  [[ -d "/etc/firejail" ]] && profiles+=("/etc/firejail"/*.profile(:t))

  # Get available archive files for import
  archives=()
  archives+=(*.tar.gz(:t))

  _arguments \
    {-i,--identity}"[Unique identity name]:identity:($identities)" \
    {-w,--whitelist}"[Comma-separated list of host files/dirs to expose]:paths:_files" \
    {-p,--port}"[Host SOCKS5 proxy port]:port:(10808 1080 9050)" \
    {-f,--profile}"[Explicitly use/override pre-existing Firejail profile]:profile:($profiles)" \
    {-d,--dns}"[Upstream DNS resolver IP]:dns:(1.1.1.1 8.8.8.8 9.9.9.9)" \
    {-t,--timeout}"[Kill sandbox after N seconds]:timeout:(30 60 120 300 600)" \
    --log-level"[Set logging level: debug, info, warn, error]:level:(debug info warn error)" \
    {-n,--no-sandbox}"[Disable Firejail filesystem/app sandboxing]" \
    --verbose"[Enable detailed step-by-step logging]" \
    --trace"[Enable shell tracing (set -x) for debugging]" \
    --progress"[Show progress indicators for long operations]" \
    --audit"[Enable audit logging for security-relevant operations]" \
    --dry-run"[Show proposed topology and profile without altering system]" \
    --force"[Skip confirmation prompts (--delete only)]" \
    --list"[List all existing identities and their state]" \
    --status"[Show running sandbox instances]" \
    --stop"[Stop a running sandbox instance]:identity:($identities)" \
    --delete"[Delete an identity and all its persistent state]:identity:($identities)" \
    --export"[Export an identity to a tarball archive]:identity:($identities)" \
    --import"[Import an identity from a tarball archive]:archive:_files -g '*.tar.gz'" \
    --clone"[Clone an existing identity to a new name]:source identity:($identities):target identity:" \
    --cleanup-only"[Clean up stale resources without launching anything]" \
    --show-config"[Show current configuration (file + command line)]" \
    {-v,--version}"[Show version information]" \
    {-h,--help}"[Show help menu]" \
    "*::command:_command"

  case $state in
    command)
      _normal
      ;;
  esac
}

_sandbox "$@"
