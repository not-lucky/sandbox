#!/usr/bin/env bash
# Bash completion script for sandbox.sh

_sandbox_completion() {
  local cur prev words cword
  _init_completion || return

  case "${prev}" in
    -i|--identity)
      # Complete with existing identities
      local identity_root="$HOME/.sandbox_identities"
      if [[ -d "$identity_root" ]]; then
        local identities=()
        for dir in "$identity_root"/*/; do
          [[ -d "$dir" ]] && identities+=("$(basename -- "$dir")")
        done
        COMPREPLY=($(compgen -W "${identities[*]}" -- "${cur}"))
      fi
      return 0
      ;;
    -f|--profile)
      # Complete with .profile files
      local profiles=()
      [[ -d "$HOME/.config/firejail" ]] && profiles+=($(compgen -W "$(ls "$HOME/.config/firejail"/*.profile 2>/dev/null | xargs -n1 basename 2>/dev/null)" -- "${cur}"))
      [[ -d "/etc/firejail" ]] && profiles+=($(compgen -W "$(ls /etc/firejail/*.profile 2>/dev/null | xargs -n1 basename 2>/dev/null)" -- "${cur}"))
      COMPREPLY=($(compgen -W "${profiles[*]}" -- "${cur}"))
      return 0
      ;;
    -p|--port)
      COMPREPLY=($(compgen -W "10808 1080 9050" -- "${cur}"))
      return 0
      ;;
    -d|--dns)
      COMPREPLY=($(compgen -W "1.1.1.1 8.8.8.8 9.9.9.9" -- "${cur}"))
      return 0
      ;;
    -t|--timeout)
      COMPREPLY=($(compgen -W "30 60 120 300 600" -- "${cur}"))
      return 0
      ;;
    --log-level)
      COMPREPLY=($(compgen -W "debug info warn error" -- "${cur}"))
      return 0
      ;;
    -w|--whitelist)
      # Complete with files and directories
      COMPREPLY=($(compgen -f -- "${cur}"))
      return 0
      ;;
    --export)
      # Complete with existing identities
      local identity_root="$HOME/.sandbox_identities"
      if [[ -d "$identity_root" ]]; then
        local identities=()
        for dir in "$identity_root"/*/; do
          [[ -d "$dir" ]] && identities+=("$(basename -- "$dir")")
        done
        COMPREPLY=($(compgen -W "${identities[*]}" -- "${cur}"))
      fi
      return 0
      ;;
    --import)
      # Complete with tar.gz files
      COMPREPLY=($(compgen -f -X '!*.tar.gz' -- "${cur}"))
      return 0
      ;;
    --clone)
      # Complete with existing identities for source
      local identity_root="$HOME/.sandbox_identities"
      if [[ -d "$identity_root" ]]; then
        local identities=()
        for dir in "$identity_root"/*/; do
          [[ -d "$dir" ]] && identities+=("$(basename -- "$dir")")
        done
        COMPREPLY=($(compgen -W "${identities[*]}" -- "${cur}"))
      fi
      return 0
      ;;
    --stop|--delete)
      # Complete with existing identities
      local identity_root="$HOME/.sandbox_identities"
      if [[ -d "$identity_root" ]]; then
        local identities=()
        for dir in "$identity_root"/*/; do
          [[ -d "$dir" ]] && identities+=("$(basename -- "$dir")")
        done
        COMPREPLY=($(compgen -W "${identities[*]}" -- "${cur}"))
      fi
      return 0
      ;;
    --)
      # After --, complete with commands (simplified)
      COMPREPLY=($(compgen -c -- "${cur}"))
      return 0
      ;;
  esac

  if [[ "${cur}" == -* ]]; then
    COMPREPLY=($(compgen -W "-i --identity -w --whitelist -p --port -f --profile -d --dns -t --timeout -n --no-sandbox --verbose --log-level --trace --progress --audit --dry-run --force --list --status --stop --delete --export --import --clone --cleanup-only --show-config -v --version -h --help --" -- "${cur}"))
  fi
}

complete -F _sandbox_completion sandbox.sh
complete -F _sandbox_completion sandbox
