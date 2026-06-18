# Fish completion script for sandbox.sh

function __sandbox_identities
    set identity_root "$HOME/.sandbox_identities"
    if test -d "$identity_root"
        for dir in $identity_root/*/
            if test -d "$dir"
                echo (basename "$dir")
            end
        end
    end
end

function __sandbox_profiles
    set profiles
    if test -d "$HOME/.config/firejail"
        set profiles $profiles (basename $HOME/.config/firejail/*.profile)
    end
    if test -d "/etc/firejail"
        set profiles $profiles (basename /etc/firejail/*.profile)
    end
    echo $profiles
end

function __sandbox_archives
    echo *.tar.gz
end

complete -c sandbox.sh -f
complete -c sandbox -f

# Identity-related completions
complete -c sandbox.sh -c sandbox -l identity -s i -d "Unique identity name" -a "(__sandbox_identities)"
complete -c sandbox.sh -c sandbox -l stop -d "Stop a running sandbox instance" -a "(__sandbox_identities)"
complete -c sandbox.sh -c sandbox -l delete -d "Delete an identity and all its persistent state" -a "(__sandbox_identities)"
complete -c sandbox.sh -c sandbox -l export -d "Export an identity to a tarball archive" -a "(__sandbox_identities)"
complete -c sandbox.sh -c sandbox -l clone -d "Clone an existing identity to a new name" -a "(__sandbox_identities)"

# Network-related completions
complete -c sandbox.sh -c sandbox -l port -s p -d "Host SOCKS5 proxy port" -a "10808 1080 9050"
complete -c sandbox.sh -c sandbox -l dns -s d -d "Upstream DNS resolver IP" -a "1.1.1.1 8.8.8.8 9.9.9.9"
complete -c sandbox.sh -c sandbox -l timeout -s t -d "Kill sandbox after N seconds" -a "30 60 120 300 600"

# Profile and whitelist completions
complete -c sandbox.sh -c sandbox -l profile -s f -d "Explicitly use/override pre-existing Firejail profile" -a "(__sandbox_profiles)"
complete -c sandbox.sh -c sandbox -l whitelist -s w -d "Comma-separated list of host files/dirs to expose"

# Logging and debugging completions
complete -c sandbox.sh -c sandbox -l verbose -d "Enable detailed step-by-step logging"
complete -c sandbox.sh -c sandbox -l log-level -d "Set logging level: debug, info, warn, error" -a "debug info warn error"
complete -c sandbox.sh -c sandbox -l trace -d "Enable shell tracing (set -x) for debugging"
complete -c sandbox.sh -c sandbox -l progress -d "Show progress indicators for long operations"
complete -c sandbox.sh -c sandbox -l audit -d "Enable audit logging for security-relevant operations"

# Sandbox mode completions
complete -c sandbox.sh -c sandbox -l no-sandbox -s n -d "Disable Firejail filesystem/app sandboxing"
complete -c sandbox.sh -c sandbox -l dry-run -d "Show proposed topology and profile without altering system"
complete -c sandbox.sh -c sandbox -l force -d "Skip confirmation prompts (--delete only)"

# Management completions
complete -c sandbox.sh -c sandbox -l import -d "Import an identity from a tarball archive" -a "(__sandbox_archives)"
complete -c sandbox.sh -c sandbox -l cleanup-only -d "Clean up stale resources without launching anything"
complete -c sandbox.sh -c sandbox -l list -d "List all existing identities and their state"
complete -c sandbox.sh -c sandbox -l status -d "Show running sandbox instances"
complete -c sandbox.sh -c sandbox -l show-config -d "Show current configuration (file + command line)"

# Help and version completions
complete -c sandbox.sh -c sandbox -l version -s v -d "Show version information"
complete -c sandbox.sh -c sandbox -l help -s h -d "Show help menu"
